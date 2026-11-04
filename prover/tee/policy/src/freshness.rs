//! Keeps a release in force: signs a short-lived freshness part over the release
//! part in `tee-policy-release/<network>.json` and publishes both as the file
//! clients download, `tee-policy/<network>.json`.
//!
//! A run publishes only a file `SignedPolicyFile::verify` accepts under the
//! release keys the SDK pins, never one whose release is older than the one
//! served, and only over the object it read: a run that raced another starts
//! again from what that run published.

use std::future::Future;

use anyhow::{anyhow, bail, ensure, Context, Result};
use aws_sdk_s3::{primitives::ByteStream, Client};
use ed25519_dalek::{Signature, VerifyingKey};
use spr_prover_tee::{
    FreshnessPayload, PolicySignature, PolicySigners, ReleasePayload, SignedPart, SignedPolicyFile,
    FRESHNESS_DOMAIN,
};

use crate::{kms::Ed25519Signer, release::json_line};

/// Runs that find the served object changed under them before giving up.
const ATTEMPTS: usize = 3;

/// An object and the tag that changes with each write.
pub struct Object {
    pub body: Vec<u8>,
    pub etag: String,
}

/// Object storage with compare-and-swap writes.
pub trait Store {
    fn get(&self, key: &str) -> impl Future<Output = Result<Option<Object>>> + Send;
    /// Writes `body` only while the object still has `etag`, or is absent when
    /// `etag` is `None`; `Ok(false)` when it changed.
    fn put_if(
        &self,
        key: &str,
        body: Vec<u8>,
        etag: Option<String>,
    ) -> impl Future<Output = Result<bool>> + Send;
}

/// What a run published.
#[derive(Debug, PartialEq, Eq)]
pub struct Published {
    pub release_version: u64,
    pub release_expires_at: u64,
    /// When the published file leaves force: the earlier of the two expiries.
    pub expires_at: u64,
}

/// One network's freshness signer.
pub struct Freshener<S, K> {
    pub store: S,
    pub signer: K,
    pub network: String,
    /// The release keys the SDK pins for `network`.
    pub signers: PolicySigners,
    /// How long each part runs, at most the release's `max_lifetime_secs`.
    pub lifetime_secs: u64,
}

impl<S: Store, K: Ed25519Signer> Freshener<S, K> {
    pub fn release_key(&self) -> String {
        format!("tee-policy-release/{}.json", self.network)
    }

    pub fn served_key(&self) -> String {
        format!("tee-policy/{}.json", self.network)
    }

    /// Publishes the release part with a freshness part issued at `now`.
    pub async fn publish(&self, now: u64) -> Result<Published> {
        for _ in 0..ATTEMPTS {
            let served = self.store.get(&self.served_key()).await?;
            let release = self
                .store
                .get(&self.release_key())
                .await?
                .with_context(|| format!("no release part at {}", self.release_key()))?;
            let part: SignedPart = serde_json::from_slice(&release.body)
                .context("the release part is not a signed part")?;
            let (approved, payload) = part
                .verify_release(&self.signers, now)
                .map_err(|error| anyhow!("clients refuse the release part: {error}"))?;
            if let Some(served) = &served {
                if no_rollback(&served.body, &approved, &payload, now)? == Served::AsFresh {
                    return self.already_published(&served.body, now);
                }
            }
            let (file, published) = self.freshen(part, approved, &payload, now).await?;
            if self
                .store
                .put_if(&self.served_key(), file, served.map(|served| served.etag))
                .await?
            {
                return Ok(published);
            }
        }
        bail!(
            "{} changed {ATTEMPTS} times while this run published",
            self.served_key()
        )
    }

    /// The served file, which a racing run published for this release no older
    /// than `now`; writing this run's part over it would roll its freshness back.
    fn already_published(&self, served: &[u8], now: u64) -> Result<Published> {
        let verified = SignedPolicyFile::verify(served, &self.signers, now)
            .map_err(|error| anyhow!("clients refuse the served file: {error}"))?;
        Ok(Published {
            release_version: verified.release.version,
            release_expires_at: verified.release.expires_at,
            expires_at: verified.expires_at(),
        })
    }

    /// The file to serve: `part` and a freshness part over it, as clients accept it.
    async fn freshen(
        &self,
        part: SignedPart,
        approved: ReleasePayload,
        payload: &[u8],
        now: u64,
    ) -> Result<(Vec<u8>, Published)> {
        let own = hex::encode(self.signer.public_key());
        ensure!(
            approved.freshness.public_keys.contains(&own),
            "the release part does not name this signer's key {own}"
        );
        ensure!(
            approved.freshness.threshold == 1,
            "the release part needs {} freshness signatures; this signer gives one",
            approved.freshness.threshold
        );
        let lifetime = self.lifetime_secs.min(approved.freshness.max_lifetime_secs);
        let freshness = json_line(&FreshnessPayload::of(
            payload,
            approved.version,
            &self.network,
            now,
            now + lifetime,
        ))?;
        let message = [FRESHNESS_DOMAIN, &freshness].concat();
        let signature = self.signer.sign(&message).await?;
        VerifyingKey::from_bytes(&self.signer.public_key())?
            .verify_strict(&message, &Signature::from_bytes(&signature))
            .context("the freshness signature does not verify")?;
        let file = json_line(&SignedPolicyFile {
            release: part,
            freshness: SignedPart {
                payload: hex::encode(freshness),
                signatures: vec![PolicySignature {
                    public_key: own,
                    signature: hex::encode(signature),
                }],
            },
        })?;
        let verified = SignedPolicyFile::verify(&file, &self.signers, now)
            .map_err(|error| anyhow!("clients would refuse the file: {error}"))?;
        let published = Published {
            release_version: approved.version,
            release_expires_at: approved.expires_at,
            expires_at: verified.expires_at(),
        };
        Ok((file, published))
    }
}

/// Refuses a release older than the served one, or another payload under its
/// version: clients that saw the served file refuse both as a rollback. A served
/// object that is not a signed policy is replaced.
/// Whether the served file leaves this run anything to publish.
#[derive(Debug, PartialEq, Eq)]
enum Served {
    /// Another release, or this one with an older freshness part.
    Older,
    /// This release with a freshness part issued at or after `now`, which a run
    /// that raced this one published.
    AsFresh,
}

/// Refuses a release older than the served one, or another payload under its
/// version: clients that saw the served file refuse both as a rollback. Clients
/// also refuse an earlier `issued_at` for the same release, so a served part
/// issued at or after `now` is left as it is. A served object that is not a
/// signed policy is replaced.
fn no_rollback(
    served: &[u8],
    approved: &ReleasePayload,
    payload: &[u8],
    now: u64,
) -> Result<Served> {
    let Some((before, before_payload, issued_at)) = served_release(served) else {
        return Ok(Served::Older);
    };
    ensure!(
        approved.version > before.version
            || (approved.version == before.version && payload == before_payload),
        "release version {} would roll back the served version {}",
        approved.version,
        before.version
    );
    Ok(
        if payload == before_payload && issued_at.is_some_and(|issued_at| issued_at >= now) {
            Served::AsFresh
        } else {
            Served::Older
        },
    )
}

/// The served release, its payload bytes and its freshness part's `issued_at`.
fn served_release(served: &[u8]) -> Option<(ReleasePayload, Vec<u8>, Option<u64>)> {
    let file: SignedPolicyFile = serde_json::from_slice(served).ok()?;
    let payload = hex::decode(&file.release.payload).ok()?;
    let issued_at = hex::decode(&file.freshness.payload)
        .ok()
        .and_then(|freshness| serde_json::from_slice::<FreshnessPayload>(&freshness).ok())
        .map(|freshness| freshness.issued_at);
    Some((serde_json::from_slice(&payload).ok()?, payload, issued_at))
}

/// An S3 bucket, with conditional writes.
pub struct S3Store {
    pub client: Client,
    pub bucket: String,
}

impl Store for S3Store {
    async fn get(&self, key: &str) -> Result<Option<Object>> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => {
                let etag = output.e_tag().context("S3 returned no ETag")?.to_owned();
                let body = output.body.collect().await?.into_bytes().to_vec();
                Ok(Some(Object { body, etag }))
            }
            Err(error) if error.as_service_error().is_some_and(|e| e.is_no_such_key()) => Ok(None),
            Err(error) => Err(anyhow!(aws_sdk_s3::error::DisplayErrorContext(error)))
                .with_context(|| format!("read s3://{}/{key}", self.bucket)),
        }
    }

    async fn put_if(&self, key: &str, body: Vec<u8>, etag: Option<String>) -> Result<bool> {
        let request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type("application/json")
            .body(ByteStream::from(body));
        let request = match etag {
            Some(etag) => request.if_match(etag),
            None => request.if_none_match("*"),
        };
        match request.send().await {
            Ok(_) => Ok(true),
            // 412: the object changed; 409: a concurrent conditional write won.
            Err(error)
                if matches!(
                    error.raw_response().map(|r| r.status().as_u16()),
                    Some(409 | 412)
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(anyhow!(aws_sdk_s3::error::DisplayErrorContext(error)))
                .with_context(|| format!("write s3://{}/{key}", self.bucket)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use super::*;
    use crate::{
        kms::LocalSigner,
        release::{
            json_line,
            tests::{release, signers, NOW},
        },
    };

    type Hook = Box<dyn Fn(&mut HashMap<String, (Vec<u8>, u64)>) + Send>;

    /// Objects in memory; `before_put` runs once, before the first write, as a
    /// run that raced this one.
    #[derive(Default)]
    struct Memory {
        objects: Mutex<HashMap<String, (Vec<u8>, u64)>>,
        before_put: Mutex<Option<Hook>>,
    }

    impl Memory {
        fn set(objects: &mut HashMap<String, (Vec<u8>, u64)>, key: &str, body: Vec<u8>) {
            let next = objects.get(key).map_or(1, |(_, tag)| tag + 1);
            objects.insert(key.into(), (body, next));
        }
    }

    impl Store for Memory {
        async fn get(&self, key: &str) -> Result<Option<Object>> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .get(key)
                .map(|(body, tag)| Object {
                    body: body.clone(),
                    etag: tag.to_string(),
                }))
        }

        async fn put_if(&self, key: &str, body: Vec<u8>, etag: Option<String>) -> Result<bool> {
            let mut objects = self.objects.lock().unwrap();
            if let Some(hook) = self.before_put.lock().unwrap().take() {
                hook(&mut objects);
            }
            if objects.get(key).map(|(_, tag)| tag.to_string()) != etag {
                return Ok(false);
            }
            Memory::set(&mut objects, key, body);
            Ok(true)
        }
    }

    async fn freshener(version: u64) -> Freshener<Memory, LocalSigner> {
        let store = Memory::default();
        let part = json_line(&release(version).await).unwrap();
        Memory::set(
            &mut store.objects.lock().unwrap(),
            "tee-policy-release/fixture.json",
            part,
        );
        Freshener {
            store,
            signer: LocalSigner::seed(5),
            network: "fixture".into(),
            signers: signers(),
            lifetime_secs: 3 * 86_400,
        }
    }

    fn served_version(freshener: &Freshener<Memory, LocalSigner>) -> u64 {
        let objects = freshener.store.objects.lock().unwrap();
        served_release(&objects["tee-policy/fixture.json"].0)
            .unwrap()
            .0
            .version
    }

    #[tokio::test]
    async fn publishes_a_file_clients_accept() {
        let freshener = freshener(4).await;
        let published = freshener.publish(NOW).await.unwrap();
        assert_eq!(published.release_version, 4);
        assert_eq!(published.expires_at, NOW + 3 * 86_400);
        let body = freshener.store.objects.lock().unwrap()["tee-policy/fixture.json"]
            .0
            .clone();
        SignedPolicyFile::verify(&body, &signers(), NOW).unwrap();
        // A second run renews the same release over the first.
        freshener.publish(NOW + 86_400).await.unwrap();
    }

    #[tokio::test]
    async fn a_run_that_raced_a_newer_release_publishes_that_release() {
        let freshener = freshener(4).await;
        freshener.publish(NOW).await.unwrap();
        // While this run signs release 4, an apply publishes release 5.
        let newer = json_line(&release(5).await).unwrap();
        let racing = Freshener {
            store: Memory::default(),
            signer: LocalSigner::seed(5),
            network: "fixture".into(),
            signers: signers(),
            lifetime_secs: 3 * 86_400,
        };
        Memory::set(
            &mut racing.store.objects.lock().unwrap(),
            "tee-policy-release/fixture.json",
            newer.clone(),
        );
        racing.publish(NOW).await.unwrap();
        let served_by_racer = racing.store.objects.lock().unwrap()["tee-policy/fixture.json"]
            .0
            .clone();
        *freshener.store.before_put.lock().unwrap() = Some(Box::new(move |objects| {
            Memory::set(objects, "tee-policy-release/fixture.json", newer.clone());
            Memory::set(objects, "tee-policy/fixture.json", served_by_racer.clone());
        }));
        freshener.publish(NOW + 60).await.unwrap();
        assert_eq!(served_version(&freshener), 5);
    }

    /// Run A starts at NOW + 100; run B publishes the same release at NOW + 101
    /// before A writes. A must not replace B's part with its older one.
    #[tokio::test]
    async fn a_run_that_raced_a_fresher_part_of_the_same_release_leaves_it() {
        let freshener = freshener(4).await;
        freshener.publish(NOW).await.unwrap();
        let racing = Freshener {
            store: Memory::default(),
            signer: LocalSigner::seed(5),
            network: "fixture".into(),
            signers: signers(),
            lifetime_secs: 3 * 86_400,
        };
        let part = freshener.store.objects.lock().unwrap()["tee-policy-release/fixture.json"]
            .0
            .clone();
        Memory::set(
            &mut racing.store.objects.lock().unwrap(),
            "tee-policy-release/fixture.json",
            part,
        );
        racing.publish(NOW + 101).await.unwrap();
        let fresher = racing.store.objects.lock().unwrap()["tee-policy/fixture.json"]
            .0
            .clone();
        *freshener.store.before_put.lock().unwrap() = Some(Box::new(move |objects| {
            Memory::set(objects, "tee-policy/fixture.json", fresher.clone());
        }));
        let published = freshener.publish(NOW + 100).await.unwrap();
        let objects = freshener.store.objects.lock().unwrap();
        let (_, _, issued_at) = served_release(&objects["tee-policy/fixture.json"].0).unwrap();
        assert_eq!(issued_at, Some(NOW + 101));
        assert_eq!(published.expires_at, NOW + 101 + 3 * 86_400);
    }

    #[tokio::test]
    async fn an_older_release_than_the_served_one_is_refused() {
        let freshener = freshener(5).await;
        freshener.publish(NOW).await.unwrap();
        let older = json_line(&release(4).await).unwrap();
        Memory::set(
            &mut freshener.store.objects.lock().unwrap(),
            "tee-policy-release/fixture.json",
            older,
        );
        let error = freshener.publish(NOW).await.unwrap_err();
        assert!(error.to_string().contains("roll back"), "{error}");
        assert_eq!(served_version(&freshener), 5);
    }

    #[tokio::test]
    async fn a_release_that_does_not_name_this_key_is_refused() {
        let mut freshener = freshener(4).await;
        freshener.signer = LocalSigner::seed(6);
        let error = freshener.publish(NOW).await.unwrap_err();
        assert!(error.to_string().contains("does not name"), "{error}");
    }

    #[tokio::test]
    async fn a_release_clients_refuse_is_not_served() {
        let freshener = freshener(4).await;
        let error = freshener.publish(NOW + 91 * 86_400).await.unwrap_err();
        assert!(error.to_string().contains("clients refuse"), "{error}");
        assert!(freshener
            .store
            .objects
            .lock()
            .unwrap()
            .get("tee-policy/fixture.json")
            .is_none());
    }
}
