//! A release part: build it unsigned, add KMS signatures, verify it as clients do.

use anyhow::{anyhow, ensure, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use spr_prover_tee::{
    FreshnessSigners, PolicySignature, PolicySigners, ReleasePayload, SignedPart, SignedPolicyFile,
    TeePolicy, VerifiedPolicy, RELEASE_DOMAIN,
};

use crate::{kms::Ed25519Signer, pins};

/// The longest a release part may last; `build` refuses more.
pub const MAX_RELEASE_DAYS: u64 = 90;
/// The freshness function signs parts of this lifetime, and each release allows it.
pub const FRESHNESS_LIFETIME_SECS: u64 = 3 * 86_400;

/// An unsigned release part approving `policy` on `network` until `expires_at`,
/// kept fresh by any one of `freshness_keys` (lowercase hex).
pub fn build(
    network: &str,
    version: u64,
    expires_at: u64,
    freshness_keys: Vec<String>,
    policy: TeePolicy,
) -> Result<SignedPart> {
    let payload = ReleasePayload {
        network: network.into(),
        version,
        expires_at,
        freshness: FreshnessSigners {
            public_keys: freshness_keys,
            threshold: 1,
            max_lifetime_secs: FRESHNESS_LIFETIME_SECS,
        },
        policy,
    };
    Ok(SignedPart {
        payload: hex::encode(json_line(&payload)?),
        signatures: vec![],
    })
}

/// Adds `signer`'s signature over the release payload once it verifies, and
/// returns the signer's key; refuses a second signature from the same key.
pub async fn sign(part: &mut SignedPart, signer: &impl Ed25519Signer) -> Result<String> {
    let payload = hex::decode(&part.payload).context("release payload is not hex")?;
    let message = [RELEASE_DOMAIN, &payload].concat();
    let signature = signer.sign(&message).await?;
    let key = signer.public_key();
    VerifyingKey::from_bytes(&key)?
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .context("the signer's signature does not verify")?;
    let public_key = hex::encode(key);
    ensure!(
        part.signatures
            .iter()
            .all(|entry| entry.public_key != public_key),
        "{public_key} already signed this part"
    );
    part.signatures.push(PolicySignature {
        public_key: public_key.clone(),
        signature: hex::encode(signature),
    });
    Ok(public_key)
}

/// The release payload, before any signature check.
pub fn peek(part: &SignedPart) -> Result<ReleasePayload> {
    let payload = hex::decode(&part.payload).context("release payload is not hex")?;
    serde_json::from_slice(&payload).context("release payload is not a release")
}

/// The release a client accepts at `now` under the keys the SDK pins for its
/// network, with `min_days_left` to spare and a version above `previous`.
pub fn verify(
    part: &SignedPart,
    now: u64,
    min_days_left: u64,
    previous: Option<&SignedPart>,
) -> Result<ReleasePayload> {
    let (signers, _) = pins::pinned(&peek(part)?.network)?;
    verify_with(part, &signers, now, min_days_left, previous)
}

pub(crate) fn verify_with(
    part: &SignedPart,
    signers: &PolicySigners,
    now: u64,
    min_days_left: u64,
    previous: Option<&SignedPart>,
) -> Result<ReleasePayload> {
    let (release, _) = part
        .verify_release(signers, now)
        .map_err(|error| anyhow!("clients refuse this release part: {error}"))?;
    ensure!(
        release.expires_at > now + min_days_left * 86_400,
        "the release part expires within {min_days_left} days"
    );
    ensure!(
        release.freshness.max_lifetime_secs <= FRESHNESS_LIFETIME_SECS,
        "the release allows freshness parts longer than {FRESHNESS_LIFETIME_SECS} seconds"
    );
    if let Some(previous) = previous {
        let before = peek(previous)?;
        ensure!(
            release.version > before.version,
            "version {} is not above {}",
            release.version,
            before.version
        );
    }
    Ok(release)
}

/// The served file as a client accepts it at `now`, in force for `min_hours_left` more.
pub fn verify_served(file: &[u8], now: u64, min_hours_left: u64) -> Result<VerifiedPolicy> {
    let parsed: SignedPolicyFile =
        serde_json::from_slice(file).context("the file is not a signed policy")?;
    let (signers, _) = pins::pinned(&peek(&parsed.release)?.network)?;
    let verified = SignedPolicyFile::verify(file, &signers, now)
        .map_err(|error| anyhow!("clients refuse this file: {error}"))?;
    ensure!(
        verified.expires_at() > now + min_hours_left * 3_600,
        "the policy leaves force within {min_hours_left} hours"
    );
    Ok(verified)
}

/// Pretty JSON and a newline, as the files are kept in git.
pub(crate) fn json_line(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::json;

    use super::*;
    use crate::{kms::LocalSigner, manifest};

    pub(crate) const NOW: u64 = 1_800_000_000;

    pub(crate) fn signers() -> PolicySigners {
        PolicySigners::new("fixture", vec![LocalSigner::seed(1).public_key()], 1).unwrap()
    }

    pub(crate) fn policy() -> TeePolicy {
        let manifest = json!({ "nitro_measurements": { "PCR0": "a".repeat(96), "PCR1": "b".repeat(96), "PCR2": "c".repeat(96) } });
        manifest::policy(&manifest, 600).unwrap()
    }

    /// Release `version` of the fixture network, signed by seed 1 and naming seed 5.
    pub(crate) async fn release(version: u64) -> SignedPart {
        let fresh = hex::encode(LocalSigner::seed(5).public_key());
        let mut part = build("fixture", version, NOW + 90 * 86_400, vec![fresh], policy()).unwrap();
        sign(&mut part, &LocalSigner::seed(1)).await.unwrap();
        part
    }

    #[tokio::test]
    async fn a_built_and_signed_part_verifies_as_clients_read_it() {
        let part = release(2).await;
        let approved = verify_with(&part, &signers(), NOW, 14, Some(&release(1).await)).unwrap();
        assert_eq!(approved.version, 2);
        assert!(verify_with(&part, &signers(), NOW, 14, Some(&release(2).await)).is_err());
        assert!(verify_with(&part, &signers(), NOW, 90, None).is_err());
    }

    #[tokio::test]
    async fn a_second_signature_from_one_key_is_refused() {
        let mut part = release(2).await;
        assert!(sign(&mut part, &LocalSigner::seed(1)).await.is_err());
    }

    #[tokio::test]
    async fn an_unpinned_signer_is_refused() {
        let fresh = hex::encode(LocalSigner::seed(5).public_key());
        let mut part = build("fixture", 2, NOW + 86_400 * 30, vec![fresh], policy()).unwrap();
        sign(&mut part, &LocalSigner::seed(4)).await.unwrap();
        let error = verify_with(&part, &signers(), NOW, 0, None).unwrap_err();
        assert!(error.to_string().contains("clients refuse"), "{error}");
    }

    #[tokio::test]
    async fn a_non_canonical_freshness_key_is_refused() {
        let non_canonical = format!("ee{}7f", "ff".repeat(30));
        let fresh = hex::encode(LocalSigner::seed(5).public_key());
        let mut part = build(
            "fixture",
            2,
            NOW + 86_400 * 30,
            vec![fresh, non_canonical],
            policy(),
        )
        .unwrap();
        sign(&mut part, &LocalSigner::seed(1)).await.unwrap();
        assert!(verify_with(&part, &signers(), NOW, 0, None).is_err());
    }
}
