use serde::Deserialize;
use serde_json::json;
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::Signer;
use thiserror::Error;
use zolana_indexer_api::Hash;
use zolana_keypair::P256Pubkey;
use zolana_ring_client::auditor_view_tag;
use zolana_ring_rpc::{
    auditor_key_attestation, CreateAuditorKeyRequest, CreateAuditorKeyResponse,
    DecryptedTransaction, GetDecryptedTransactionsRequest, GetDecryptedTransactionsResponse,
    ReadBuildError, RequestBuildError, RingState, RingStatusRequest, RingStatusResponse,
    SkippedReason, CREATE_AUDITOR_KEY, GET_DECRYPTED_TRANSACTIONS, RING_STATUS,
};

use crate::{
    probe,
    transact::{wait_for, Probe, WaitError},
    Context,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    Pinned(Address),
    Unpinned,
    Refuse,
}

pub struct AttestedAuditorKey {
    pub auditor_pk: P256Pubkey,
    pub service_pubkey: Address,
}

pub struct RingRpcClient {
    url: String,
    http: reqwest::blocking::Client,
}

pub struct TransactionLookup<'a> {
    pub ring: Address,
    pub reader: &'a dyn Signer,
    pub signature: Signature,
}

/// `authority` is the upgrade authority or, once the config exists, the config authority.
pub struct AuditorKeyRelease<'a> {
    pub ring: Address,
    pub genesis_hash: [u8; 32],
    pub authority: &'a dyn Signer,
}

#[derive(Debug, Error)]
pub enum RingRpcClientError {
    #[error("no ring rpc answers at {url}")]
    Unreachable {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("ring rpc {method} failed, {error}")]
    Rpc {
        method: &'static str,
        error: serde_json::Value,
    },
    #[error("ring rpc {method} returned no result")]
    EmptyResult { method: &'static str },
    #[error("the ring rpc at {url} returned an auditor key its service key {service_pubkey} did not sign")]
    UnsignedAttestation {
        url: String,
        service_pubkey: Address,
    },
    #[error("the ring rpc signs with {actual} but ring.toml pins {pinned}")]
    PinMismatch { pinned: Address, actual: Address },
    #[error("ring.toml pins no ring rpc service key, the rpc signs with {service_pubkey}. Put it in ring_rpc_pubkey after confirming it out of band, or pass --trust-ring-rpc for a local instance")]
    Unpinned { service_pubkey: Address },
    #[error("the ring rpc at {url} holds another auditor key for this ring than the one its config names ({expected_tag}). A config fixes its auditor when it is created, so this service can never open the ring. Serve the ring from a ring rpc holding its key, or deploy a new ring")]
    ForeignAuditor { url: String, expected_tag: Hash },
    #[error("the ring has no config yet, run `zolana-ring init` before `transact`")]
    NotInitialized,
    #[error(transparent)]
    Read(#[from] ReadBuildError),
    #[error(transparent)]
    Request(#[from] RequestBuildError),
    #[error("ring rpc could not open {signature}, {reason:?}")]
    Skipped {
        signature: Signature,
        reason: SkippedReason,
    },
    #[error("timed out waiting for {label}")]
    Timeout {
        label: String,
        #[source]
        last: Option<Box<RingRpcClientError>>,
    },
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

/// Answers before the ring has a config, so a pipeline can stop before `init`
/// pins an auditor the service does not hold.
pub fn run_check(ctx: &Context) -> Result<(), RingRpcClientError> {
    let url = ctx.config.urls().ring_rpc.clone();
    let status = ctx.ring_rpc().ring_status(ctx.ring.program_id())?;
    match status.state {
        RingState::Served => crate::line("ring rpc", format_args!("{url} serves this ring")),
        RingState::Uninitialized => crate::line(
            "ring rpc",
            format_args!("{url} holds a key for the ring, `init` pins it"),
        ),
        RingState::ForeignAuditor => {
            return Err(RingRpcClientError::ForeignAuditor {
                url,
                expected_tag: config_view_tag(&status),
            });
        }
    }
    Ok(())
}

/// The config names a key whenever the state is `ForeignAuditor`.
fn config_view_tag(status: &RingStatusResponse) -> Hash {
    status
        .config_auditor_pubkey
        .map(|key| Hash(auditor_view_tag(key.as_key())))
        .unwrap_or_default()
}

impl AttestedAuditorKey {
    pub fn require(self, trust: Trust) -> Result<P256Pubkey, RingRpcClientError> {
        match trust {
            Trust::Pinned(pinned) if pinned == self.service_pubkey => Ok(self.auditor_pk),
            Trust::Pinned(pinned) => Err(RingRpcClientError::PinMismatch {
                pinned,
                actual: self.service_pubkey,
            }),
            Trust::Unpinned => Ok(self.auditor_pk),
            Trust::Refuse => Err(RingRpcClientError::Unpinned {
                service_pubkey: self.service_pubkey,
            }),
        }
    }
}

impl RingRpcClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            http: probe::http(probe::CONNECT_TIMEOUT, probe::TOTAL_TIMEOUT),
        }
    }

    /// Verified against the service key the response names, the caller decides whether to trust that key.
    pub fn release_auditor_key(
        &self,
        release: &AuditorKeyRelease<'_>,
    ) -> Result<AttestedAuditorKey, RingRpcClientError> {
        let ring = release.ring;
        let request = CreateAuditorKeyRequest::for_ring(ring, release.genesis_hash)
            .sign(release.authority)?;
        let created: CreateAuditorKeyResponse =
            self.call(CREATE_AUDITOR_KEY, serde_json::to_value(request)?)?;
        let service_pubkey = created.service_pubkey.0;
        let auditor_pk = *created.auditor_pubkey.as_key();
        if !created.signature.0.verify(
            service_pubkey.as_ref(),
            &auditor_key_attestation(&ring, &auditor_pk),
        ) {
            return Err(RingRpcClientError::UnsignedAttestation {
                url: self.url.clone(),
                service_pubkey,
            });
        }
        Ok(AttestedAuditorKey {
            auditor_pk,
            service_pubkey,
        })
    }

    /// Unsigned, `release_auditor_key` is the attested path `init` pins from.
    pub fn ring_status(&self, ring: Address) -> Result<RingStatusResponse, RingRpcClientError> {
        self.call(
            RING_STATUS,
            serde_json::to_value(RingStatusRequest {
                ring_program_id: ring.to_bytes().into(),
            })?,
        )
    }

    /// A service that holds another key for this ring can open nothing here.
    pub fn check_serves(&self, ring: Address) -> Result<(), RingRpcClientError> {
        let status = self.ring_status(ring)?;
        match status.state {
            RingState::Served => Ok(()),
            RingState::Uninitialized => Err(RingRpcClientError::NotInitialized),
            RingState::ForeignAuditor => Err(RingRpcClientError::ForeignAuditor {
                url: self.url.clone(),
                expected_tag: config_view_tag(&status),
            }),
        }
    }

    pub fn decrypted_transactions(
        &self,
        request: &GetDecryptedTransactionsRequest,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcClientError> {
        self.call(GET_DECRYPTED_TRANSACTIONS, serde_json::to_value(request)?)
    }

    pub fn wait_for_decrypted(
        &self,
        lookup: TransactionLookup<'_>,
    ) -> Result<DecryptedTransaction, RingRpcClientError> {
        let TransactionLookup {
            ring,
            reader,
            signature,
        } = lookup;
        wait_for("ring rpc to open the transaction".to_owned(), || {
            let mut since = None;
            loop {
                let mut request = GetDecryptedTransactionsRequest::read(ring);
                if let Some(next) = since.take() {
                    request = request.with_since(next);
                }
                let page = match self.decrypted_transactions(&request.sign(reader)?) {
                    Ok(page) => page,
                    Err(error) => return Ok(Probe::Retry(error)),
                };
                if let Some(item) = page
                    .value
                    .items
                    .into_iter()
                    .find(|item| item.tx_signature.0 == signature)
                {
                    return Ok(Probe::Ready(item));
                }
                if let Some(skipped) = page
                    .value
                    .skipped
                    .iter()
                    .find(|item| item.tx_signature.0 == signature)
                {
                    return Err(RingRpcClientError::Skipped {
                        signature,
                        reason: skipped.reason,
                    });
                }
                match page.value.next {
                    Some(next) => since = Some(next),
                    None => return Ok(Probe::NotYet),
                }
            }
        })
        .map_err(|error| match error {
            WaitError::Timeout { label, last } => RingRpcClientError::Timeout { label, last },
            WaitError::Failed(error) => error,
        })
    }

    fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> Result<T, RingRpcClientError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let response: JsonRpcResponse<T> = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .map_err(|source| RingRpcClientError::Unreachable {
                url: self.url.clone(),
                source,
            })?
            .error_for_status()?
            .json()?;
        if let Some(error) = response.error {
            return Err(RingRpcClientError::Rpc { method, error });
        }
        response
            .result
            .ok_or(RingRpcClientError::EmptyResult { method })
    }
}

#[cfg(test)]
mod tests {
    use zolana_keypair::ViewingKey;

    use super::*;

    const SERVICE: Address = Address::new_from_array([7u8; 32]);

    fn attested(auditor_pk: P256Pubkey) -> AttestedAuditorKey {
        AttestedAuditorKey {
            auditor_pk,
            service_pubkey: SERVICE,
        }
    }

    #[test]
    fn trust_accepts_the_pinned_key_or_an_explicit_waiver() {
        let auditor_pk = ViewingKey::new().pubkey();
        assert_eq!(
            attested(auditor_pk)
                .require(Trust::Pinned(SERVICE))
                .expect("pinned"),
            auditor_pk
        );
        assert_eq!(
            attested(auditor_pk)
                .require(Trust::Unpinned)
                .expect("unpinned"),
            auditor_pk
        );
        assert!(matches!(
            attested(auditor_pk).require(Trust::Pinned(Address::new_from_array([8u8; 32]))),
            Err(RingRpcClientError::PinMismatch { .. })
        ));
        assert!(matches!(
            attested(auditor_pk).require(Trust::Refuse),
            Err(RingRpcClientError::Unpinned { .. })
        ));
    }
}
