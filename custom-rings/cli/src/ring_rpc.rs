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
    ReadBuildError, SkippedReason, CREATE_AUDITOR_KEY, GET_DECRYPTED_TRANSACTIONS,
};

use crate::{
    init::configured_auditor_pk,
    transact::{wait_for, Probe, WaitError},
    Context, InitError,
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
    #[error("the ring rpc at {url} serves auditor tag {served_tag} but this ring's key has tag {expected_tag}, stop it or point ring.toml at another port")]
    ServesAnotherRing {
        url: String,
        served_tag: Hash,
        expected_tag: Hash,
    },
    #[error(transparent)]
    Read(#[from] ReadBuildError),
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

#[derive(Debug, Error)]
pub enum RpcCheckError {
    #[error(transparent)]
    Init(#[from] InitError),
    #[error(transparent)]
    RingRpc(#[from] RingRpcClientError),
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

pub fn run_check(ctx: &Context) -> Result<(), RpcCheckError> {
    let auditor_pk = configured_auditor_pk(&ctx.rpc, ctx.ring)?;
    ctx.ring_rpc()
        .check_serves(ctx.ring.program_id(), &auditor_pk)?;
    println!(
        "ring rpc    {} serves this ring",
        ctx.config.urls().ring_rpc
    );
    Ok(())
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
            http: reqwest::blocking::Client::new(),
        }
    }

    /// Verified against the service key the response names, the caller decides whether to trust that key.
    pub fn auditor_pubkey(&self, ring: Address) -> Result<AttestedAuditorKey, RingRpcClientError> {
        let created: CreateAuditorKeyResponse = self.call(
            CREATE_AUDITOR_KEY,
            serde_json::to_value(CreateAuditorKeyRequest {
                ring_program_id: ring.to_bytes().into(),
            })?,
        )?;
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

    /// Another ring's RPC on the same port answers `health` but can open nothing here.
    pub fn check_serves(
        &self,
        ring: Address,
        auditor_pk: &P256Pubkey,
    ) -> Result<(), RingRpcClientError> {
        let served = self.auditor_pubkey(ring)?.auditor_pk;
        if served != *auditor_pk {
            return Err(RingRpcClientError::ServesAnotherRing {
                url: self.url.clone(),
                served_tag: Hash(auditor_view_tag(&served)),
                expected_tag: Hash(auditor_view_tag(auditor_pk)),
            });
        }
        Ok(())
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
            let mut cursor = None;
            loop {
                let mut request = GetDecryptedTransactionsRequest::read(ring);
                if let Some(next) = cursor.take() {
                    request = request.with_cursor(next)?;
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
                match page.value.cursor {
                    Some(next) => cursor = Some(next),
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
