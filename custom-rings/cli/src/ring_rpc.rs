//! Client side of the ring RPC, the auditor's view of the ring.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::json;
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_indexer_api::Base64String;
use zolana_keypair::P256Pubkey;
use zolana_ring_client::auditor_view_tag;
use zolana_ring_rpc::api::{
    auditor_key_attestation, read_attestation, CreateAuditorKeyRequest, CreateAuditorKeyResponse,
    DecryptedTransaction, GetDecryptedTransactionsRequest, GetDecryptedTransactionsResponse,
    ReadAuth, CREATE_AUDITOR_KEY, GET_DECRYPTED_TRANSACTIONS,
};

use crate::transfer::wait_for;

pub struct RingRpc {
    url: String,
    http: reqwest::blocking::Client,
}

/// An auditor key the RPC handed out, and the service key that signed for it.
pub struct AttestedAuditorKey {
    pub auditor_pk: P256Pubkey,
    pub service_pubkey: Address,
}

impl AttestedAuditorKey {
    /// A ring that pinned its RPC's service key takes the auditor key only from
    /// that key. Without a pin the caller has to opt in explicitly, since a key
    /// baked into `create_config` cannot be changed afterwards.
    pub fn require(self, pinned: Option<Address>, trust_unpinned: bool) -> Result<P256Pubkey> {
        match pinned {
            Some(pinned) if pinned == self.service_pubkey => Ok(self.auditor_pk),
            Some(pinned) => Err(anyhow!(
                "the ring rpc signs with {} but ring.toml pins {pinned}",
                self.service_pubkey
            )),
            None if trust_unpinned => Ok(self.auditor_pk),
            None => Err(anyhow!(
                "ring.toml pins no ring rpc service key, the rpc signs with {}. Put it in \
                 [urls] ring_rpc_pubkey after confirming it out of band, or pass \
                 --trust-ring-rpc for a local instance",
                self.service_pubkey
            )),
        }
    }
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

impl RingRpc {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            http: reqwest::blocking::Client::new(),
        }
    }

    /// The auditor public key the RPC holds for `ring`, with the service key
    /// that attested it. Derived instances mint it on first call, a local
    /// instance returns its one key. The attestation signature is checked
    /// against the key the response names, so a caller that pins a service
    /// pubkey compares it with the returned one.
    pub fn auditor_pubkey(&self, ring: Address) -> Result<AttestedAuditorKey> {
        let created: CreateAuditorKeyResponse = self
            .call(
                CREATE_AUDITOR_KEY,
                serde_json::to_value(CreateAuditorKeyRequest {
                    ring_program_id: ring.to_bytes().into(),
                })?,
            )
            .with_context(|| format!("no ring rpc answers at {}", self.url))?;
        let service_pubkey = created.service_pubkey.0;
        if !created.signature.0.verify(
            service_pubkey.as_ref(),
            &auditor_key_attestation(&ring, &created.auditor_pubkey.0),
        ) {
            return Err(anyhow!(
                "the ring rpc at {} returned an auditor key its service key {service_pubkey} did not sign",
                self.url
            ));
        }
        let bytes: [u8; 33] = created
            .auditor_pubkey
            .0
            .try_into()
            .map_err(|_| anyhow!("ring rpc returned an auditor key of the wrong length"))?;
        Ok(AttestedAuditorKey {
            auditor_pk: P256Pubkey::from_bytes(bytes)?,
            service_pubkey,
        })
    }

    /// The RPC at this URL must hold the key behind `auditor_pk`; another
    /// ring's RPC on the same port answers `health` but can open nothing here.
    pub fn check_serves(&self, ring: Address, auditor_pk: &P256Pubkey) -> Result<()> {
        let served = self.auditor_pubkey(ring)?.auditor_pk;
        if served != *auditor_pk {
            return Err(anyhow!(
                "the ring rpc at {} serves auditor tag {} but this ring's key has tag {}; \
                 stop it or point ring.toml at another port",
                self.url,
                zolana_indexer_api::Hash(auditor_view_tag(&served)),
                zolana_indexer_api::Hash(auditor_view_tag(auditor_pk))
            ));
        }
        Ok(())
    }

    /// One page of opened transactions, the request signed by `reader`, which
    /// must be the ring's on-chain authority.
    pub fn decrypted_transactions(
        &self,
        ring: Address,
        reader: &dyn Signer,
        cursor: Option<Base64String>,
    ) -> Result<GetDecryptedTransactionsResponse> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or_default();
        let message = read_attestation(
            &ring,
            timestamp,
            cursor.as_ref().map(|cursor| cursor.0.as_slice()),
            None,
        );
        let request = GetDecryptedTransactionsRequest {
            ring_program_id: Some(ring.to_bytes().into()),
            cursor,
            limit: None,
            auth: ReadAuth {
                reader: reader.pubkey().to_bytes().into(),
                timestamp,
                signature: reader.sign_message(&message).into(),
            },
        };
        self.call(GET_DECRYPTED_TRANSACTIONS, serde_json::to_value(request)?)
    }

    /// Walk every page until `signature` shows up as an opened transaction.
    pub fn wait_for_decrypted(
        &self,
        ring: Address,
        reader: &dyn Signer,
        signature: Signature,
    ) -> Result<DecryptedTransaction> {
        wait_for("ring rpc to open the transaction", || {
            let mut cursor = None;
            loop {
                let page = self.decrypted_transactions(ring, reader, cursor.take())?;
                if let Some(item) = page
                    .value
                    .items
                    .into_iter()
                    .find(|item| item.tx_signature.0 == signature)
                {
                    return Ok(Some(item));
                }
                if let Some(skipped) = page
                    .value
                    .skipped
                    .iter()
                    .find(|item| item.tx_signature.0 == signature)
                {
                    return Err(anyhow!(
                        "ring rpc could not open {signature}: {}",
                        skipped.reason
                    ));
                }
                match page.value.cursor {
                    Some(next) => cursor = Some(next),
                    None => return Ok(None),
                }
            }
        })
    }

    fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let response: JsonRpcResponse<T> = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .with_context(|| format!("ring rpc {method} at {}", self.url))?
            .error_for_status()?
            .json()?;
        if let Some(error) = response.error {
            return Err(anyhow!("ring rpc {method}: {error}"));
        }
        response
            .result
            .ok_or_else(|| anyhow!("ring rpc {method}: empty result"))
    }
}
