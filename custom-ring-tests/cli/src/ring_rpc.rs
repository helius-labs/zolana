//! Client side of the ring RPC, the auditor's view of the ring.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::json;
use solana_address::Address;
use solana_signature::Signature;
use zolana_keypair::P256Pubkey;
use zolana_ring_client::auditor_view_tag;
use zolana_ring_rpc::api::{
    CreateAuditorKeyRequest, CreateAuditorKeyResponse, DecryptedTransaction,
    GetDecryptedTransactionsRequest, GetDecryptedTransactionsResponse, HealthResponse,
    CREATE_AUDITOR_KEY, GET_DECRYPTED_TRANSACTIONS, HEALTH,
};

use crate::transfer::wait_for;

pub struct RingRpc {
    url: String,
    http: reqwest::blocking::Client,
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

    pub fn health(&self) -> Result<HealthResponse> {
        self.call(HEALTH, json!({}))
    }

    /// The auditor public key the RPC holds for `ring`. Derived instances mint
    /// it on first call; a local instance returns its one key.
    pub fn auditor_pubkey(&self, ring: Address) -> Result<P256Pubkey> {
        let created: CreateAuditorKeyResponse = self
            .call(
                CREATE_AUDITOR_KEY,
                serde_json::to_value(CreateAuditorKeyRequest {
                    ring_program_id: ring.to_bytes().into(),
                })?,
            )
            .with_context(|| format!("no ring rpc answers at {}", self.url))?;
        let bytes: [u8; 33] = created
            .auditor_pubkey
            .0
            .try_into()
            .map_err(|_| anyhow!("ring rpc returned an auditor key of the wrong length"))?;
        Ok(P256Pubkey::from_bytes(bytes)?)
    }

    /// The RPC at this URL must hold the key behind `auditor_pk`; another
    /// ring's RPC on the same port answers `health` but can open nothing here.
    pub fn check_serves(&self, ring: Address, auditor_pk: &P256Pubkey) -> Result<()> {
        let served = self.auditor_pubkey(ring)?;
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

    /// The instance selects the ring by program id when it derives keys.
    pub fn transactions_request(ring: Address) -> GetDecryptedTransactionsRequest {
        GetDecryptedTransactionsRequest {
            ring_program_id: Some(ring.to_bytes().into()),
            ..Default::default()
        }
    }

    pub fn decrypted_transactions(
        &self,
        request: &GetDecryptedTransactionsRequest,
    ) -> Result<GetDecryptedTransactionsResponse> {
        self.call(GET_DECRYPTED_TRANSACTIONS, serde_json::to_value(request)?)
    }

    /// Walk every page until `signature` shows up as an opened transaction.
    pub fn wait_for_decrypted(
        &self,
        ring: Address,
        signature: Signature,
    ) -> Result<DecryptedTransaction> {
        wait_for("ring rpc to open the transaction", || {
            let mut request = Self::transactions_request(ring);
            loop {
                let page = self.decrypted_transactions(&request)?;
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
                    Some(cursor) => request.cursor = Some(cursor),
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
