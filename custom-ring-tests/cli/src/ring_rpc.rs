//! Client side of the ring RPC, the auditor's view of the ring.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::json;
use solana_signature::Signature;
use zolana_ring_rpc::api::{
    DecryptedTransaction, GetDecryptedTransactionsRequest, GetDecryptedTransactionsResponse,
    HealthResponse, GET_DECRYPTED_TRANSACTIONS, HEALTH,
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

    pub fn decrypted_transactions(
        &self,
        request: &GetDecryptedTransactionsRequest,
    ) -> Result<GetDecryptedTransactionsResponse> {
        self.call(GET_DECRYPTED_TRANSACTIONS, serde_json::to_value(request)?)
    }

    /// Walk every page until `signature` shows up as an opened transaction.
    pub fn wait_for_decrypted(&self, signature: Signature) -> Result<DecryptedTransaction> {
        wait_for("ring rpc to open the transaction", || {
            let mut request = GetDecryptedTransactionsRequest::default();
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
