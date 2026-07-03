//! Minimal blocking client for the photon `get_nullifier_queue_elements` RPC.
//!
//! The on-chain nullifier queue keeps only bloom filters and hash chains, not
//! the raw queued values, so the forester cannot rebuild the reference tree
//! from the account alone. Photon already indexes every queued nullifier (in
//! `rings_tx_nullifiers`); this read-only RPC serves them back, ordered by
//! input-queue sequence, so the forester can replay them into its reference
//! `IndexedMerkleTree`.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use solana_pubkey::Pubkey;

/// Blocking JSON-RPC client for photon. Construct on a thread with no Tokio
/// runtime (`reqwest::blocking` panics inside one).
pub struct PhotonClient {
    url: String,
    http: reqwest::blocking::Client,
}

/// One queued nullifier in on-chain input-queue order.
#[derive(Debug, Clone)]
pub struct QueuedNullifier {
    pub seq: u64,
    pub value: [u8; 32],
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<QueueResult>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct QueueResult {
    elements: Vec<QueueElement>,
}

#[derive(Deserialize)]
struct QueueElement {
    seq: u64,
    /// base58, matching photon's `Hash` serialization.
    value: String,
}

impl PhotonClient {
    pub fn new(url: String) -> Self {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("failed to build photon HTTP client");
        Self { url, http }
    }

    /// Fetch queued nullifier values for `tree` with `input_queue_seq >=
    /// start_seq`, ordered ascending, up to `limit` elements.
    pub fn fetch_queued(
        &self,
        tree: Pubkey,
        start_seq: u64,
        limit: u64,
    ) -> Result<Vec<QueuedNullifier>> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_nullifier_queue_elements",
            "params": {
                "tree_account": tree.to_string(),
                "start_seq": start_seq,
                "limit": limit,
            },
        });
        let response: RpcResponse = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .with_context(|| format!("photon request to {} failed", self.url))?
            .error_for_status()
            .context("photon returned an HTTP error")?
            .json()
            .context("decode photon response")?;

        if let Some(err) = response.error {
            return Err(anyhow!("photon rpc error {}: {}", err.code, err.message));
        }
        let result = response
            .result
            .ok_or_else(|| anyhow!("photon response missing result"))?;

        result
            .elements
            .into_iter()
            .map(|element| {
                let decoded = bs58::decode(&element.value)
                    .into_vec()
                    .with_context(|| format!("decode nullifier {}", element.value))?;
                let value: [u8; 32] = decoded.try_into().map_err(|bytes: Vec<u8>| {
                    anyhow!(
                        "nullifier {} decoded to {} bytes, expected 32",
                        element.value,
                        bytes.len()
                    )
                })?;
                Ok(QueuedNullifier {
                    seq: element.seq,
                    value,
                })
            })
            .collect()
    }
}
