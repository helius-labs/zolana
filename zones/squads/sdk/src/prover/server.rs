//! Minimal blocking HTTP client for the prover server's `/prove` endpoint.
//!
//! The `zolana-client` `ProverClient::send` is private and hard-wired to the
//! transfer/merge circuits, so this mirrors its request/retry behaviour for the
//! `squads-key-encryption` circuit and returns the raw gnark proof JSON for
//! [`crate::prover::proof`] to compress. Use `zolana_client::prover::spawn_prover`
//! to start a server before calling this.

use std::{thread::sleep, time::Duration};

use crate::prover::error::SquadsProverError;

const PROVE_PATH: &str = "/prove";
// A cold key-encryption request lazy-loads a 130-200MB proving key and runs a
// large Groth16 prove; allow several minutes and retry dropped connections.
const PROVE_MAX_ATTEMPTS: usize = 3;
const PROVE_RETRY_BACKOFF_SECS: u64 = 2;
const PROVE_REQUEST_TIMEOUT_SECS: u64 = 600;
const PROVE_CONNECT_TIMEOUT_SECS: u64 = 10;

fn build_http_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(PROVE_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(PROVE_REQUEST_TIMEOUT_SECS))
        .build()
        .expect("failed to build HTTP client")
}

/// POST `body` to `<server_address>/prove`, retrying dropped connections, and
/// return the gnark proof JSON object as a string (the `proof` field of the
/// `{ "proof": .., "proof_duration_ms": .. }` envelope, or the bare proof).
pub(crate) fn send_prove_request(
    server_address: &str,
    body: &str,
) -> Result<String, SquadsProverError> {
    let http = build_http_client();
    let url = format!("{server_address}{PROVE_PATH}");
    let mut attempt = 0;
    let response = loop {
        attempt += 1;
        match http
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
        {
            Ok(response) => break response,
            Err(_) if attempt < PROVE_MAX_ATTEMPTS => {
                sleep(Duration::from_secs(PROVE_RETRY_BACKOFF_SECS));
            }
            Err(e) => {
                return Err(SquadsProverError::ProverServer(format!(
                    "request failed after {attempt} attempt(s): {e}"
                )));
            }
        }
    };

    let status = response.status();
    let text = response
        .text()
        .map_err(|e| SquadsProverError::ProverServer(format!("failed to read body: {e}")))?;
    if !status.is_success() {
        return Err(SquadsProverError::ProverServer(format!(
            "status {status}: {text}"
        )));
    }

    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| SquadsProverError::ProofParse(format!("invalid response JSON: {e}")))?;
    let proof_value = value.get("proof").unwrap_or(&value);
    if proof_value.is_null() {
        return Err(SquadsProverError::ProverServer(
            "server returned a null proof".to_string(),
        ));
    }
    serde_json::to_string(proof_value)
        .map_err(|e| SquadsProverError::ProofParse(format!("re-serialize proof: {e}")))
}
