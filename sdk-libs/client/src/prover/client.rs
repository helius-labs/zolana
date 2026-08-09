use std::{
    env,
    net::IpAddr,
    path::Path,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    thread::sleep,
    time::Duration,
};

use tokio::time::sleep as async_sleep;

use crate::{
    error::ClientError,
    prover::{
        aggregate::{to_json_aggregate, AggregateInputs},
        inputs::{BatchAddressAppendInputs, MergeInputs, TransferInputs, TransferP256Inputs},
        json::{
            to_json, to_json_batch_address_append, to_json_merge, to_json_merge_ring,
            to_json_p256_ring, to_json_ring, to_json_ring_authority,
        },
        merge_chain::{to_json_merge_chain, MergeChainInputs},
        nullifier_fold::{to_json_nullifier_fold, NullifierFoldInputs},
        proof::{proof_from_gnark_json, Proof},
    },
};

pub const SERVER_ADDRESS: &str = "http://127.0.0.1:3001";
pub const HEALTH_CHECK: &str = "/health";
pub const PROVE_PATH: &str = "/prove";
const CLIENT_API_KEY_ENV: &str = "ZOLANA_PROVER_API_KEY";
const SHARED_API_KEY_ENV: &str = "PROVER_API_KEY";

/// Default prover port, mirrored from the CLI's `DEFAULT_PROVER_PORT`. Used as
/// the fallback when a custom [`server_address`] has no parseable port.
const DEFAULT_PROVER_PORT: u16 = 3001;

/// Address the local prover client connects to and that [`spawn_prover`] starts
/// the server on. Defaults to [`SERVER_ADDRESS`]; set `ZOLANA_PROVER_URL` per
/// local clone to avoid port contention between concurrent checkouts.
pub fn server_address() -> String {
    match env::var("ZOLANA_PROVER_URL") {
        Ok(url) if !url.trim().is_empty() => url.trim().to_string(),
        _ => SERVER_ADDRESS.to_string(),
    }
}

/// Extract the TCP port from a prover address so [`spawn_prover`] starts the
/// server on the same port the client will connect to. Falls back to
/// [`DEFAULT_PROVER_PORT`] when the address carries no parseable port.
fn prover_port(server_address: &str) -> u16 {
    server_address
        .rsplit(':')
        .next()
        .map(|s| s.trim_end_matches('/'))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PROVER_PORT)
}

const STARTUP_HEALTH_CHECK_RETRIES: usize = 300;
static IS_LOADING: AtomicBool = AtomicBool::new(false);

// A cold proof can drop the HTTP connection under load while the server stays up.
// Proof generation is idempotent, so the request is retried and the warm key proves
// quickly.
const PROVE_MAX_ATTEMPTS: usize = 3;
const PROVE_RETRY_BACKOFF_SECS: u64 = 2;
// Upper bound so a slow cold prove cannot hang the client. The server times out sync
// work first.
const PROVE_REQUEST_TIMEOUT_SECS: u64 = 600;
const PROVE_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Polling cadence and ceiling for async (queued) proofs. Queue-backed provers
/// return a job handle immediately. The client polls the status endpoint until
/// the proof completes or `max_wait_secs` elapses. The first batch job loads its
/// proving key before proving, so the default ceiling is generous.
///
/// Held on the [`ProverClient`] and overridable via
/// [`ProverClient::with_async_poll_config`].
#[derive(Clone, Copy, Debug)]
pub struct AsyncPollConfig {
    /// Seconds between `/prove/status` polls (floored at 1 so it can't spin).
    pub poll_interval_secs: u64,
    /// Max seconds to wait for a queued proof before returning a timeout error.
    pub max_wait_secs: u64,
}

impl Default for AsyncPollConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 3,
            max_wait_secs: 1200,
        }
    }
}

fn build_http_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(PROVE_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(PROVE_REQUEST_TIMEOUT_SECS))
        .build()
        .expect("client options are valid, only a broken TLS backend can fail here")
}

fn build_async_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(PROVE_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(PROVE_REQUEST_TIMEOUT_SECS))
        .build()
        .expect("client options are valid, only a broken TLS backend can fail here")
}

fn configured_api_key() -> Option<String> {
    [CLIENT_API_KEY_ENV, SHARED_API_KEY_ENV]
        .into_iter()
        .find_map(|name| env::var(name).ok().and_then(nonempty_api_key))
}

fn nonempty_api_key(api_key: String) -> Option<String> {
    let api_key = api_key.trim();
    (!api_key.is_empty()).then(|| api_key.to_string())
}

/// What a proof request's inputs reveal to whoever proves them. The
/// classification travels with the payload, so a new request type cannot pick
/// up a transport policy by which method happened to send it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputSensitivity {
    /// The payload carries wallet secrets. `merge-chain` legs carry the
    /// commitment-to-nullifier linkage and the owner identity the protocol
    /// hides, so they belong here with the spend circuits.
    WalletSecrets,
    /// The payload carries only hashes and roots that are already public.
    PublicOnly,
}

/// A prove request and what its inputs reveal.
pub(crate) struct ProofRequest {
    body: String,
    sensitivity: InputSensitivity,
}

impl ProofRequest {
    pub(crate) fn wallet_secrets(body: String) -> Self {
        Self {
            body,
            sensitivity: InputSensitivity::WalletSecrets,
        }
    }

    pub(crate) fn public_only(body: String) -> Self {
        Self {
            body,
            sensitivity: InputSensitivity::PublicOnly,
        }
    }
}

fn validate_prover_transport(
    server_address: &str,
    sensitivity: InputSensitivity,
) -> Result<(), ClientError> {
    let url = reqwest::Url::parse(server_address).map_err(|_| ClientError::ProverUrlMalformed {
        server_address: server_address.to_string(),
    })?;
    let loopback = url.host_str().is_some_and(|host| {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if loopback {
        return Ok(());
    }
    if sensitivity == InputSensitivity::WalletSecrets {
        return Err(ClientError::ProverRequiresLocalTransport {
            server_address: server_address.to_string(),
        });
    }
    if url.scheme() != "https" {
        return Err(ClientError::ProverTransportNotHttps {
            server_address: server_address.to_string(),
        });
    }
    Ok(())
}

/// Blocking client for the transfer proving endpoints of the prover server.
pub struct ProverClient {
    server_address: String,
    http: reqwest::blocking::Client,
    async_poll: AsyncPollConfig,
    api_key: Option<String>,
}

/// Async client for the transfer proving endpoints of the prover server.
pub struct AsyncProverClient {
    server_address: String,
    http: reqwest::Client,
    async_poll: AsyncPollConfig,
    api_key: Option<String>,
}

impl Default for ProverClient {
    fn default() -> Self {
        Self::local()
    }
}

impl Default for AsyncProverClient {
    fn default() -> Self {
        Self::local()
    }
}

impl ProverClient {
    pub fn local() -> Self {
        Self::new(server_address())
    }

    pub fn new(server_address: String) -> Self {
        Self {
            server_address,
            http: build_http_client(),
            async_poll: AsyncPollConfig::default(),
            api_key: configured_api_key(),
        }
    }

    /// Authenticate prover requests with a bearer token. An empty token is a
    /// configuration mistake, so it is rejected rather than read as a request
    /// to send unauthenticated.
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Result<Self, ClientError> {
        self.api_key =
            Some(nonempty_api_key(api_key.into()).ok_or(ClientError::EmptyProverApiKey)?);
        Ok(self)
    }

    /// Send prover requests unauthenticated, dropping any key the environment
    /// supplied.
    pub fn without_api_key(mut self) -> Self {
        self.api_key = None;
        self
    }

    /// Override the async-proof polling config (see [`AsyncPollConfig`]).
    pub fn with_async_poll_config(mut self, config: AsyncPollConfig) -> Self {
        self.async_poll = config;
        self
    }

    /// Prove a Solana-only (eddsa) transfer, returning the uncompressed negated proof.
    /// Call [`Proof::compress`] for the wire format.
    pub fn prove_transfer(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.send(ProofRequest::wallet_secrets(to_json(inputs)))
    }

    /// Prove an 8-in/1-out merge, returning the uncompressed negated proof.
    /// Call [`Proof::compress`] for the wire format.
    pub fn prove_merge(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.send(ProofRequest::wallet_secrets(to_json_merge(inputs)))
    }

    /// Prove a ring-authority transfer (anonymous, no signature), returning the
    /// uncompressed negated proof. Reuses the Solana-only [`TransferInputs`].
    /// Call [`Proof::compress`] for the wire format.
    pub fn prove_ring_authority(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.send(ProofRequest::wallet_secrets(to_json_ring_authority(inputs)))
    }

    /// Prove a policy-ring merge (`merge-ring`), returning the uncompressed negated
    /// proof. Reuses [`MergeInputs`]. Call [`Proof::compress`] for the wire format.
    pub fn prove_merge_ring(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.send(ProofRequest::wallet_secrets(to_json_merge_ring(inputs)))
    }

    /// Prove an eddsa confidential policy-ring transfer (`transfer-ring`).
    pub fn prove_transfer_ring(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.send(ProofRequest::wallet_secrets(to_json_ring(inputs)))
    }

    /// Batch transfer proofs into one recursive proof.
    pub fn prove_aggregate(&self, inputs: &AggregateInputs) -> Result<Proof, ClientError> {
        self.send(ProofRequest::public_only(to_json_aggregate(inputs)))
    }

    /// Chain merge proofs into one recursive proof, collapsing more UTXOs than
    /// the merge circuit's fixed eight inputs. Each leg names its input UTXO
    /// hashes, nullifiers and signer, so the request stays on the device.
    pub fn prove_merge_chain(&self, inputs: &MergeChainInputs) -> Result<Proof, ClientError> {
        self.send(ProofRequest::wallet_secrets(to_json_merge_chain(inputs)))
    }

    /// Prove a custom-ring P256 transfer.
    pub fn prove_transfer_p256_ring(
        &self,
        inputs: &TransferP256Inputs,
    ) -> Result<Proof, ClientError> {
        self.send(ProofRequest::wallet_secrets(to_json_p256_ring(inputs)))
    }

    /// Prove a nullifier-tree batch address-append update, returning the
    /// uncompressed negated proof. Call [`ProofCompressed::try_from`] for the
    /// SPP instruction wire format.
    pub fn prove_batch_address_append(
        &self,
        inputs: &BatchAddressAppendInputs,
    ) -> Result<Proof, ClientError> {
        self.send(ProofRequest::public_only(to_json_batch_address_append(
            inputs,
        )))
    }

    pub fn prove_nullifier_fold(&self, inputs: &NullifierFoldInputs) -> Result<Proof, ClientError> {
        self.send(ProofRequest::public_only(to_json_nullifier_fold(inputs)))
    }

    /// POST a prove request and return the gnark proof object as JSON text.
    /// Callers that parse a circuit-specific proof shape use this instead of the
    /// typed prove methods.
    pub fn send_raw(
        &self,
        body: String,
        sensitivity: InputSensitivity,
    ) -> Result<String, ClientError> {
        let value = self.send_value(ProofRequest { body, sensitivity })?;
        let proof_value = value.get("proof").unwrap_or(&value);
        if proof_value.is_null() {
            return Err(ClientError::ProverServer(
                "server returned a null proof".to_string(),
            ));
        }
        serde_json::to_string(proof_value)
            .map_err(|e| ClientError::ProofParse(format!("failed to re-serialize proof: {e}")))
    }

    fn send(&self, request: ProofRequest) -> Result<Proof, ClientError> {
        let value = self.send_value(request)?;
        Self::proof_from_value(&value, &value.to_string())
    }

    /// Run one prove request to completion, polling a queued job if the server
    /// returned a handle, and return the response value.
    fn send_value(&self, request: ProofRequest) -> Result<serde_json::Value, ClientError> {
        let ProofRequest { body, sensitivity } = request;
        validate_prover_transport(&self.server_address, sensitivity)?;
        let url = format!("{}{}", self.server_address, PROVE_PATH);
        let mut attempt = 0;
        let response = loop {
            attempt += 1;
            let mut request = self
                .http
                .post(&url)
                .header("Content-Type", "application/json")
                .body(body.clone());
            if let Some(api_key) = &self.api_key {
                request = request.bearer_auth(api_key);
            }
            let outcome = request.send();
            match outcome {
                Ok(response) => break response,
                Err(_) if attempt < PROVE_MAX_ATTEMPTS => {
                    sleep(Duration::from_secs(PROVE_RETRY_BACKOFF_SECS));
                }
                Err(e) => {
                    return Err(ClientError::ProverServer(format!(
                        "request failed after {attempt} attempt(s): {e}"
                    )));
                }
            }
        };

        let status = response.status();
        let text = response
            .text()
            .map_err(|e| ClientError::ProverServer(format!("failed to read response body: {e}")))?;
        if !status.is_success() {
            return Err(ClientError::ProverServer(format!(
                "status {status}: {text}"
            )));
        }

        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| ClientError::ProofParse(format!("invalid response JSON: {e}")))?;

        // A Redis-backed prover queues supported proofs and returns a job
        // handle (`{ job_id, status, status_url }`) instead of a proof; poll the
        // status endpoint until it completes. A synchronous prover returns the
        // proof directly (plain gnark JSON or a `{ proof, .. }` envelope).
        if value.get("proof").is_none() {
            if let Some(job_id) = value.get("job_id").and_then(|v| v.as_str()) {
                return self.poll_async(job_id);
            }
        }
        Ok(value)
    }

    /// Poll the async job status endpoint until the queued proof completes.
    fn poll_async(&self, job_id: &str) -> Result<serde_json::Value, ClientError> {
        let url = format!("{}/prove/status?job_id={}", self.server_address, job_id);
        let poll_interval = self.async_poll.poll_interval_secs.max(1);
        let max_wait = self.async_poll.max_wait_secs;
        let mut waited = 0u64;
        loop {
            let mut request = self.http.get(&url);
            if let Some(api_key) = &self.api_key {
                request = request.bearer_auth(api_key);
            }
            let response = match request.send() {
                Ok(response) => response,
                Err(_) => {
                    wait_or_timeout(job_id, &mut waited, max_wait, poll_interval)?;
                    continue;
                }
            };
            let status = response.status();
            if status.is_client_error() {
                let text = match response.text() {
                    Ok(text) => text,
                    Err(e) => format!("failed to read status body: {e}"),
                };
                return Err(ClientError::ProverServer(format!(
                    "status {status}: {text}"
                )));
            }
            if status.is_server_error() {
                wait_or_timeout(job_id, &mut waited, max_wait, poll_interval)?;
                continue;
            }

            let text = match response.text() {
                Ok(text) => text,
                Err(_) => {
                    wait_or_timeout(job_id, &mut waited, max_wait, poll_interval)?;
                    continue;
                }
            };
            let value: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| ClientError::ProofParse(format!("invalid status JSON: {e}")))?;

            match value.get("status").and_then(|v| v.as_str()) {
                // The completed result is a `{ proof, proof_duration_ms }` envelope
                // nested under `result`.
                Some("completed") => {
                    return Ok(value.get("result").cloned().unwrap_or(value));
                }
                Some("failed") => {
                    return Err(ClientError::ProverServer(format!(
                        "async proof failed (job {job_id}): {text}"
                    )));
                }
                // queued / processing / unknown: keep polling until the bound.
                _ => {
                    wait_or_timeout(job_id, &mut waited, max_wait, poll_interval)?;
                }
            }
        }
    }

    /// Extract and parse a gnark proof from a proof value, accepting either a
    /// plain proof object or a `{ proof, .. }` envelope.
    fn proof_from_value(value: &serde_json::Value, raw: &str) -> Result<Proof, ClientError> {
        let proof_value = value.get("proof").unwrap_or(value);
        if proof_value.is_null() {
            return Err(ClientError::ProverServer(
                "server returned a null proof".to_string(),
            ));
        }
        let proof_json = serde_json::to_string(proof_value)
            .map_err(|e| ClientError::ProofParse(format!("failed to re-serialize proof: {e}")))?;
        proof_from_gnark_json(&proof_json)
            .ok_or_else(|| ClientError::ProofParse(format!("could not parse proof: {raw}")))
    }
}

fn wait_or_timeout(
    job_id: &str,
    waited: &mut u64,
    max_wait: u64,
    poll_interval: u64,
) -> Result<(), ClientError> {
    if *waited >= max_wait {
        let waited_secs = *waited;
        return Err(ClientError::ProverServer(format!(
            "async proof timed out after {waited_secs}s (job {job_id})"
        )));
    }
    let remaining = max_wait.saturating_sub(*waited);
    let sleep_secs = poll_interval.min(remaining);
    sleep(Duration::from_secs(sleep_secs));
    *waited = (*waited).saturating_add(sleep_secs);
    Ok(())
}

impl AsyncProverClient {
    pub fn local() -> Self {
        Self::new(server_address())
    }

    pub fn new(server_address: String) -> Self {
        Self {
            server_address,
            http: build_async_http_client(),
            async_poll: AsyncPollConfig::default(),
            api_key: configured_api_key(),
        }
    }

    /// Authenticate prover requests with a bearer token. An empty token is a
    /// configuration mistake, so it is rejected rather than read as a request
    /// to send unauthenticated.
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Result<Self, ClientError> {
        self.api_key =
            Some(nonempty_api_key(api_key.into()).ok_or(ClientError::EmptyProverApiKey)?);
        Ok(self)
    }

    /// Send prover requests unauthenticated, dropping any key the environment
    /// supplied.
    pub fn without_api_key(mut self) -> Self {
        self.api_key = None;
        self
    }

    /// Override the queued-proof polling config (see [`AsyncPollConfig`]).
    pub fn with_async_poll_config(mut self, config: AsyncPollConfig) -> Self {
        self.async_poll = config;
        self
    }

    /// Prove a Solana-only (eddsa) transfer, returning the uncompressed negated proof.
    /// Call [`Proof::compress`] for the wire format.
    pub async fn prove_transfer(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.send(ProofRequest::wallet_secrets(to_json(inputs)))
            .await
    }

    pub async fn prove_merge(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.send(ProofRequest::wallet_secrets(to_json_merge(inputs)))
            .await
    }

    pub async fn prove_ring_authority(
        &self,
        inputs: &TransferInputs,
    ) -> Result<Proof, ClientError> {
        self.send(ProofRequest::wallet_secrets(to_json_ring_authority(inputs)))
            .await
    }

    pub async fn prove_merge_ring(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.send(ProofRequest::wallet_secrets(to_json_merge_ring(inputs)))
            .await
    }

    pub async fn prove_transfer_ring(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.send(ProofRequest::wallet_secrets(to_json_ring(inputs)))
            .await
    }

    pub async fn prove_transfer_p256_ring(
        &self,
        inputs: &TransferP256Inputs,
    ) -> Result<Proof, ClientError> {
        self.send(ProofRequest::wallet_secrets(to_json_p256_ring(inputs)))
            .await
    }

    pub async fn prove_batch_address_append(
        &self,
        inputs: &BatchAddressAppendInputs,
    ) -> Result<Proof, ClientError> {
        self.send(ProofRequest::public_only(to_json_batch_address_append(
            inputs,
        )))
        .await
    }

    pub async fn prove_merge_chain(&self, inputs: &MergeChainInputs) -> Result<Proof, ClientError> {
        self.send(ProofRequest::wallet_secrets(to_json_merge_chain(inputs)))
            .await
    }

    async fn send(&self, request: ProofRequest) -> Result<Proof, ClientError> {
        let ProofRequest { body, sensitivity } = request;
        validate_prover_transport(&self.server_address, sensitivity)?;
        let url = format!("{}{}", self.server_address, PROVE_PATH);
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut request = self
                .http
                .post(&url)
                .header("Content-Type", "application/json")
                .body(body.clone());
            if let Some(api_key) = &self.api_key {
                request = request.bearer_auth(api_key);
            }
            let outcome = request.send().await;
            match outcome {
                Ok(response) => {
                    let status = response.status();
                    let text = response.text().await.map_err(|e| {
                        ClientError::ProverServer(format!("failed to read response body: {e}"))
                    })?;
                    if !status.is_success() {
                        return Err(ClientError::ProverServer(format!(
                            "status {status}: {text}"
                        )));
                    }

                    let value: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
                        ClientError::ProofParse(format!("invalid response JSON: {e}"))
                    })?;
                    if value.get("proof").is_none() {
                        if let Some(job_id) = value.get("job_id").and_then(|v| v.as_str()) {
                            return self.poll_async(job_id).await;
                        }
                    }
                    return ProverClient::proof_from_value(&value, &text);
                }
                Err(_) if attempt < PROVE_MAX_ATTEMPTS => {
                    async_sleep(Duration::from_secs(PROVE_RETRY_BACKOFF_SECS)).await;
                }
                Err(e) => {
                    return Err(ClientError::ProverServer(format!(
                        "request failed after {attempt} attempt(s): {e}"
                    )));
                }
            }
        }
    }

    async fn poll_async(&self, job_id: &str) -> Result<Proof, ClientError> {
        let url = format!("{}/prove/status?job_id={}", self.server_address, job_id);
        let poll_interval = self.async_poll.poll_interval_secs.max(1);
        let max_wait = self.async_poll.max_wait_secs;
        let mut waited = 0u64;
        loop {
            let mut request = self.http.get(&url);
            if let Some(api_key) = &self.api_key {
                request = request.bearer_auth(api_key);
            }
            let response = match request.send().await {
                Ok(response) => response,
                Err(_) => {
                    async_wait_or_timeout(job_id, &mut waited, max_wait, poll_interval).await?;
                    continue;
                }
            };
            let status = response.status();
            if status.is_client_error() {
                let text = match response.text().await {
                    Ok(text) => text,
                    Err(e) => format!("failed to read status body: {e}"),
                };
                return Err(ClientError::ProverServer(format!(
                    "status {status}: {text}"
                )));
            }
            if status.is_server_error() {
                async_wait_or_timeout(job_id, &mut waited, max_wait, poll_interval).await?;
                continue;
            }

            let text = match response.text().await {
                Ok(text) => text,
                Err(_) => {
                    async_wait_or_timeout(job_id, &mut waited, max_wait, poll_interval).await?;
                    continue;
                }
            };
            let value: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| ClientError::ProofParse(format!("invalid status JSON: {e}")))?;

            match value.get("status").and_then(|v| v.as_str()) {
                Some("completed") => {
                    let result = value.get("result").map_or(&value, |result| result);
                    return ProverClient::proof_from_value(result, &text);
                }
                Some("failed") => {
                    return Err(ClientError::ProverServer(format!(
                        "async proof failed (job {job_id}): {text}"
                    )));
                }
                _ => {
                    async_wait_or_timeout(job_id, &mut waited, max_wait, poll_interval).await?;
                }
            }
        }
    }
}

async fn async_wait_or_timeout(
    job_id: &str,
    waited: &mut u64,
    max_wait: u64,
    poll_interval: u64,
) -> Result<(), ClientError> {
    if *waited >= max_wait {
        let waited_secs = *waited;
        return Err(ClientError::ProverServer(format!(
            "async proof timed out after {waited_secs}s (job {job_id})"
        )));
    }
    let remaining = max_wait.saturating_sub(*waited);
    let sleep_secs = poll_interval.min(remaining);
    async_sleep(Duration::from_secs(sleep_secs)).await;
    *waited = (*waited).saturating_add(sleep_secs);
    Ok(())
}

/// Block until a prover server is reachable, starting one via the `zolana` CLI if
/// none is already running. Intended for tests.
pub fn spawn_prover() -> Result<(), ClientError> {
    spawn_prover_inner(None, None)
}

fn spawn_prover_inner(
    cli_override: Option<String>,
    keys_dir: Option<&Path>,
) -> Result<(), ClientError> {
    if health_check(10, 1) {
        return Ok(());
    }

    if IS_LOADING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // Another caller is already starting it; wait for that to finish.
        if health_check(STARTUP_HEALTH_CHECK_RETRIES, 1) {
            return Ok(());
        }
        return Err(ClientError::Prover(
            "prover failed to start (health check failed)".to_string(),
        ));
    }

    let Some(cli) = cli_override.or_else(get_cli_command) else {
        IS_LOADING.store(false, Ordering::Release);
        return Err(ClientError::Prover(
            "could not locate the `zolana` CLI; set ZOLANA_CLI_BIN or build target/debug/zolana"
                .to_string(),
        ));
    };

    let port = prover_port(&server_address());
    let redis_url = env::var("ZOLANA_PROVER_REDIS_URL").ok();
    let command = prover_start_command(&cli, port, redis_url.as_deref());
    let mut child_command = Command::new("sh");
    child_command.arg("-c").arg(command);
    if let Some(keys_dir) = keys_dir {
        child_command.env("ZOLANA_PROVER_KEYS_DIR", keys_dir);
    }
    let spawn_result = child_command.spawn();

    let result = match spawn_result {
        Ok(mut child) => {
            let healthy = health_check(STARTUP_HEALTH_CHECK_RETRIES, 1);
            if !healthy {
                let _ = child.kill();
                let _ = child.wait();
            }
            healthy
        }
        Err(e) => {
            IS_LOADING.store(false, Ordering::Release);
            return Err(ClientError::Prover(format!("failed to start prover: {e}")));
        }
    };

    IS_LOADING.store(false, Ordering::Release);

    if result {
        Ok(())
    } else {
        Err(ClientError::Prover(
            "prover failed to start (health check failed)".to_string(),
        ))
    }
}

/// Start the test prover from an explicit CLI binary and key-cache directory.
/// Repository tests use this entry point so neither artifact is discovered
/// from Git or `PATH`. A healthy server is reused so separate test binaries keep
/// its lazily loaded proving keys warm.
pub fn spawn_prover_with_artifacts(
    cli_bin: impl AsRef<Path>,
    keys_dir: impl AsRef<Path>,
) -> Result<(), ClientError> {
    let cli_bin = cli_bin.as_ref();
    if !cli_bin.is_file() {
        return Err(ClientError::Prover(format!(
            "zolana CLI is missing: {}; build it before starting the prover",
            cli_bin.display()
        )));
    }
    let keys_dir = keys_dir.as_ref();
    let parent = keys_dir.parent().ok_or_else(|| {
        ClientError::Prover(format!(
            "prover keys path has no parent: {}",
            keys_dir.display()
        ))
    })?;
    if !parent.is_dir() {
        return Err(ClientError::Prover(format!(
            "prover keys parent is missing: {}",
            parent.display()
        )));
    }
    spawn_prover_inner(
        Some(shell_quote(&cli_bin.to_string_lossy())),
        Some(keys_dir),
    )
}

fn health_check(retries: usize, timeout_secs: u64) -> bool {
    let client = build_http_client();
    let timeout = Duration::from_secs(timeout_secs);
    let address = server_address();
    for attempt in 0..retries {
        let ok = client
            .get(format!("{}{}", address, HEALTH_CHECK))
            .timeout(timeout)
            .send()
            .is_ok();
        if ok {
            return true;
        }
        if attempt + 1 < retries {
            sleep(timeout);
        }
    }
    false
}

fn get_cli_command() -> Option<String> {
    if let Ok(command) = env::var("ZOLANA_CLI_CMD") {
        let command = command.trim();
        if !command.is_empty() {
            return Some(command.to_string());
        }
    }
    if let Ok(path) = env::var("ZOLANA_CLI_BIN") {
        let path = path.trim();
        if !path.is_empty() {
            return Some(shell_quote(path));
        }
    }
    if let Some(project_root) = get_project_root() {
        for relative_path in ["target/debug/zolana", "target/release/zolana"] {
            let local_cli = Path::new(&project_root).join(relative_path);
            if local_cli.is_file() {
                return Some(shell_quote(&local_cli.to_string_lossy()));
            }
        }
    }
    find_in_path("zolana").map(|path| shell_quote(&path))
}

fn get_project_root() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if output.status.success() {
        String::from_utf8(output.stdout)
            .ok()
            .map(|root| root.trim().to_string())
    } else {
        None
    }
}

fn find_in_path(binary: &str) -> Option<String> {
    let paths = env::var_os("PATH")?;
    for dir in env::split_paths(&paths) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn prover_start_command(cli: &str, port: u16, redis_url: Option<&str>) -> String {
    let mut command = format!("{cli} dev prover start --prover-port {port}");
    if let Some(redis_url) = redis_url.filter(|url| !url.trim().is_empty()) {
        command.push_str(" --redis-url ");
        command.push_str(&shell_quote(redis_url.trim()));
    }
    command
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::mpsc,
        thread,
    };

    use serde_json::{json, Value};

    use super::*;

    #[test]
    fn prover_start_command_forwards_redis_url() {
        assert_eq!(
            prover_start_command(
                "'/tmp/zolana cli'",
                3002,
                Some("redis://localhost:6379/15")
            ),
            "'/tmp/zolana cli' dev prover start --prover-port 3002 --redis-url 'redis://localhost:6379/15'"
        );
    }

    #[test]
    fn prover_start_command_omits_empty_redis_url() {
        assert_eq!(
            prover_start_command("zolana", 3001, Some("  ")),
            "zolana dev prover start --prover-port 3001"
        );
    }

    #[test]
    fn poll_async_returns_completed_nested_proof() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(
                202,
                json!({
                    "job_id": "job-1",
                    "status": "queued",
                    "status_url": "/prove/status?job_id=job-1",
                }),
            ),
            MockResponse::json(200, json!({ "status": "queued" })),
            MockResponse::json(
                200,
                json!({
                    "status": "completed",
                    "result": {
                        "proof": gnark_proof(),
                        "proof_duration_ms": 7,
                    },
                }),
            ),
        ]);
        let proof = queued_prover_client(server.url())
            .send(ProofRequest::public_only("{}".to_string()))
            .expect("queued proof should complete");
        let requests = server.requests();

        assert_paths(
            &requests,
            [
                "/prove",
                "/prove/status?job_id=job-1",
                "/prove/status?job_id=job-1",
            ],
        );
        assert_eq!(proof.a, [0u8; 64]);
        assert_eq!(proof.b, [0u8; 128]);
        assert_eq!(proof.c, [0u8; 64]);
        assert!(proof.commitment.is_none());
    }

    #[test]
    fn prover_client_authenticates_prove_requests() {
        let server = MockServer::respond_with(vec![MockResponse::json(200, gnark_proof())]);
        ProverClient::new(server.url().to_string())
            .with_api_key("test-api-key")
            .expect("a non-empty api key is accepted")
            .send(ProofRequest::public_only("{}".to_string()))
            .expect("authenticated proof request should complete");

        let requests = server.requests();
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some("Bearer test-api-key")
        );
    }

    #[test]
    fn prover_client_authenticates_status_requests() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "job_id": "authenticated-job" })),
            MockResponse::json(
                200,
                json!({
                    "status": "completed",
                    "result": { "proof": gnark_proof() },
                }),
            ),
        ]);
        ProverClient::new(server.url().to_string())
            .with_api_key("test-api-key")
            .expect("a non-empty api key is accepted")
            .send(ProofRequest::public_only("{}".to_string()))
            .expect("authenticated queued proof should complete");

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests
            .iter()
            .all(|request| { request.authorization.as_deref() == Some("Bearer test-api-key") }));
    }

    #[tokio::test]
    async fn async_prover_client_authenticates_prove_requests() {
        let server = MockServer::respond_with(vec![MockResponse::json(200, gnark_proof())]);
        AsyncProverClient::new(server.url().to_string())
            .with_api_key("test-api-key")
            .expect("a non-empty api key is accepted")
            .send(ProofRequest::public_only("{}".to_string()))
            .await
            .expect("authenticated proof request should complete");

        let requests = server.requests();
        assert_eq!(
            requests[0].authorization.as_deref(),
            Some("Bearer test-api-key")
        );
    }

    #[test]
    fn poll_async_failed_status_errors() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "job_id": "job-failed" })),
            MockResponse::json(
                200,
                json!({
                    "status": "failed",
                    "message": "prover rejected witness",
                }),
            ),
        ]);
        let err = queued_prover_client(server.url())
            .send(ProofRequest::public_only("{}".to_string()))
            .expect_err("failed async status should surface");
        let requests = server.requests();

        assert_paths(&requests, ["/prove", "/prove/status?job_id=job-failed"]);
        let message = err.to_string();
        assert!(message.contains("async proof failed"));
        assert!(message.contains("prover rejected witness"));
    }

    #[test]
    fn poll_async_times_out_after_max_wait() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "job_id": "job-slow" })),
            MockResponse::json(200, json!({ "status": "queued" })),
            MockResponse::json(200, json!({ "status": "processing" })),
        ]);
        let err = queued_prover_client(server.url())
            .send(ProofRequest::public_only("{}".to_string()))
            .expect_err("slow async proof should time out");
        let requests = server.requests();

        assert_paths(
            &requests,
            [
                "/prove",
                "/prove/status?job_id=job-slow",
                "/prove/status?job_id=job-slow",
            ],
        );
        assert!(err.to_string().contains("async proof timed out after 1s"));
    }

    #[test]
    fn poll_async_rejects_malformed_status_body() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "job_id": "job-bad-json" })),
            MockResponse::text(200, "not json"),
        ]);
        let err = queued_prover_client(server.url())
            .send(ProofRequest::public_only("{}".to_string()))
            .expect_err("malformed status body should fail");
        let requests = server.requests();

        assert_paths(&requests, ["/prove", "/prove/status?job_id=job-bad-json"]);
        assert!(err.to_string().contains("invalid status JSON"));
    }

    #[test]
    fn poll_async_client_error_status_fails_fast() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "job_id": "missing-job" })),
            MockResponse::json(
                404,
                json!({
                    "code": "job_not_found",
                    "message": "unknown job",
                }),
            ),
        ]);
        let err = queued_prover_client(server.url())
            .send(ProofRequest::public_only("{}".to_string()))
            .expect_err("404 status should fail immediately");
        let requests = server.requests();

        assert_paths(&requests, ["/prove", "/prove/status?job_id=missing-job"]);
        let message = err.to_string();
        assert!(message.contains("status 404 Not Found"));
        assert!(message.contains("job_not_found"));
    }

    #[test]
    fn poll_async_retries_transient_status_poll_errors() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "job_id": "job-transient" })),
            MockResponse::disconnect(),
            MockResponse::json(
                200,
                json!({
                    "status": "completed",
                    "result": {
                        "proof": gnark_proof(),
                        "proof_duration_ms": 3,
                    },
                }),
            ),
        ]);
        let proof = queued_prover_client(server.url())
            .send(ProofRequest::public_only("{}".to_string()))
            .expect("transient poll error should be retried");
        let requests = server.requests();

        assert_paths(
            &requests,
            [
                "/prove",
                "/prove/status?job_id=job-transient",
                "/prove/status?job_id=job-transient",
            ],
        );
        assert_eq!(proof.a, [0u8; 64]);
    }

    #[tokio::test]
    async fn async_prover_poll_returns_completed_nested_proof() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "job_id": "async-job" })),
            MockResponse::json(200, json!({ "status": "processing" })),
            MockResponse::json(
                200,
                json!({
                    "status": "completed",
                    "result": {
                        "proof": gnark_proof(),
                        "proof_duration_ms": 4,
                    },
                }),
            ),
        ]);
        let proof = async_prover_client(server.url())
            .send(ProofRequest::public_only("{}".to_string()))
            .await
            .expect("queued async proof should complete");
        let requests = server.requests();

        assert_paths(
            &requests,
            [
                "/prove",
                "/prove/status?job_id=async-job",
                "/prove/status?job_id=async-job",
            ],
        );
        assert_eq!(proof.a, [0u8; 64]);
        assert_eq!(proof.b, [0u8; 128]);
        assert_eq!(proof.c, [0u8; 64]);
    }

    #[tokio::test]
    async fn async_prover_poll_retries_transient_error() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "job_id": "async-transient" })),
            MockResponse::disconnect(),
            MockResponse::json(
                200,
                json!({
                    "status": "completed",
                    "result": { "proof": gnark_proof() },
                }),
            ),
        ]);
        async_prover_client(server.url())
            .send(ProofRequest::public_only("{}".to_string()))
            .await
            .expect("transient async poll error should be retried");
        let requests = server.requests();

        assert_paths(
            &requests,
            [
                "/prove",
                "/prove/status?job_id=async-transient",
                "/prove/status?job_id=async-transient",
            ],
        );
    }

    #[test]
    fn prover_port_parses_url() {
        assert_eq!(prover_port("http://127.0.0.1:3001"), 3001);
        assert_eq!(prover_port("http://127.0.0.1:3101"), 3101);
        // Trailing slash is tolerated.
        assert_eq!(prover_port("http://127.0.0.1:8080/"), 8080);
        // No port -> default, so a malformed override never starts the server
        // on a port the client cannot derive.
        assert_eq!(prover_port("http://localhost"), DEFAULT_PROVER_PORT);
        assert_eq!(prover_port("garbage"), DEFAULT_PROVER_PORT);
        // The default const and SERVER_ADDRESS stay in agreement.
        assert_eq!(prover_port(SERVER_ADDRESS), DEFAULT_PROVER_PORT);
    }

    #[test]
    fn remote_prover_requires_https() {
        use InputSensitivity::{PublicOnly, WalletSecrets};

        assert!(validate_prover_transport("https://prover.example", PublicOnly).is_ok());
        assert!(validate_prover_transport("http://127.0.0.1:3001", WalletSecrets).is_ok());
        assert!(validate_prover_transport("http://localhost:3001", WalletSecrets).is_ok());
        assert!(validate_prover_transport("http://[::1]:3001", WalletSecrets).is_ok());

        let error = validate_prover_transport("http://prover.example", PublicOnly)
            .expect_err("remote plaintext prover must be rejected");
        assert!(matches!(error, ClientError::ProverTransportNotHttps { .. }));
    }

    #[test]
    fn wallet_secret_proofs_require_a_local_prover() {
        let error =
            validate_prover_transport("https://prover.example", InputSensitivity::WalletSecrets)
                .expect_err("wallet secrets must not leave the device");
        assert!(matches!(
            error,
            ClientError::ProverRequiresLocalTransport { .. }
        ));
    }

    /// Each merge chain leg names its input UTXO hashes, its nullifiers and its
    /// signer, so the linkage the protocol hides must not reach a third-party
    /// prover.
    #[test]
    fn merge_chain_inputs_are_classified_as_wallet_secrets() {
        let error = ProverClient::new("https://prover.example".to_string())
            .prove_merge_chain(&MergeChainInputs {
                levels: vec![1],
                legs: Vec::new(),
            })
            .expect_err("merge chain legs must not leave the device");
        assert!(matches!(
            error,
            ClientError::ProverRequiresLocalTransport { .. }
        ));
    }

    #[test]
    fn empty_api_key_is_rejected() {
        let result = ProverClient::local().with_api_key("   ");
        assert!(matches!(result.err(), Some(ClientError::EmptyProverApiKey)));
    }

    #[test]
    fn malformed_prover_url_is_named() {
        let error = validate_prover_transport("not a url", InputSensitivity::PublicOnly)
            .expect_err("a malformed URL must be rejected");
        assert!(matches!(error, ClientError::ProverUrlMalformed { .. }));
    }

    fn queued_prover_client(url: &str) -> ProverClient {
        ProverClient::new(url.to_string()).with_async_poll_config(AsyncPollConfig {
            poll_interval_secs: 1,
            max_wait_secs: 1,
        })
    }

    fn async_prover_client(url: &str) -> AsyncProverClient {
        AsyncProverClient::new(url.to_string()).with_async_poll_config(AsyncPollConfig {
            poll_interval_secs: 1,
            max_wait_secs: 1,
        })
    }

    fn gnark_proof() -> Value {
        json!({
            "ar": [zero_hex(), zero_hex()],
            "bs": [
                [zero_hex(), zero_hex()],
                [zero_hex(), zero_hex()],
            ],
            "krs": [zero_hex(), zero_hex()],
        })
    }

    fn zero_hex() -> &'static str {
        "0x0"
    }

    fn assert_paths<const N: usize>(requests: &[RecordedRequest], expected: [&str; N]) {
        assert_eq!(requests.len(), expected.len());
        for (request, expected_path) in requests.iter().zip(expected.iter()) {
            assert_eq!(request.path, *expected_path);
        }
    }

    struct RecordedRequest {
        path: String,
        authorization: Option<String>,
    }

    enum MockResponse {
        Http { status: u16, body: String },
        Disconnect,
    }

    impl MockResponse {
        fn json(status: u16, body: Value) -> Self {
            Self::Http {
                status,
                body: body.to_string(),
            }
        }

        fn text(status: u16, body: &str) -> Self {
            Self::Http {
                status,
                body: body.to_string(),
            }
        }

        fn disconnect() -> Self {
            Self::Disconnect
        }
    }

    struct MockServer {
        url: String,
        request_rx: mpsc::Receiver<RecordedRequest>,
        handle: thread::JoinHandle<()>,
    }

    impl MockServer {
        fn respond_with(responses: Vec<MockResponse>) -> Self {
            let listener =
                TcpListener::bind("127.0.0.1:0").expect("mock server should bind to a local port");
            let url = format!(
                "http://{}",
                listener
                    .local_addr()
                    .expect("mock server should expose its local address")
            );
            let (request_tx, request_rx) = mpsc::channel();
            let handle = thread::spawn(move || {
                for response in responses {
                    let (mut stream, _) = listener
                        .accept()
                        .expect("mock server should accept a request");
                    let request = read_http_request(&mut stream);
                    request_tx
                        .send(request)
                        .expect("mock request receiver should stay open");
                    if let MockResponse::Http { status, body } = response {
                        write_http_response(&mut stream, status, &body);
                    }
                }
            });
            Self {
                url,
                request_rx,
                handle,
            }
        }

        fn url(&self) -> &str {
            &self.url
        }

        fn requests(self) -> Vec<RecordedRequest> {
            self.handle
                .join()
                .expect("mock server thread should finish");
            self.request_rx.try_iter().collect()
        }
    }

    fn read_http_request(stream: &mut TcpStream) -> RecordedRequest {
        let mut data = Vec::new();
        let mut buf = [0_u8; 1024];
        let mut body_start = None;
        let mut content_len = None;
        loop {
            let read = stream
                .read(&mut buf)
                .expect("mock server should read request bytes");
            assert!(read != 0, "HTTP client closed before sending a request");
            data.extend_from_slice(
                buf.get(..read)
                    .expect("read length should stay within the buffer"),
            );
            if body_start.is_none() {
                if let Some(header_end) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                    body_start = Some(header_end + 4);
                    let header = String::from_utf8_lossy(
                        data.get(..header_end)
                            .expect("header end should be within request data"),
                    );
                    content_len = Some(parse_content_length(&header).unwrap_or(0));
                }
            }
            if let (Some(start), Some(len)) = (body_start, content_len) {
                if data.len() >= start.saturating_add(len) {
                    break;
                }
            }
        }

        let header_end = body_start.unwrap_or(data.len());
        let header = String::from_utf8_lossy(
            data.get(..header_end)
                .expect("header end should be within request data"),
        );
        let path = header
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .expect("request line should include a path")
            .to_string();
        let authorization = header.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then(|| value.trim().to_string())
        });
        RecordedRequest {
            path,
            authorization,
        }
    }

    fn parse_content_length(header: &str) -> Option<usize> {
        header.lines().find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower
                .strip_prefix("content-length:")
                .map(str::trim)
                .and_then(|value| value.parse().ok())
        })
    }

    fn write_http_response(stream: &mut TcpStream, status: u16, body: &str) {
        write!(
            stream,
            "HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            reason_phrase(status),
            body.len(),
            body
        )
        .expect("mock server should write response");
    }

    fn reason_phrase(status: u16) -> &'static str {
        match status {
            200 => "OK",
            202 => "Accepted",
            400 => "Bad Request",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "OK",
        }
    }
}
