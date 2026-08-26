use std::{
    env,
    path::Path,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    thread::sleep,
    time::{Duration, Instant},
};

use reqwest::redirect::Policy;
use reqwest::StatusCode;
use tokio::time::sleep as async_sleep;
use zeroize::Zeroizing;

use crate::{
    error::ClientError,
    prover::{
        inputs::{BatchAddressAppendInputs, MergeInputs, TransferInputs, TransferP256Inputs},
        json::{
            to_json, to_json_batch_address_append, to_json_merge, to_json_merge_ring,
            to_json_p256_ring, to_json_ring, to_json_ring_authority,
        },
        proof::{proof_from_gnark_json, Proof},
    },
};

pub const SERVER_ADDRESS: &str = "http://127.0.0.1:3001";
pub const HEALTH_CHECK: &str = "/health";
pub const PROVE_PATH: &str = "/prove";

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

// A heavy cold proof (the first P256 request loads a 63MB key and runs a
// 205k-constraint Groth16 prove) can drop the HTTP connection under CPU/memory
// contention while the server stays up. Proof generation is idempotent, so the
// request is retried; the key is warm by the next attempt and proves quickly.
/// Whether the prover should answer with the proof or with a job handle.
///
/// A transfer-shaped proof is ~150ms of work, and asking for it in the response
/// costs one round trip. Queueing it costs an enqueue, then a poll schedule that
/// starts at 25ms and doubles -- so the proof is collected somewhere between one
/// and several round trips after it was ready, and the client sleeps through the
/// difference. Batch proofs are the other way round: they run far longer than a
/// connection or a load balancer's idle timeout should be held open.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Ask for the proof in the response, falling back to the queue if the
    /// prover says it is at its concurrency limit.
    InResponse,
    /// Let the prover queue it and poll for the result.
    Queued,
}

/// A `/prove` body from a downstream crate, sent through the client's retry,
/// queue-fallback, and poll handling.
pub trait ProveRequest {
    /// `Zeroizing`, a body may carry key material.
    fn body(&self) -> Result<Zeroizing<String>, ClientError>;

    /// The queue suits anything heavier than a transfer-shaped proof.
    fn delivery(&self) -> Delivery {
        Delivery::Queued
    }
}

const PROVE_MAX_ATTEMPTS: usize = 3;
const PROVE_RETRY_BACKOFF_SECS: u64 = 2;
// Generous bound so a slow cold prove never hangs the client forever; the server
// caps sync work at 120–180s depending on circuit, so a clean timeout returns
// well before this.
const PROVE_REQUEST_TIMEOUT_SECS: u64 = 600;
const PROVE_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Per-request bound on a `/prove/status` poll.
///
/// The status endpoint reads one Redis key and returns; it is not the request
/// that 600s was sized for. Sharing the prove timeout let a single hung poll
/// block a worker for ten minutes, and since the poll loop retries, the delays
/// stacked: a 220-worker run whose proofs had all finished or been reaped sat
/// wedged for over half an hour, every worker parked inside a status GET.
const STATUS_POLL_TIMEOUT_SECS: u64 = 30;
/// Polling cadence and ceiling for async (queued) proofs. Redis-backed provers
/// queue batch, transfer, and merge proofs and return a job handle immediately
/// instead of blocking; the client then polls the status endpoint until the
/// proof completes or `max_wait_secs` elapses. The first batch job loads a
/// multi-GB proving key before proving, so the default ceiling is generous.
///
/// Held on the [`ProverClient`] and overridable via
/// [`ProverClient::with_async_poll_config`], mirroring light-client's
/// `RetryConfig` (a client-held config with a `Default`).
#[derive(Clone, Copy, Debug)]
pub struct AsyncPollConfig {
    /// Seconds between `/prove/status` polls (floored at 1 so it can't spin).
    pub poll_interval_secs: u64,
    /// Wall-clock seconds to wait for a queued proof before returning a timeout
    /// error.
    ///
    /// Wall clock, measured from the first poll. It used to be a running total
    /// of time *slept*, which bounds nothing: the time inside each request did
    /// not count, so with a 600s request timeout this "1200s" ceiling permitted
    /// well over a day of waiting.
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
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(PROVE_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(PROVE_REQUEST_TIMEOUT_SECS))
        .build()
        .expect("failed to build HTTP client")
}

fn build_async_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(PROVE_CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(PROVE_REQUEST_TIMEOUT_SECS))
        .build()
        .expect("failed to build HTTP client")
}

/// Blocking client for the transfer proving endpoints of the prover server.
pub struct ProverClient {
    server_address: String,
    http: reqwest::blocking::Client,
    async_poll: AsyncPollConfig,
    /// Rail for transfer-shaped proofs. Batch proofs are always queued.
    delivery: Delivery,
}

/// Async client for the transfer proving endpoints of the prover server.
pub struct AsyncProverClient {
    server_address: String,
    http: reqwest::Client,
    async_poll: AsyncPollConfig,
    /// Rail for transfer-shaped proofs. Batch proofs are always queued.
    delivery: Delivery,
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
            delivery: Delivery::InResponse,
        }
    }

    /// Override the async-proof polling config (see [`AsyncPollConfig`]).
    pub fn with_async_poll_config(mut self, config: AsyncPollConfig) -> Self {
        self.async_poll = config;
        self
    }

    /// Queue transfer-shaped proofs instead of asking for them in the response.
    ///
    /// The response is the faster rail and the default. Queueing is still the
    /// right choice for a caller sharing a prover with heavier work, and it is
    /// the rail the queue's own tests have to exercise.
    pub fn with_queued_proofs(mut self) -> Self {
        self.delivery = Delivery::Queued;
        self
    }

    /// Prove a Solana-only (eddsa) transfer, returning the uncompressed negated proof.
    /// Call [`Proof::compress`] for the wire format.
    pub fn prove_transfer(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.send(to_json(inputs), self.delivery)
    }

    /// Prove an 8-in/1-out merge, returning the uncompressed negated proof.
    /// Call [`Proof::compress`] for the wire format.
    pub fn prove_merge(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.send(to_json_merge(inputs), self.delivery)
    }

    /// Prove a ring-authority transfer (anonymous, no signature), returning the
    /// uncompressed negated proof. Reuses the Solana-only [`TransferInputs`] witness;
    /// call [`Proof::compress`] for the wire format.
    pub fn prove_ring_authority(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.send(to_json_ring_authority(inputs), self.delivery)
    }

    /// Prove a policy-ring merge (`merge-ring`), returning the uncompressed negated
    /// proof. Reuses the [`MergeInputs`] witness; call [`Proof::compress`] for the
    /// wire format.
    pub fn prove_merge_ring(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.send(to_json_merge_ring(inputs), self.delivery)
    }

    /// Prove an eddsa confidential policy-ring transfer (`transfer-ring`).
    pub fn prove_transfer_ring(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.send(to_json_ring(inputs), self.delivery)
    }

    /// Prove a custom-ring P256 transfer.
    pub fn prove_transfer_p256_ring(
        &self,
        inputs: &TransferP256Inputs,
    ) -> Result<Proof, ClientError> {
        self.send(to_json_p256_ring(inputs), self.delivery)
    }

    pub fn prove(&self, request: &impl ProveRequest) -> Result<Proof, ClientError> {
        self.send(request.body()?, request.delivery())
    }

    /// Prove a nullifier-tree batch address-append update, returning the
    /// uncompressed negated proof. Call [`ProofCompressed::try_from`] for the
    /// SPP instruction wire format.
    pub fn prove_batch_address_append(
        &self,
        inputs: &BatchAddressAppendInputs,
    ) -> Result<Proof, ClientError> {
        self.send(to_json_batch_address_append(inputs), Delivery::Queued)
    }

    /// One POST to `/prove`, retried only for transport failures. Returns the
    /// status alongside the body so the caller can act on a shed request.
    fn post(
        &self,
        url: &str,
        body: &str,
        delivery: Delivery,
    ) -> Result<(StatusCode, String), ClientError> {
        let mut attempt = 0;
        let response = loop {
            attempt += 1;
            let mut request = self
                .http
                .post(url)
                .header("Content-Type", "application/json");
            if delivery == Delivery::InResponse {
                request = request.header("X-Sync", "true");
            }
            match request.body(body.to_string()).send() {
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
        Ok((status, text))
    }

    fn send(&self, body: impl AsRef<str>, delivery: Delivery) -> Result<Proof, ClientError> {
        let url = format!("{}{}", self.server_address, PROVE_PATH);
        crate::timing::note(0, "prover_request_bytes", body.as_ref().len());
        // Dropped to `Queued` if the prover sheds the synchronous request, so a
        // busy prover degrades to waiting in line rather than to an error.
        let mut delivery = delivery;
        let (status, text) = loop {
            let (status, text) = self.post(&url, body.as_ref(), delivery)?;
            if status == StatusCode::TOO_MANY_REQUESTS && delivery == Delivery::InResponse {
                // Retrying synchronously would compete for the same permit that
                // was just refused; queueing waits for it once instead.
                delivery = Delivery::Queued;
                continue;
            }
            break (status, text);
        };
        if !status.is_success() {
            return Err(ClientError::ProverServer(format!(
                "status {status}: {text}"
            )));
        }

        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| ClientError::ProofParse(format!("invalid response JSON: {e}")))?;

        // A Redis-backed prover queues supported proofs and returns a job
        // handle (`{ jobId, status, statusUrl }`) instead of a proof; poll the
        // status endpoint until it completes. A synchronous prover returns the
        // proof directly (plain gnark JSON or a `{ proof, .. }` envelope).
        if value.get("proof").is_none() {
            if let Some(job_id) = value.get("jobId").and_then(|v| v.as_str()) {
                return self.poll_async(job_id);
            }
        }
        Self::proof_from_value(&value, &text)
    }

    /// Poll the async job status endpoint until the queued proof completes.
    fn poll_async(&self, job_id: &str) -> Result<Proof, ClientError> {
        let url = format!("{}/prove/status?jobId={}", self.server_address, job_id);
        // The configured interval caps the backoff rather than setting it. This
        // used to be `.max(1)` and `sleep_secs`, which put a hard 1s floor on
        // every proof: a 270ms proof measured 3.3s end to end, essentially all
        // of it spent asleep between polls.
        // The backoff ceiling is deliberately left to `poll_interval_secs` rather than
        // clamped to something tighter.
        //
        // Tightening it to 250ms looks like an obvious win -- a finished proof then
        // waits at most a quarter second to be collected -- and it measurably is not.
        // Two 8-worker load tests, identical apart from this ceiling:
        //
        //     ceiling 1s     prove mean 2025ms   1.14 tps
        //     ceiling 250ms  prove mean 3632ms   0.92 tps
        //
        // sync, send, and confirm were unchanged across the pair, so the regression is
        // isolated to proving. Polling four times as hard contends with the prover's
        // own queue rather than shortening the wait. Poll often enough to avoid the
        // whole-second floor, then get out of the way.
        let poll_cap_ms = self
            .async_poll
            .poll_interval_secs
            .saturating_mul(1_000)
            .max(INITIAL_POLL_MS);
        let max_wait = Duration::from_secs(self.async_poll.max_wait_secs);
        let started = Instant::now();
        let mut interval_ms = INITIAL_POLL_MS;
        loop {
            let response = match self
                .http
                .get(&url)
                .timeout(Duration::from_secs(STATUS_POLL_TIMEOUT_SECS))
                .send()
            {
                Ok(response) => response,
                Err(_) => {
                    wait_or_timeout(job_id, started, max_wait, interval_ms)?;
                    interval_ms = next_poll_interval_ms(interval_ms, poll_cap_ms);
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
                wait_or_timeout(job_id, started, max_wait, interval_ms)?;
                interval_ms = next_poll_interval_ms(interval_ms, poll_cap_ms);
                continue;
            }

            let text = match response.text() {
                Ok(text) => text,
                Err(_) => {
                    wait_or_timeout(job_id, started, max_wait, interval_ms)?;
                    interval_ms = next_poll_interval_ms(interval_ms, poll_cap_ms);
                    continue;
                }
            };
            let value: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| ClientError::ProofParse(format!("invalid status JSON: {e}")))?;

            match value.get("status").and_then(|v| v.as_str()) {
                // The completed result is a `{ proof, proofDurationMs }` envelope
                // nested under `result`.
                Some("completed") => {
                    let result = value.get("result").map_or(&value, |result| result);
                    return Self::proof_from_value(result, &text);
                }
                Some("failed") => {
                    return Err(ClientError::ProverServer(format!(
                        "async proof failed (job {job_id}): {text}"
                    )));
                }
                // queued / processing / unknown: keep polling until the bound.
                _ => {
                    wait_or_timeout(job_id, started, max_wait, interval_ms)?;
                    interval_ms = next_poll_interval_ms(interval_ms, poll_cap_ms);
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

/// First gap between status polls. A transfer proof completes in well under a
/// second, so the first poll should land almost immediately; the cost of being
/// early is one cheap GET.
const INITIAL_POLL_MS: u64 = 25;

/// Next gap in the backoff, doubling up to `cap_ms`.
///
/// The configured poll interval is the CEILING, not a fixed period: a proof that
/// finishes in 270ms should not wait a full second to be collected, but a proof
/// that takes a minute should not be polled 2400 times either.
fn next_poll_interval_ms(current_ms: u64, cap_ms: u64) -> u64 {
    current_ms
        .saturating_mul(2)
        .min(cap_ms.max(INITIAL_POLL_MS))
}

/// How long is left before the deadline, or `Err` if it has passed.
///
/// Shared by the blocking and async poll loops so one definition of "expired"
/// covers both. `started`/`max_wait` are wall clock: the previous version added
/// up only the sleeps, which meant time spent inside a request was free and the
/// ceiling bounded nothing.
fn remaining_before_deadline(
    job_id: &str,
    started: Instant,
    max_wait: Duration,
    poll_interval_ms: u64,
) -> Result<Duration, ClientError> {
    let elapsed = started.elapsed();
    let Some(remaining) = max_wait.checked_sub(elapsed) else {
        return Err(ClientError::ProverServer(format!(
            "async proof timed out after {}s (job {job_id})",
            elapsed.as_secs()
        )));
    };
    Ok(Duration::from_millis(poll_interval_ms).min(remaining))
}

fn wait_or_timeout(
    job_id: &str,
    started: Instant,
    max_wait: Duration,
    poll_interval_ms: u64,
) -> Result<(), ClientError> {
    sleep(remaining_before_deadline(
        job_id,
        started,
        max_wait,
        poll_interval_ms,
    )?);
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
            delivery: Delivery::InResponse,
        }
    }

    /// Override the queued-proof polling config (see [`AsyncPollConfig`]).
    pub fn with_async_poll_config(mut self, config: AsyncPollConfig) -> Self {
        self.async_poll = config;
        self
    }

    /// Queue transfer-shaped proofs instead of asking for them in the response.
    ///
    /// The response is the faster rail and the default. Queueing is still the
    /// right choice for a caller sharing a prover with heavier work, and it is
    /// the rail the queue's own tests have to exercise.
    pub fn with_queued_proofs(mut self) -> Self {
        self.delivery = Delivery::Queued;
        self
    }

    /// Prove a Solana-only (eddsa) transfer, returning the uncompressed negated proof.
    /// Call [`Proof::compress`] for the wire format.
    pub async fn prove_transfer(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.send(to_json(inputs), self.delivery).await
    }

    pub async fn prove_merge(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.send(to_json_merge(inputs), self.delivery).await
    }

    pub async fn prove_ring_authority(
        &self,
        inputs: &TransferInputs,
    ) -> Result<Proof, ClientError> {
        self.send(to_json_ring_authority(inputs), self.delivery)
            .await
    }

    pub async fn prove_merge_ring(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.send(to_json_merge_ring(inputs), self.delivery).await
    }

    pub async fn prove_transfer_ring(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.send(to_json_ring(inputs), self.delivery).await
    }

    pub async fn prove_transfer_p256_ring(
        &self,
        inputs: &TransferP256Inputs,
    ) -> Result<Proof, ClientError> {
        self.send(to_json_p256_ring(inputs), self.delivery).await
    }

    pub async fn prove(&self, request: &impl ProveRequest) -> Result<Proof, ClientError> {
        self.send(request.body()?, request.delivery()).await
    }

    pub async fn prove_batch_address_append(
        &self,
        inputs: &BatchAddressAppendInputs,
    ) -> Result<Proof, ClientError> {
        self.send(to_json_batch_address_append(inputs), Delivery::Queued)
            .await
    }

    async fn send(&self, body: impl AsRef<str>, delivery: Delivery) -> Result<Proof, ClientError> {
        let url = format!("{}{}", self.server_address, PROVE_PATH);
        let mut delivery = delivery;
        let (status, text) = loop {
            let (status, text) = self.post(&url, body.as_ref(), delivery).await?;
            if status == StatusCode::TOO_MANY_REQUESTS && delivery == Delivery::InResponse {
                delivery = Delivery::Queued;
                continue;
            }
            break (status, text);
        };
        if !status.is_success() {
            return Err(ClientError::ProverServer(format!(
                "status {status}: {text}"
            )));
        }

        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| ClientError::ProofParse(format!("invalid response JSON: {e}")))?;
        if value.get("proof").is_none() {
            if let Some(job_id) = value.get("jobId").and_then(|v| v.as_str()) {
                return self.poll_async(job_id).await;
            }
        }
        ProverClient::proof_from_value(&value, &text)
    }

    async fn post(
        &self,
        url: &str,
        body: &str,
        delivery: Delivery,
    ) -> Result<(StatusCode, String), ClientError> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut request = self
                .http
                .post(url)
                .header("Content-Type", "application/json");
            if delivery == Delivery::InResponse {
                request = request.header("X-Sync", "true");
            }
            match request.body(body.to_string()).send().await {
                Ok(response) => {
                    let status = response.status();
                    let text = response.text().await.map_err(|e| {
                        ClientError::ProverServer(format!("failed to read response body: {e}"))
                    })?;
                    return Ok((status, text));
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
        let url = format!("{}/prove/status?jobId={}", self.server_address, job_id);
        let poll_cap_ms = self
            .async_poll
            .poll_interval_secs
            .saturating_mul(1_000)
            .max(INITIAL_POLL_MS);
        let max_wait = Duration::from_secs(self.async_poll.max_wait_secs);
        let started = Instant::now();
        let mut interval_ms = INITIAL_POLL_MS;
        loop {
            let response = match self
                .http
                .get(&url)
                .timeout(Duration::from_secs(STATUS_POLL_TIMEOUT_SECS))
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => {
                    async_wait_or_timeout(job_id, started, max_wait, interval_ms).await?;
                    interval_ms = next_poll_interval_ms(interval_ms, poll_cap_ms);
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
                async_wait_or_timeout(job_id, started, max_wait, interval_ms).await?;
                interval_ms = next_poll_interval_ms(interval_ms, poll_cap_ms);
                continue;
            }

            let text = match response.text().await {
                Ok(text) => text,
                Err(_) => {
                    async_wait_or_timeout(job_id, started, max_wait, interval_ms).await?;
                    interval_ms = next_poll_interval_ms(interval_ms, poll_cap_ms);
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
                    async_wait_or_timeout(job_id, started, max_wait, interval_ms).await?;
                    interval_ms = next_poll_interval_ms(interval_ms, poll_cap_ms);
                }
            }
        }
    }
}

async fn async_wait_or_timeout(
    job_id: &str,
    started: Instant,
    max_wait: Duration,
    poll_interval_ms: u64,
) -> Result<(), ClientError> {
    async_sleep(remaining_before_deadline(
        job_id,
        started,
        max_wait,
        poll_interval_ms,
    )?)
    .await;
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
        sync::{mpsc, Arc},
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

    /// The prover is queue-backed: `/prove` returns a job handle and the proof
    /// is collected by polling. The gap between polls used to be
    /// `Duration::from_secs(poll_interval.max(1))`, so a proof the server
    /// finished in 270ms was not collected for a further second or more --
    /// measured on devnet as 3.3s end to end for 270ms of proving, which made
    /// the prover call the largest phase of a transfer for no real reason.
    ///
    /// Asserts wall-clock rather than the sleep arithmetic, because the bug was
    /// only visible as latency.
    #[test]
    fn a_proof_ready_on_the_first_poll_is_not_held_for_a_whole_second() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "jobId": "job-1", "status": "queued" })),
            MockResponse::json(
                200,
                json!({
                    "status": "completed",
                    "result": { "proof": gnark_proof(), "proofDurationMs": 7 },
                }),
            ),
        ]);
        let started = std::time::Instant::now();
        queued_prover_client(server.url())
            .send("{}", Delivery::Queued)
            .expect("queued proof should complete");
        let elapsed = started.elapsed();

        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "collecting a ready proof took {elapsed:?}; the poll interval is a \
             ceiling, not a floor"
        );
    }

    #[test]
    fn a_custom_prove_request_takes_the_queued_rail() {
        struct StaticRequest;

        impl ProveRequest for StaticRequest {
            fn body(&self) -> Result<Zeroizing<String>, ClientError> {
                Ok(Zeroizing::new("{}".to_string()))
            }
        }

        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "jobId": "job-custom", "status": "queued" })),
            MockResponse::json(
                200,
                json!({
                    "status": "completed",
                    "result": { "proof": gnark_proof(), "proofDurationMs": 7 },
                }),
            ),
        ]);
        queued_prover_client(server.url())
            .prove(&StaticRequest)
            .expect("queued proof should complete");

        let requests = server.requests();
        assert_paths(&requests, ["/prove", "/prove/status?jobId=job-custom"]);
        assert!(
            requests.iter().all(|request| !request.sync_requested),
            "a custom request must not ask for a synchronous answer"
        );
    }

    /// The configured interval bounds the backoff instead of fixing it, so a
    /// long proof still settles into infrequent polling.
    #[test]
    fn poll_backoff_doubles_up_to_the_configured_ceiling() {
        let cap = 1_000;
        let mut interval = INITIAL_POLL_MS;
        let mut seen = vec![interval];
        for _ in 0..8 {
            interval = next_poll_interval_ms(interval, cap);
            seen.push(interval);
        }
        assert_eq!(seen[0], 25, "first poll lands almost immediately");
        assert_eq!(&seen[1..4], &[50, 100, 200]);
        assert_eq!(
            *seen.last().expect("non-empty"),
            cap,
            "backoff settles at the configured interval"
        );
        assert!(
            seen.windows(2).all(|w| w[1] >= w[0]),
            "backoff is monotonic"
        );
    }

    #[test]
    fn poll_async_returns_completed_nested_proof() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(
                202,
                json!({
                    "jobId": "job-1",
                    "status": "queued",
                    "statusUrl": "/prove/status?jobId=job-1",
                }),
            ),
            MockResponse::json(200, json!({ "status": "queued" })),
            MockResponse::json(
                200,
                json!({
                    "status": "completed",
                    "result": {
                        "proof": gnark_proof(),
                        "proofDurationMs": 7,
                    },
                }),
            ),
        ]);
        let proof = queued_prover_client(server.url())
            .send("{}", Delivery::Queued)
            .expect("queued proof should complete");
        let requests = server.requests();

        assert_paths(
            &requests,
            [
                "/prove",
                "/prove/status?jobId=job-1",
                "/prove/status?jobId=job-1",
            ],
        );
        assert_eq!(proof.a, [0u8; 64]);
        assert_eq!(proof.b, [0u8; 128]);
        assert_eq!(proof.c, [0u8; 64]);
        assert!(proof.commitment.is_none());
    }

    #[test]
    fn poll_async_failed_status_errors() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "jobId": "job-failed" })),
            MockResponse::json(
                200,
                json!({
                    "status": "failed",
                    "message": "prover rejected witness",
                }),
            ),
        ]);
        let err = queued_prover_client(server.url())
            .send("{}", Delivery::Queued)
            .expect_err("failed async status should surface");
        let requests = server.requests();

        assert_paths(&requests, ["/prove", "/prove/status?jobId=job-failed"]);
        let message = err.to_string();
        assert!(message.contains("async proof failed"));
        assert!(message.contains("prover rejected witness"));
    }

    /// The deadline is wall clock, so a slow-but-alive status endpoint cannot
    /// stretch it.
    ///
    /// This is the case the old accounting missed. It summed only the time
    /// *slept* between polls, so a poll that took 1.5s to answer added nothing
    /// to the total: the client stayed under a 1s "ceiling" indefinitely. In
    /// production, with a 600s request timeout inherited from the prove call,
    /// that turned a 1200s bound into a hang -- 220 workers sat wedged for 35
    /// minutes with the prover queue empty.
    ///
    /// The single poll here answers after 1.5s against a 1s ceiling, so the
    /// client must give up on it alone. Under the old rule that poll counted as
    /// 0ms, leaving the whole budget unspent, and polling continued -- so the
    /// server is held open to record any further polls rather than refusing
    /// them where they would go unseen.
    #[test]
    fn a_slow_status_endpoint_cannot_extend_the_deadline() {
        let server = MockServer::respond_then_hold(vec![
            MockResponse::json(202, json!({ "jobId": "job-slow-status" })),
            MockResponse::slow_json(
                200,
                json!({ "status": "processing" }),
                Duration::from_millis(1_500),
            ),
        ]);

        let started = Instant::now();
        let err = queued_prover_client(server.url())
            .send("{}", Delivery::Queued)
            .expect_err("a deadline measured in wall clock must expire");
        let elapsed = started.elapsed();

        assert!(
            err.to_string().contains("async proof timed out"),
            "expected a timeout, got {err}"
        );
        // The slow poll alone exceeds the ceiling; anything much beyond it means
        // the deadline is still being measured in slept time.
        assert!(
            elapsed < Duration::from_secs(5),
            "gave up only after {elapsed:?}"
        );
        // The slow poll is the last one. A second status request would mean the
        // time it spent waiting had not been charged against the deadline.
        assert_paths(
            &server.requests(),
            ["/prove", "/prove/status?jobId=job-slow-status"],
        );
    }

    #[test]
    fn poll_async_times_out_after_max_wait() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "jobId": "job-slow" })),
            MockResponse::json(200, json!({ "status": "queued" })),
            MockResponse::json(200, json!({ "status": "processing" })),
        ]);
        let err = queued_prover_client(server.url())
            .send("{}", Delivery::Queued)
            .expect_err("slow async proof should time out");
        let requests = server.requests();

        assert_paths(
            &requests,
            [
                "/prove",
                "/prove/status?jobId=job-slow",
                "/prove/status?jobId=job-slow",
            ],
        );
        assert!(err.to_string().contains("async proof timed out after 1s"));
    }

    #[test]
    fn poll_async_rejects_malformed_status_body() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "jobId": "job-bad-json" })),
            MockResponse::text(200, "not json"),
        ]);
        let err = queued_prover_client(server.url())
            .send("{}", Delivery::Queued)
            .expect_err("malformed status body should fail");
        let requests = server.requests();

        assert_paths(&requests, ["/prove", "/prove/status?jobId=job-bad-json"]);
        assert!(err.to_string().contains("invalid status JSON"));
    }

    #[test]
    fn poll_async_client_error_status_fails_fast() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "jobId": "missing-job" })),
            MockResponse::json(
                404,
                json!({
                    "code": "job_not_found",
                    "message": "unknown job",
                }),
            ),
        ]);
        let err = queued_prover_client(server.url())
            .send("{}", Delivery::Queued)
            .expect_err("404 status should fail immediately");
        let requests = server.requests();

        assert_paths(&requests, ["/prove", "/prove/status?jobId=missing-job"]);
        let message = err.to_string();
        assert!(message.contains("status 404 Not Found"));
        assert!(message.contains("job_not_found"));
    }

    #[test]
    fn poll_async_retries_transient_status_poll_errors() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "jobId": "job-transient" })),
            MockResponse::disconnect(),
            MockResponse::json(
                200,
                json!({
                    "status": "completed",
                    "result": {
                        "proof": gnark_proof(),
                        "proofDurationMs": 3,
                    },
                }),
            ),
        ]);
        let proof = queued_prover_client(server.url())
            .send("{}", Delivery::Queued)
            .expect("transient poll error should be retried");
        let requests = server.requests();

        assert_paths(
            &requests,
            [
                "/prove",
                "/prove/status?jobId=job-transient",
                "/prove/status?jobId=job-transient",
            ],
        );
        assert_eq!(proof.a, [0u8; 64]);
    }

    #[tokio::test]
    async fn async_prover_poll_returns_completed_nested_proof() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "jobId": "async-job" })),
            MockResponse::json(200, json!({ "status": "processing" })),
            MockResponse::json(
                200,
                json!({
                    "status": "completed",
                    "result": {
                        "proof": gnark_proof(),
                        "proofDurationMs": 4,
                    },
                }),
            ),
        ]);
        let proof = async_prover_client(server.url())
            .send("{}", Delivery::Queued)
            .await
            .expect("queued async proof should complete");
        let requests = server.requests();

        assert_paths(
            &requests,
            [
                "/prove",
                "/prove/status?jobId=async-job",
                "/prove/status?jobId=async-job",
            ],
        );
        assert_eq!(proof.a, [0u8; 64]);
        assert_eq!(proof.b, [0u8; 128]);
        assert_eq!(proof.c, [0u8; 64]);
    }

    #[tokio::test]
    async fn async_prover_poll_retries_transient_error() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(202, json!({ "jobId": "async-transient" })),
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
            .send("{}", Delivery::Queued)
            .await
            .expect("transient async poll error should be retried");
        let requests = server.requests();

        assert_paths(
            &requests,
            [
                "/prove",
                "/prove/status?jobId=async-transient",
                "/prove/status?jobId=async-transient",
            ],
        );
    }

    /// Transfer-shaped proofs ask for the proof in the response: the queue's
    /// enqueue plus poll schedule costs more round trips than the proof takes.
    #[test]
    fn a_transfer_proof_asks_for_the_proof_in_the_response() {
        let server = MockServer::respond_with(vec![MockResponse::json(
            200,
            json!({ "proof": gnark_proof() }),
        )]);
        queued_prover_client(server.url())
            .send("{}", Delivery::InResponse)
            .expect("a synchronous prover answers with the proof");

        let requests = server.requests();
        assert_paths(&requests, ["/prove"]);
        assert!(
            requests
                .first()
                .expect("one request was recorded")
                .sync_requested,
            "the request must say it wants the proof back"
        );
    }

    /// And a prover at its concurrency limit must not turn into a failed
    /// transfer. Retrying synchronously would compete for the permit that was
    /// just refused, so the client queues instead -- one wait rather than a
    /// storm.
    #[test]
    fn a_shed_sync_proof_falls_back_to_the_queue() {
        let server = MockServer::respond_with(vec![
            MockResponse::json(429, json!({ "code": "prover_busy" })),
            MockResponse::json(202, json!({ "jobId": "queued-after-shed" })),
            MockResponse::json(
                200,
                json!({
                    "status": "completed",
                    "result": { "proof": gnark_proof() },
                }),
            ),
        ]);

        let proof = queued_prover_client(server.url())
            .send("{}", Delivery::InResponse)
            .expect("a shed proof should be queued, not failed");
        assert_eq!(proof.a, [0u8; 64]);

        let requests = server.requests();
        assert_paths(
            &requests,
            ["/prove", "/prove", "/prove/status?jobId=queued-after-shed"],
        );
        assert!(
            requests
                .first()
                .expect("the shed request was recorded")
                .sync_requested,
            "the first attempt asked for the proof in the response"
        );
        assert!(
            !requests
                .get(1)
                .expect("the retry was recorded")
                .sync_requested,
            "the retry must queue rather than ask again for a permit just refused"
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
        /// Whether the request asked for the proof in the response.
        sync_requested: bool,
    }

    enum MockResponse {
        Http {
            status: u16,
            body: String,
        },
        /// Answers, but only after `delay`. Models a status endpoint that is
        /// reachable and slow rather than down -- the case the poll deadline has
        /// to survive, and the one a fast mock cannot exercise.
        SlowHttp {
            status: u16,
            body: String,
            delay: Duration,
        },
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

        fn slow_json(status: u16, body: Value, delay: Duration) -> Self {
            Self::SlowHttp {
                status,
                body: body.to_string(),
                delay,
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
        /// Set only by [`MockServer::respond_then_hold`], whose server would
        /// otherwise never stop accepting.
        stop: Option<Arc<AtomicBool>>,
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
                    match response {
                        MockResponse::Http { status, body } => {
                            write_http_response(&mut stream, status, &body)
                        }
                        MockResponse::SlowHttp {
                            status,
                            body,
                            delay,
                        } => {
                            thread::sleep(delay);
                            write_http_response(&mut stream, status, &body);
                        }
                        MockResponse::Disconnect => {}
                    }
                }
            });
            Self {
                url,
                request_rx,
                handle,
                stop: None,
            }
        }

        /// Like [`respond_with`], but after the scripted responses run out the
        /// last one repeats for as long as the client keeps asking.
        ///
        /// `respond_with` stops answering once its list is exhausted, which
        /// makes "the client polled more times than it should have" invisible:
        /// the extra polls hit a closed port and go unrecorded. Holding the
        /// server open records them, so a test can assert on the exact number
        /// of polls. [`requests`] stops the server.
        fn respond_then_hold(responses: Vec<MockResponse>) -> Self {
            let listener =
                TcpListener::bind("127.0.0.1:0").expect("mock server should bind to a local port");
            let url = format!(
                "http://{}",
                listener
                    .local_addr()
                    .expect("mock server should expose its local address")
            );
            let (request_tx, request_rx) = mpsc::channel();
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let handle = thread::spawn(move || {
                let mut remaining = responses.into_iter().peekable();
                let mut last: Option<(u16, String)> = None;
                while let Ok((mut stream, _)) = listener.accept() {
                    if thread_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let request = read_http_request(&mut stream);
                    if request_tx.send(request).is_err() {
                        break;
                    }
                    match remaining.next() {
                        Some(MockResponse::Http { status, body }) => {
                            write_http_response(&mut stream, status, &body);
                            last = Some((status, body));
                        }
                        Some(MockResponse::SlowHttp {
                            status,
                            body,
                            delay,
                        }) => {
                            thread::sleep(delay);
                            write_http_response(&mut stream, status, &body);
                            last = Some((status, body));
                        }
                        Some(MockResponse::Disconnect) => {}
                        None => {
                            if let Some((status, body)) = last.as_ref() {
                                write_http_response(&mut stream, *status, body);
                            }
                        }
                    }
                }
            });
            Self {
                url,
                request_rx,
                handle,
                stop: Some(stop),
            }
        }

        fn url(&self) -> &str {
            &self.url
        }

        fn requests(self) -> Vec<RecordedRequest> {
            if let Some(stop) = self.stop.as_ref() {
                stop.store(true, Ordering::SeqCst);
                // The server is parked in accept(); one throwaway connection
                // wakes it so it can observe the flag and exit.
                let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
            }
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
        RecordedRequest {
            path,
            sync_requested: header.lines().any(|line| {
                let lower = line.to_ascii_lowercase();
                lower.strip_prefix("x-sync:").map(str::trim) == Some("true")
            }),
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
