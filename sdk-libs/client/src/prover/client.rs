use std::{
    env,
    path::Path,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    thread::sleep,
    time::Duration,
};

use crate::{
    error::ClientError,
    prover::{
        inputs::{BatchAddressAppendInputs, MergeInputs, TransferInputs, TransferP256Inputs},
        json::{
            to_json, to_json_batch_address_append, to_json_merge, to_json_merge_zone, to_json_p256,
            to_json_p256_zone, to_json_zone, to_json_zone_authority,
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
const PROVE_MAX_ATTEMPTS: usize = 3;
const PROVE_RETRY_BACKOFF_SECS: u64 = 2;
// Generous bound so a slow cold prove never hangs the client forever; the server
// caps sync work at 120–180s depending on circuit, so a clean timeout returns
// well before this.
const PROVE_REQUEST_TIMEOUT_SECS: u64 = 600;
const PROVE_CONNECT_TIMEOUT_SECS: u64 = 10;
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
        .expect("failed to build HTTP client")
}

/// Blocking client for the transfer proving endpoints of the prover server.
pub struct ProverClient {
    server_address: String,
    http: reqwest::blocking::Client,
    async_poll: AsyncPollConfig,
}

impl Default for ProverClient {
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
        }
    }

    /// Override the async-proof polling config (see [`AsyncPollConfig`]).
    pub fn with_async_poll_config(mut self, config: AsyncPollConfig) -> Self {
        self.async_poll = config;
        self
    }

    /// Prove a P256-rail transfer, returning the uncompressed negated proof. Use
    /// `ProofCompressed::try_from` for the wire format.
    pub fn prove_transfer_p256(&self, inputs: &TransferP256Inputs) -> Result<Proof, ClientError> {
        self.send(to_json_p256(inputs))
    }

    /// Prove a Solana-only (eddsa) transfer, returning the uncompressed negated proof.
    /// Call [`Proof::compress`] for the wire format.
    pub fn prove_transfer(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.send(to_json(inputs))
    }

    /// Prove an 8-in/1-out merge, returning the uncompressed negated proof.
    /// Call [`Proof::compress`] for the wire format.
    pub fn prove_merge(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.send(to_json_merge(inputs))
    }

    /// Prove a zone-authority transfer (anonymous, no signature), returning the
    /// uncompressed negated proof. Reuses the Solana-only [`TransferInputs`] witness;
    /// call [`Proof::compress`] for the wire format.
    pub fn prove_zone_authority(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.send(to_json_zone_authority(inputs))
    }

    /// Prove a policy-zone merge (`merge-zone`), returning the uncompressed negated
    /// proof. Reuses the [`MergeInputs`] witness; call [`Proof::compress`] for the
    /// wire format.
    pub fn prove_merge_zone(&self, inputs: &MergeInputs) -> Result<Proof, ClientError> {
        self.send(to_json_merge_zone(inputs))
    }

    /// Prove an eddsa anonymous policy-zone transfer (`transfer-zone`).
    pub fn prove_transfer_zone(&self, inputs: &TransferInputs) -> Result<Proof, ClientError> {
        self.send(to_json_zone(inputs))
    }

    /// Prove a P256 anonymous policy-zone transfer (`transfer-p256-zone`).
    pub fn prove_transfer_p256_zone(
        &self,
        inputs: &TransferP256Inputs,
    ) -> Result<Proof, ClientError> {
        self.send(to_json_p256_zone(inputs))
    }

    /// Prove a nullifier-tree batch address-append update, returning the
    /// uncompressed negated proof. Call [`ProofCompressed::try_from`] for the
    /// SPP instruction wire format.
    pub fn prove_batch_address_append(
        &self,
        inputs: &BatchAddressAppendInputs,
    ) -> Result<Proof, ClientError> {
        self.send(to_json_batch_address_append(inputs))
    }

    fn send(&self, body: String) -> Result<Proof, ClientError> {
        let url = format!("{}{}", self.server_address, PROVE_PATH);
        let mut attempt = 0;
        let response = loop {
            attempt += 1;
            let outcome = self
                .http
                .post(&url)
                .header("Content-Type", "application/json")
                .body(body.clone())
                .send();
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
        Self::proof_from_value(&value, &text)
    }

    /// Poll the async job status endpoint until the queued proof completes.
    fn poll_async(&self, job_id: &str) -> Result<Proof, ClientError> {
        let url = format!("{}/prove/status?job_id={}", self.server_address, job_id);
        let poll_interval = self.async_poll.poll_interval_secs.max(1);
        let max_wait = self.async_poll.max_wait_secs;
        let mut waited = 0u64;
        loop {
            let response = match self.http.get(&url).send() {
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

/// Block until a prover server is reachable, starting one via the `zolana` CLI if
/// none is already running. Intended for tests.
pub fn spawn_prover() -> Result<(), ClientError> {
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

    let cli = get_cli_command().ok_or_else(|| {
        ClientError::Prover(
            "could not locate the `zolana` CLI; set ZOLANA_CLI_BIN or build target/debug/zolana"
                .to_string(),
        )
    })?;

    let port = prover_port(&server_address());
    let redis_url = env::var("ZOLANA_PROVER_REDIS_URL").ok();
    let spawn_result = Command::new("sh")
        .arg("-c")
        .arg(prover_start_command(&cli, port, redis_url.as_deref()))
        .spawn();

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
        let proof = async_client(server.url())
            .send("{}".to_string())
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
        let err = async_client(server.url())
            .send("{}".to_string())
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
        let err = async_client(server.url())
            .send("{}".to_string())
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
        let err = async_client(server.url())
            .send("{}".to_string())
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
        let err = async_client(server.url())
            .send("{}".to_string())
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
        let proof = async_client(server.url())
            .send("{}".to_string())
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

    fn async_client(url: &str) -> ProverClient {
        ProverClient::new(url.to_string()).with_async_poll_config(AsyncPollConfig {
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
        RecordedRequest { path }
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
