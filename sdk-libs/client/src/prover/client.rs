use std::{
    env,
    path::Path,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    thread::sleep,
    time::Duration,
};

use crate::error::ClientError;
use crate::prover::inputs::{TransferInputs, TransferP256Inputs};
use crate::prover::json::{to_json, to_json_p256};
use crate::prover::proof::{proof_from_gnark_json, Proof};

pub const SERVER_ADDRESS: &str = "http://127.0.0.1:3001";
pub const HEALTH_CHECK: &str = "/health";
pub const PROVE_PATH: &str = "/prove";

const STARTUP_HEALTH_CHECK_RETRIES: usize = 300;
static IS_LOADING: AtomicBool = AtomicBool::new(false);

fn build_http_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .expect("failed to build HTTP client")
}

/// Blocking client for the transfer proving endpoints of the prover server.
pub struct ProverClient {
    server_address: String,
    http: reqwest::blocking::Client,
}

impl Default for ProverClient {
    fn default() -> Self {
        Self::local()
    }
}

impl ProverClient {
    pub fn local() -> Self {
        Self::new(SERVER_ADDRESS.to_string())
    }

    pub fn new(server_address: String) -> Self {
        Self {
            server_address,
            http: build_http_client(),
        }
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

    fn send(&self, body: String) -> Result<Proof, ClientError> {
        let url = format!("{}{}", self.server_address, PROVE_PATH);
        let response = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .map_err(|e| ClientError::ProverServer(format!("request failed: {e}")))?;

        let status = response.status();
        let text = response
            .text()
            .map_err(|e| ClientError::ProverServer(format!("failed to read response body: {e}")))?;

        if !status.is_success() {
            return Err(ClientError::ProverServer(format!(
                "status {status}: {text}"
            )));
        }

        // The server returns either a plain gnark proof JSON or a
        // `{ "proof": {..}, "proof_duration_ms": N }` envelope.
        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| ClientError::ProofParse(format!("invalid response JSON: {e}")))?;
        let proof_value = value.get("proof").unwrap_or(&value);
        if proof_value.is_null() {
            return Err(ClientError::ProverServer(
                "server returned a null proof".to_string(),
            ));
        }
        let proof_json = serde_json::to_string(proof_value)
            .map_err(|e| ClientError::ProofParse(format!("failed to re-serialize proof: {e}")))?;

        proof_from_gnark_json(&proof_json)
            .ok_or_else(|| ClientError::ProofParse(format!("could not parse proof: {text}")))
    }
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

    let spawn_result = Command::new("sh")
        .arg("-c")
        .arg(format!("{cli} start-prover"))
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
    for attempt in 0..retries {
        let ok = client
            .get(format!("{}{}", SERVER_ADDRESS, HEALTH_CHECK))
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
