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
        loop {
            attempt += 1;
            let outcome = self
                .http
                .post(&url)
                .header("Content-Type", "application/json")
                .body(body.clone())
                .send();
            match outcome {
                Ok(response) => return Self::parse_response(response),
                Err(_) if attempt < PROVE_MAX_ATTEMPTS => {
                    sleep(Duration::from_secs(PROVE_RETRY_BACKOFF_SECS));
                }
                Err(e) => {
                    return Err(ClientError::ProverServer(format!(
                        "request failed after {attempt} attempt(s): {e}"
                    )));
                }
            }
        }
    }

    fn parse_response(response: reqwest::blocking::Response) -> Result<Proof, ClientError> {
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

    let port = prover_port(&server_address());
    let spawn_result = Command::new("sh")
        .arg("-c")
        .arg(format!("{cli} dev prover start --prover-port {port}"))
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
