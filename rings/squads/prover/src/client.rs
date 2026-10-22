//! Test prover server client. The first proof of a process connects to the
//! server of this clone, starting `squads-test-prover-server` from the squads
//! workspace target directory when none is listening. Without a server binary
//! the process proves in process instead.

use std::{
    os::unix::{net::UnixStream, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::OnceLock,
    time::Duration,
};

use zolana_gnark_ffi_prover::{Circuit, ProofInputMap};

use crate::{
    server_protocol::{
        log_path, read_message, socket_path, write_message, ProveRequest, ProveResponse,
    },
    CircuitId, Error, Result, SquadsProof,
};

const SERVER_BINARY: &str = "squads-test-prover-server";
const PROVE_TIMEOUT: Duration = Duration::from_secs(600);
const STARTUP_POLLS: usize = 100;
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(100);

static SERVER_AVAILABLE: OnceLock<bool> = OnceLock::new();

fn server_available() -> bool {
    *SERVER_AVAILABLE.get_or_init(|| {
        let socket = socket_path();
        if UnixStream::connect(&socket).is_ok() {
            return true;
        }
        let Some(binary) = find_server_binary() else {
            eprintln!(
                "squads-prover: {SERVER_BINARY} not built, proving in process \
                 (run `just build-squads-prover-server`)"
            );
            return false;
        };
        match spawn_server(&binary, &socket) {
            Ok(()) => true,
            Err(error) => {
                eprintln!("squads-prover: {error}, proving in process");
                false
            }
        }
    })
}

fn find_server_binary() -> Option<PathBuf> {
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target");
    ["release", "debug"]
        .iter()
        .map(|profile| target.join(profile).join(SERVER_BINARY))
        .find(|binary| binary.exists())
}

fn spawn_server(binary: &Path, socket: &Path) -> std::result::Result<(), String> {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())
        .map_err(|e| format!("open {}: {e}", log_path().display()))?;
    // SAFETY: setsid is async-signal-safe; it detaches the server from the
    // test's process group so it outlives the test process.
    unsafe {
        Command::new(binary)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .pre_exec(|| {
                libc::setsid();
                Ok(())
            })
            .spawn()
    }
    .map_err(|e| format!("spawn {}: {e}", binary.display()))?;
    for _ in 0..STARTUP_POLLS {
        std::thread::sleep(STARTUP_POLL_INTERVAL);
        if UnixStream::connect(socket).is_ok() {
            return Ok(());
        }
    }
    Err(format!("{} did not start listening", binary.display()))
}

/// `None` when no server is available, so the caller proves in process.
pub(crate) fn try_prove_via_server(
    circuit: CircuitId,
    inputs: &ProofInputMap,
) -> Option<Result<SquadsProof>> {
    server_available().then(|| prove_via_server(circuit, inputs))
}

fn prove_via_server(circuit: CircuitId, inputs: &ProofInputMap) -> Result<SquadsProof> {
    let server = |e: std::io::Error| Error::Server(e.to_string());
    let mut stream = UnixStream::connect(socket_path()).map_err(server)?;
    stream
        .set_read_timeout(Some(PROVE_TIMEOUT))
        .map_err(server)?;
    write_message(
        &mut stream,
        &ProveRequest {
            circuit: circuit.name().to_string(),
            inputs: inputs.clone(),
        },
    )
    .map_err(server)?;
    let response: ProveResponse = read_message(&mut stream).map_err(server)?;
    if let Some(error) = response.error {
        return Err(Error::Server(error));
    }
    response
        .proof
        .ok_or_else(|| Error::Server("response carries neither a proof nor an error".to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| Error::Server("proof is not 192 bytes".to_string()))
}
