//! Squads test prover server. Test processes prove through it over a unix
//! socket, so each squads proving key is loaded once, on its first proof, and
//! stays loaded across test binaries. `squads_prover::client` starts it on
//! demand; `just stop-squads-prover-server` stops it.

use std::{
    os::unix::net::{UnixListener, UnixStream},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use squads_prover::{
    prove_in_process,
    server_protocol::{
        pid_path, read_message, socket_path, write_message, ProveRequest, ProveResponse,
    },
    CircuitId,
};
use zolana_gnark_ffi_prover::Circuit;

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn stop(_: libc::c_int) {
    RUNNING.store(false, Ordering::Relaxed);
}

fn main() {
    let socket = socket_path();
    // SAFETY: installing plain signal handlers before any thread is spawned.
    // SIGPIPE is ignored so a client that disconnects early cannot kill it.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
    }
    if socket.exists() {
        if UnixStream::connect(&socket).is_ok() {
            eprintln!(
                "squads prover server already listening on {}",
                socket.display()
            );
            return;
        }
        let _ = std::fs::remove_file(&socket);
    }
    let listener =
        UnixListener::bind(&socket).unwrap_or_else(|e| panic!("bind {}: {e}", socket.display()));
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    if let Err(e) = std::fs::write(pid_path(), std::process::id().to_string()) {
        eprintln!("write {}: {e}", pid_path().display());
    }
    eprintln!(
        "squads prover server listening on {} (pid {})",
        socket.display(),
        std::process::id()
    );

    while RUNNING.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                std::thread::spawn(move || handle(stream));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(pid_path());
}

fn handle(mut stream: UnixStream) {
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    // A connection that closes without a request is a liveness probe.
    let Ok(request) = read_message::<ProveRequest>(&mut stream) else {
        return;
    };
    let response =
        catch_unwind(AssertUnwindSafe(|| respond(request))).unwrap_or_else(|_| ProveResponse {
            proof: None,
            error: Some("prover panicked".to_string()),
        });
    if let Err(e) = write_message(&mut stream, &response) {
        eprintln!("write response: {e}");
    }
}

fn respond(request: ProveRequest) -> ProveResponse {
    let Some(circuit) = CircuitId::ALL
        .iter()
        .copied()
        .find(|circuit| circuit.name() == request.circuit)
    else {
        return ProveResponse {
            proof: None,
            error: Some(format!("unknown circuit {:?}", request.circuit)),
        };
    };
    let start = Instant::now();
    match prove_in_process(circuit, &request.inputs) {
        Ok(proof) => {
            eprintln!("{} proved in {:.2?}", circuit.name(), start.elapsed());
            ProveResponse {
                proof: Some(proof.to_vec()),
                error: None,
            }
        }
        Err(e) => ProveResponse {
            proof: None,
            error: Some(e.to_string()),
        },
    }
}
