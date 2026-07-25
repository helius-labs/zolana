//! Rust-side oracle for the TypeScript async-poll parity test (row C19).
//!
//! `poll_async` is a state machine over three inputs: whether the HTTP request
//! reached the server, what status it answered with, and what the body says. Each
//! combination either retries against the wait budget or terminates. The
//! TypeScript port reproduced the arms and was checked by reading them side by
//! side, which is the evidence class that failed this queue's audit.
//!
//! So the arms are generated instead. Every scenario below drives the real
//! `ProverClient::send`, which reaches the real `poll_async`, against a mock
//! server replaying a fixed response script. What gets recorded is the observable
//! behaviour: how many requests Rust made before it stopped, which tells retry
//! from terminate, and which arm it stopped in.
//!
//! The arm tag is a pure function of the Rust error message, computed in
//! `classify` below. Rust carries only `ProverServer` and `ProofParse` through
//! this path and distinguishes the cases by message text, while TypeScript
//! carries a distinct code per case, so the tag is the common vocabulary. Adding
//! a Rust arm without a tag fails `classify` rather than passing silently.
//!
//! Regenerate with
//! `ZOLANA_UPDATE_TS_ORACLES=1 cargo test -p zolana-client --lib ts_poll_oracle`.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};

use serde_json::{json, Value};

use super::client::ProverClient;
use crate::prover::AsyncPollConfig;

/// One second of budget with a one second interval means exactly one wait is
/// affordable, so a scenario that retries twice times out. That makes the retry
/// arms observable in the request count without the oracle sleeping for long.
const POLL_INTERVAL_SECS: u64 = 1;
const MAX_WAIT_SECS: u64 = 1;

/// A gnark proof the parser accepts, so scenarios that reach the parser
/// terminate on the arm under test rather than on proof contents.
fn gnark_proof() -> Value {
    json!({
        "ar": ["0x0", "0x0"],
        "bs": [["0x0", "0x0"], ["0x0", "0x0"]],
        "krs": ["0x0", "0x0"],
    })
}

/// The `/prove` answer that sends the client into the poll loop.
fn queued(job_id: &str) -> MockResponse {
    MockResponse::json(202, json!({ "job_id": job_id }))
}

/// Every distinguishable path through `poll_async`, named by what the server
/// does rather than by what Rust is expected to conclude.
fn scenarios() -> Vec<(&'static str, Vec<MockResponse>)> {
    vec![
        (
            "completed with the proof nested under result",
            vec![MockResponse::json(
                200,
                json!({ "status": "completed", "result": { "proof": gnark_proof(), "proof_duration_ms": 7 } }),
            )],
        ),
        (
            "completed with the proof at the top level",
            vec![MockResponse::json(
                200,
                json!({ "status": "completed", "proof": gnark_proof() }),
            )],
        ),
        (
            "queued once, then completed",
            vec![
                MockResponse::json(200, json!({ "status": "queued" })),
                MockResponse::json(
                    200,
                    json!({ "status": "completed", "result": { "proof": gnark_proof() } }),
                ),
            ],
        ),
        (
            "queued past the wait budget",
            vec![
                MockResponse::json(200, json!({ "status": "queued" })),
                MockResponse::json(200, json!({ "status": "processing" })),
            ],
        ),
        (
            "an unrecognised status keeps polling",
            vec![
                MockResponse::json(200, json!({ "status": "reticulating" })),
                MockResponse::json(200, json!({ "status": "pending" })),
            ],
        ),
        (
            "a body with no status field keeps polling",
            vec![
                MockResponse::json(200, json!({ "note": "still here" })),
                MockResponse::json(200, json!({})),
            ],
        ),
        (
            "failed",
            vec![MockResponse::json(
                200,
                json!({ "status": "failed", "message": "prover rejected witness" }),
            )],
        ),
        (
            "400 is final",
            vec![MockResponse::json(400, json!({ "error": "bad job" }))],
        ),
        (
            "404 is final",
            vec![MockResponse::json(404, json!({ "error": "no such job" }))],
        ),
        (
            "500 is transient, then completed",
            vec![
                MockResponse::json(500, json!({ "error": "overloaded" })),
                MockResponse::json(
                    200,
                    json!({ "status": "completed", "result": { "proof": gnark_proof() } }),
                ),
            ],
        ),
        (
            "500 past the wait budget",
            vec![
                MockResponse::json(500, json!({ "error": "overloaded" })),
                MockResponse::json(503, json!({ "error": "still overloaded" })),
            ],
        ),
        (
            "a dropped connection is transient, then completed",
            vec![
                MockResponse::disconnect(),
                MockResponse::json(
                    200,
                    json!({ "status": "completed", "result": { "proof": gnark_proof() } }),
                ),
            ],
        ),
        (
            "a dropped connection past the wait budget",
            vec![MockResponse::disconnect(), MockResponse::disconnect()],
        ),
        (
            "a body that is not JSON is final",
            vec![MockResponse::text(200, "not json")],
        ),
        ("an empty body is final", vec![MockResponse::text(200, "")]),
        (
            "completed with a null result",
            vec![MockResponse::json(
                200,
                json!({ "status": "completed", "result": Value::Null }),
            )],
        ),
        (
            "completed with a result that is not an object",
            vec![MockResponse::json(
                200,
                json!({ "status": "completed", "result": "done" }),
            )],
        ),
        (
            "completed with no proof anywhere",
            vec![MockResponse::json(200, json!({ "status": "completed" }))],
        ),
        (
            "completed with a null proof",
            vec![MockResponse::json(
                200,
                json!({ "status": "completed", "result": { "proof": Value::Null } }),
            )],
        ),
        (
            "completed with a proof the parser rejects",
            vec![MockResponse::json(
                200,
                json!({ "status": "completed", "result": { "proof": { "ar": ["nope"] } } }),
            )],
        ),
    ]
}

/// Job ids the client must refuse before it builds a status URL from them, since
/// the handle is interpolated into the query string.
fn job_ids() -> Vec<(&'static str, &'static str)> {
    vec![
        ("plain", "job-1"),
        ("underscore and digits", "job_42"),
        ("empty", ""),
        ("query separator", "job&x=1"),
        ("path separator", "job/../secret"),
        ("percent escape", "job%2f"),
        ("whitespace", "job 1"),
        ("too long", "reject me at 257 characters"),
    ]
}

/// The arm Rust stopped in, derived from its message. Rust reuses two error
/// variants across seven outcomes, so the message is the only discriminator it
/// exposes; this turns it into a tag TypeScript can be compared against.
fn classify(message: &str) -> &'static str {
    if message.contains("malformed job id") {
        "jobId"
    } else if message.contains("async proof timed out") {
        "timeout"
    } else if message.contains("async proof failed") {
        "failed"
    } else if message.starts_with("prover server error: status ") {
        "httpStatus"
    } else if message.contains("null proof") {
        "nullProof"
    } else if message.contains("invalid status JSON") {
        "invalidJson"
    } else if message.contains("could not parse proof") {
        "unparsableProof"
    } else {
        panic!("unclassified poll outcome: {message}")
    }
}

fn client(url: &str) -> ProverClient {
    ProverClient::new(url.to_string()).with_async_poll_config(AsyncPollConfig {
        poll_interval_secs: POLL_INTERVAL_SECS,
        max_wait_secs: MAX_WAIT_SECS,
    })
}

/// Drive the real poll loop and record what it did, not what it should have.
fn run(name: &str, job_id: &str, status_responses: Vec<MockResponse>) -> Value {
    let responses: Vec<Value> = status_responses
        .iter()
        .map(MockResponse::describe)
        .collect();
    let mut script = vec![queued(job_id)];
    script.extend(status_responses);
    let server = MockServer::respond_with(script);
    let outcome = client(server.url()).send("{}".to_string());
    let paths = server.paths();
    // The `/prove` request is not part of the poll; the count that matters is how
    // many times the loop went back for a status.
    let status_requests = paths.iter().filter(|path| path.contains("/status")).count();
    let mut case = json!({
        "name": name,
        "jobId": job_id,
        "responses": responses,
        "statusRequests": status_requests,
        "paths": paths,
    });
    match outcome {
        Ok(proof) => {
            case["outcome"] = json!("proof");
            case["proof"] = json!({
                "a": hex(&proof.a),
                "b": hex(&proof.b),
                "c": hex(&proof.c),
                "hasCommitment": proof.commitment.is_some(),
            });
        }
        Err(error) => {
            let message = error.to_string();
            case["outcome"] = json!("error");
            case["arm"] = json!(classify(&message));
            case["message"] = json!(message);
        }
    }
    case
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn oracle_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../ts/client/test/oracles")
        .join("prover-poll-v1.json")
}

#[test]
fn ts_poll_oracle_is_current() {
    let cases: Vec<Value> = scenarios()
        .into_iter()
        .map(|(name, responses)| run(name, "job-1", responses))
        .collect();

    // The job id is checked before any request, so these scenarios never reach
    // the script; an accepted id runs one status request and then times out.
    let ids: Vec<Value> = job_ids()
        .into_iter()
        .map(|(name, id)| {
            let id = if name == "too long" {
                "j".repeat(257)
            } else {
                id.to_string()
            };
            let accepted = (1..=256).contains(&id.len())
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
            // Two queued answers: an accepted handle then polls until the
            // budget runs out, so the count separates a refusal before any
            // request from a poll that ran and timed out.
            let case = run(
                name,
                &id,
                vec![
                    MockResponse::json(200, json!({ "status": "queued" })),
                    MockResponse::json(200, json!({ "status": "queued" })),
                ],
            );
            json!({
                "name": name,
                "jobId": id,
                "accepted": accepted,
                "statusRequests": case["statusRequests"],
                "arm": case["arm"],
            })
        })
        .collect();

    let oracle = json!({
        "config": {
            "pollIntervalSecs": POLL_INTERVAL_SECS,
            "maxWaitSecs": MAX_WAIT_SECS,
        },
        "cases": cases,
        "jobIds": ids,
    });

    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&oracle).expect("render")
    );
    let path = oracle_path();
    let current = std::fs::read_to_string(&path).unwrap_or_default();
    if current == rendered {
        return;
    }
    std::fs::create_dir_all(path.parent().expect("oracle directory")).expect("create oracle dir");
    std::fs::write(&path, &rendered).expect("write oracle");
    assert!(
        std::env::var_os("ZOLANA_UPDATE_TS_ORACLES").is_some(),
        "{} was stale and has been rewritten; commit it",
        path.display()
    );
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

    /// The script goes into the fixture so the TypeScript replay drives the same
    /// bytes rather than a second transcription of them.
    fn describe(&self) -> Value {
        match self {
            Self::Http { status, body } => json!({ "status": status, "body": body }),
            Self::Disconnect => json!({ "disconnect": true }),
        }
    }
}

/// The script is an upper bound, not a schedule: a scenario that terminates on
/// its first status, or refuses the job id before making any request, leaves
/// responses unclaimed. The listener is therefore non-blocking and the thread
/// stops when the scenario says it is done, rather than waiting on an accept
/// that will never arrive.
struct MockServer {
    url: String,
    request_rx: mpsc::Receiver<String>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockServer {
    fn respond_with(responses: Vec<MockResponse>) -> Self {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("mock server should bind to a local port");
        listener
            .set_nonblocking(true)
            .expect("mock server should accept without blocking");
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
            for response in responses {
                let stream = loop {
                    if thread_stop.load(Ordering::Relaxed) {
                        return;
                    }
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                };
                let mut stream = stream;
                stream
                    .set_nonblocking(false)
                    .expect("an accepted stream should read blocking");
                let path = read_request_path(&mut stream);
                if request_tx.send(path).is_err() {
                    return;
                }
                if let MockResponse::Http { status, body } = response {
                    write_response(&mut stream, status, &body);
                }
            }
        });
        Self {
            url,
            request_rx,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn paths(mut self) -> Vec<String> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("mock server thread should finish");
        }
        self.request_rx.try_iter().collect()
    }
}

fn read_request_path(stream: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut buf = [0_u8; 1024];
    let mut body_start = None;
    let mut content_len = None;
    loop {
        let Ok(read) = stream.read(&mut buf) else {
            break;
        };
        if read == 0 {
            break;
        }
        data.extend_from_slice(buf.get(..read).unwrap_or_default());
        if body_start.is_none() {
            if let Some(header_end) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                body_start = Some(header_end + 4);
                let header = String::from_utf8_lossy(data.get(..header_end).unwrap_or_default());
                content_len = Some(content_length(&header).unwrap_or(0));
            }
        }
        if let (Some(start), Some(len)) = (body_start, content_len) {
            if data.len() >= start.saturating_add(len) {
                break;
            }
        }
    }
    let header_end = body_start.unwrap_or(data.len());
    let header = String::from_utf8_lossy(data.get(..header_end).unwrap_or_default());
    header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or_default()
        .to_string()
}

fn content_length(header: &str) -> Option<usize> {
    header.lines().find_map(|line| {
        line.to_ascii_lowercase()
            .strip_prefix("content-length:")
            .map(str::trim)
            .and_then(|value| value.parse().ok())
    })
}

fn write_response(stream: &mut TcpStream, status: u16, body: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
}
