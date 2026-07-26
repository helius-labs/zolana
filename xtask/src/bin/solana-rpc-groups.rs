//! Records how the Rust client groups a confirmed transaction's instructions.
//!
//! Row C05 left the grouping rules unpinned: both sides reimplement the same
//! walk over a `getTransaction` result, and reading alone cannot settle which
//! account keys an index resolves against, what stack height each slot gets, or
//! which malformed bodies are refused. So a real `SolanaRpc` is pointed at a
//! listener that answers with a canned `getTransaction` body, and whatever
//! `fetch_confirmed_instruction_groups` makes of it -- groups or refusal -- is
//! recorded verbatim.
//!
//! The refusals are recorded as acceptance decisions, not as messages to match:
//! Rust returns one `ClientError::Rpc(String)` for every malformed body while
//! TypeScript names a structured code per path, so the message is not portable
//! but the accept/reject decision is.
//!
//! ```text
//! cargo run -p xtask --bin solana-rpc-groups            # write the fixture
//! cargo run -p xtask --bin solana-rpc-groups -- --check # fail on any drift
//! ```

use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use solana_signature::Signature;
use zolana_client::SolanaRpc;

const FIXTURE: &str = "sdk-libs/ts/vectors/solana-rpc-groups-v1.json";

/// Base58 account keys the cases index into. The message carries the first
/// three; the last two arrive through the address lookup table, readonly listed
/// before writable in the body so a client that concatenates them in listed
/// order rather than writable-first resolves the wrong key.
const MESSAGE_KEYS: [&str; 3] = [
    "11111111111111111111111111111111",
    "SysvarC1ock11111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111",
];
const LOADED_WRITABLE: &str = "Stake11111111111111111111111111111111111111";
const LOADED_READONLY: &str = "SysvarRent111111111111111111111111111111111";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("solana-rpc-groups: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let fixture = json!({
        "version": 1,
        "signature": signature().to_string(),
        "cases": cases()?,
    });
    let mut rendered = serde_json::to_string_pretty(&fixture)?;
    rendered.push('\n');

    let path = repository_root()?.join(FIXTURE);
    if env::args().any(|argument| argument == "--check") {
        let current =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        if current != rendered {
            bail!("{FIXTURE} is stale; rerun without --check");
        }
        return Ok(ExitCode::SUCCESS);
    }
    fs::write(&path, rendered).with_context(|| format!("writing {}", path.display()))?;
    Ok(ExitCode::SUCCESS)
}

fn cases() -> Result<Vec<Value>> {
    let cases = [
        ("outerOnly", outer_only()),
        ("innerGroups", inner_groups()),
        ("loadedAddresses", loaded_addresses()),
        ("emptyInstructions", empty_instructions()),
        ("missingMeta", missing_meta()),
        ("missingInnerInstructions", missing_inner_instructions()),
        ("innerIndexPastLastOuter", inner_index_past_last_outer()),
        (
            "programIdIndexOutOfBounds",
            program_id_index_out_of_bounds(),
        ),
        ("accountIndexOutOfBounds", account_index_out_of_bounds()),
        (
            "loadedAddressIndexWithoutTable",
            loaded_index_without_table(),
        ),
        ("base64Transaction", base64_transaction()),
        ("parsedMessage", parsed_message()),
        ("parsedInnerInstruction", parsed_inner_instruction()),
    ];

    cases
        .into_iter()
        .map(|(name, result)| {
            let decision = decide(&result)?;
            Ok(json!({
                "name": name,
                "result": result,
                "accepted": decision.is_some(),
                "groups": decision,
            }))
        })
        .collect()
}

/// `Some(groups)` when the Rust client accepts the body, `None` when it refuses.
///
/// Every case must be answered in one request. `fetch_confirmed_transaction`
/// retries any transport or decode failure for thirty seconds, so a body the
/// RPC client cannot deserialize would be recorded as a grouping refusal it is
/// not; a second request is that mistake, and it fails the run.
fn decide(result: &Value) -> Result<Option<Value>> {
    let server = MockServer::start(json!({ "jsonrpc": "2.0", "id": 1, "result": result }));
    let rpc = SolanaRpc::new(server.url.clone());
    let groups = rpc.fetch_confirmed_instruction_groups(&signature());
    let requests = server.finish()?;
    if requests != 1 {
        bail!("the RPC client re-requested a case body {requests} times; it does not deserialize");
    }
    Ok(groups.ok().map(|groups| {
        Value::Array(
            groups
                .groups
                .iter()
                .map(|group| {
                    json!({
                        "outer": instruction_json(&group.outer),
                        "inner": group.inner.iter().map(instruction_json).collect::<Vec<_>>(),
                    })
                })
                .collect(),
        )
    }))
}

fn instruction_json(instruction: &zolana_event::ParsedInstruction) -> Value {
    json!({
        "programId": instruction.program_id.to_string(),
        "accounts": instruction
            .accounts
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "data": hex(&instruction.data),
        "stackHeight": instruction.stack_height,
    })
}

/// A `getTransaction` result body, JSON encoding with a raw message.
fn transaction(instructions: Value, meta: Value) -> Value {
    json!({
        "slot": 100,
        "blockTime": 1_700_000_000_u64,
        "transaction": {
            "signatures": [signature().to_string()],
            "message": {
                "header": {
                    "numRequiredSignatures": 1,
                    "numReadonlySignedAccounts": 0,
                    "numReadonlyUnsignedAccounts": 2,
                },
                "accountKeys": MESSAGE_KEYS,
                "recentBlockhash": MESSAGE_KEYS[0],
                "instructions": instructions,
            },
        },
        "meta": meta,
    })
}

fn compiled(program_id_index: u8, accounts: Vec<u8>, data: &[u8]) -> Value {
    json!({
        "programIdIndex": program_id_index,
        "accounts": accounts,
        "data": bs58::encode(data).into_string(),
        "stackHeight": Value::Null,
    })
}

fn meta(inner_instructions: Value, loaded_addresses: Option<Value>) -> Value {
    let mut meta = json!({
        "err": Value::Null,
        "status": { "Ok": Value::Null },
        "fee": 5000,
        "preBalances": [1u64],
        "postBalances": [1u64],
        "innerInstructions": inner_instructions,
        "logMessages": Vec::<String>::new(),
        "rewards": Vec::<Value>::new(),
    });
    if let Some(loaded) = loaded_addresses {
        meta["loadedAddresses"] = loaded;
    }
    meta
}

fn outer_only() -> Value {
    transaction(
        json!([compiled(0, vec![1, 2], &[7, 8, 9])]),
        meta(json!([]), None),
    )
}

/// Two outer instructions with the inner group hanging off the second, so a
/// client that attached inner instructions positionally rather than by `index`
/// would put them on the first.
fn inner_groups() -> Value {
    transaction(
        json!([compiled(0, vec![1], &[1]), compiled(1, vec![0, 2], &[2, 2]),]),
        meta(
            json!([{
                "index": 1,
                "instructions": [
                    {
                        "programIdIndex": 2,
                        "accounts": [0],
                        "data": bs58::encode([3u8]).into_string(),
                        "stackHeight": 2,
                    },
                    {
                        "programIdIndex": 2,
                        "accounts": [1],
                        "data": bs58::encode([4u8]).into_string(),
                        "stackHeight": 3,
                    },
                ],
            }]),
            None,
        ),
    )
}

/// Indexes 3 and 4 reach past the message keys into the lookup table. The body
/// lists `readonly` first to make the writable-before-readonly order load-bearing.
fn loaded_addresses() -> Value {
    transaction(
        json!([compiled(0, vec![3, 4], &[5])]),
        meta(
            json!([]),
            Some(json!({
                "readonly": [LOADED_READONLY],
                "writable": [LOADED_WRITABLE],
            })),
        ),
    )
}

fn empty_instructions() -> Value {
    transaction(json!([]), meta(json!([]), None))
}

fn missing_meta() -> Value {
    transaction(json!([compiled(0, vec![], &[1])]), Value::Null)
}

fn missing_inner_instructions() -> Value {
    transaction(json!([compiled(0, vec![], &[1])]), meta(Value::Null, None))
}

fn inner_index_past_last_outer() -> Value {
    transaction(
        json!([compiled(0, vec![], &[1])]),
        meta(
            json!([{
                "index": 3,
                "instructions": [{
                    "programIdIndex": 0,
                    "accounts": [],
                    "data": bs58::encode([1u8]).into_string(),
                    "stackHeight": 2,
                }],
            }]),
            None,
        ),
    )
}

fn program_id_index_out_of_bounds() -> Value {
    transaction(json!([compiled(9, vec![0], &[1])]), meta(json!([]), None))
}

fn account_index_out_of_bounds() -> Value {
    transaction(json!([compiled(0, vec![9], &[1])]), meta(json!([]), None))
}

/// The same index the `loadedAddresses` case resolves, with no table in the
/// metadata: the key list is then only the message's own.
fn loaded_index_without_table() -> Value {
    transaction(json!([compiled(0, vec![3], &[5])]), meta(json!([]), None))
}

fn base64_transaction() -> Value {
    let mut body = transaction(json!([compiled(0, vec![], &[1])]), meta(json!([]), None));
    body["transaction"] = json!(["AQAB", "base64"]);
    body
}

/// A `jsonParsed` message, which carries named fields instead of the compiled
/// indexes both clients walk.
fn parsed_message() -> Value {
    let mut body = transaction(json!([compiled(0, vec![], &[1])]), meta(json!([]), None));
    body["transaction"]["message"] = json!({
        "accountKeys": [{
            "pubkey": MESSAGE_KEYS[0],
            "signer": true,
            "writable": true,
            "source": "transaction",
        }],
        "recentBlockhash": MESSAGE_KEYS[0],
        "instructions": [{
            "program": "system",
            "programId": MESSAGE_KEYS[0],
            "parsed": { "type": "transfer" },
            "stackHeight": Value::Null,
        }],
    });
    body
}

/// An inner instruction in `jsonParsed` form under a raw outer message.
fn parsed_inner_instruction() -> Value {
    transaction(
        json!([compiled(0, vec![], &[1])]),
        meta(
            json!([{
                "index": 0,
                "instructions": [{
                    "program": "system",
                    "programId": MESSAGE_KEYS[0],
                    "parsed": { "type": "transfer" },
                    "stackHeight": 2,
                }],
            }]),
            None,
        ),
    )
}

/// Answers the same body to every request until the caller stops asking, and
/// reports how many it served.
struct MockServer {
    url: String,
    served: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
}

impl MockServer {
    fn start(response: Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let url = format!("http://{}", listener.local_addr().expect("local address"));
        listener
            .set_nonblocking(true)
            .expect("nonblocking mock server");
        let served = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = thread::spawn({
            let served = Arc::clone(&served);
            let stop = Arc::clone(&stop);
            move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_nonblocking(false)
                                .expect("blocking accepted stream");
                            read_request_body(&mut stream);
                            served.fetch_add(1, Ordering::Relaxed);
                            write_response(&mut stream, &response);
                        }
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
            }
        });
        Self {
            url,
            served,
            stop,
            handle,
        }
    }

    fn finish(self) -> Result<usize> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle
            .join()
            .map_err(|_| anyhow::anyhow!("mock server thread panicked"))?;
        Ok(self.served.load(Ordering::Relaxed))
    }
}

fn read_request_body(stream: &mut TcpStream) {
    let mut data = Vec::new();
    let mut buffer = [0u8; 1024];
    let mut body_start = None;
    let mut content_length = None;
    loop {
        let read = stream.read(&mut buffer).expect("read request");
        assert!(read != 0, "client closed before sending a request");
        data.extend_from_slice(&buffer[..read]);
        if body_start.is_none() {
            if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                body_start = Some(index + 4);
                content_length = parse_content_length(&String::from_utf8_lossy(&data[..index]));
            }
        }
        if let (Some(start), Some(length)) = (body_start, content_length) {
            if data.len() >= start + length {
                return;
            }
        }
    }
}

fn parse_content_length(header: &str) -> Option<usize> {
    header.lines().find_map(|line| {
        line.to_ascii_lowercase()
            .strip_prefix("content-length:")
            .map(str::trim)
            .and_then(|value| value.parse().ok())
    })
}

fn write_response(stream: &mut TcpStream, body: &Value) {
    let body = serde_json::to_string(body).expect("serialize response");
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .expect("write response");
}

fn signature() -> Signature {
    Signature::from([1u8; 64])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn repository_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(PathBuf::from)
        .context("xtask has a parent directory")
}
