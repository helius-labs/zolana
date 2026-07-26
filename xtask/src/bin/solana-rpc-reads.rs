//! Records what the Rust client puts on the wire for the plain Solana reads,
//! and what `Rpc::create_and_send_transaction` compiles.
//!
//! Row C03 asked whether the TypeScript client is missing part of the Rust
//! surface. The reads below are pass-throughs, so the only behaviour worth
//! comparing is the JSON-RPC method and parameters each one sends and the value
//! it decodes back. Neither is visible from the source: `solana_rpc_client`
//! chooses both, including which commitment rides along and whether
//! `getSignatureStatuses` searches transaction history. So a real `SolanaRpc`
//! is pointed at a listener that records the request and answers with a canned
//! body.
//!
//! `create_and_send_transaction` is the one entry with a body of its own rather
//! than a delegation. It is driven through a recorder that implements only
//! `get_latest_blockhash` and `send_transaction`, so the default body runs and
//! the compiled message it built is captured verbatim.
//!
//! ```text
//! cargo run -p xtask --bin solana-rpc-reads            # write the fixture
//! cargo run -p xtask --bin solana-rpc-reads -- --check # fail on any drift
//! ```

use std::{
    cell::RefCell,
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::ExitCode,
    sync::mpsc::{self, Receiver},
    thread,
};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::{rpc::Rpc, ClientError, SolanaRpc};

const FIXTURE: &str = "sdk-libs/ts/vectors/solana-rpc-reads-v1.json";

/// One exchange: the request the client sent and the answer it was given.
struct Exchange {
    id: &'static str,
    request: Value,
    response: Value,
    decoded: Value,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("solana-rpc-reads: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let fixture = json!({
        "version": 1,
        "reads": reads()?,
        "createAndSendTransaction": create_and_send_transaction()?,
    });
    let mut rendered = serde_json::to_string_pretty(&fixture)?;
    rendered.push('\n');

    let path = repository_root()?.join(FIXTURE);
    if env::args().any(|argument| argument == "--check") {
        let current = fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        if current != rendered {
            bail!("{FIXTURE} is stale; rerun without --check");
        }
        return Ok(ExitCode::SUCCESS);
    }
    fs::write(&path, rendered).with_context(|| format!("writing {}", path.display()))?;
    Ok(ExitCode::SUCCESS)
}

/// Drives each read against a listener that records the request body, so the
/// method name, the parameter list and the commitment come from
/// `solana_rpc_client` rather than from this file.
fn reads() -> Result<Vec<Value>> {
    let signatures = [signature(1), signature(2)];
    let cases: Vec<(&'static str, Value, Box<dyn Fn(&SolanaRpc) -> Value>)> = vec![
        (
            "getSlot",
            json!({ "jsonrpc": "2.0", "id": 1, "result": 214_748_364_755_u64 }),
            Box::new(|rpc| json!(rpc.get_slot().expect("get_slot").to_string())),
        ),
        (
            "getBlockHeight",
            json!({ "jsonrpc": "2.0", "id": 1, "result": 198_765_432_u64 }),
            Box::new(|rpc| json!(rpc.get_block_height().expect("get_block_height").to_string())),
        ),
        (
            "getMinimumBalanceForRentExemption",
            json!({ "jsonrpc": "2.0", "id": 1, "result": 33_594_240_u64 }),
            Box::new(|rpc| {
                json!(rpc
                    .get_minimum_balance_for_rent_exemption(8_236)
                    .expect("get_minimum_balance_for_rent_exemption")
                    .to_string())
            }),
        ),
        (
            "getHealth",
            json!({ "jsonrpc": "2.0", "id": 1, "result": "ok" }),
            Box::new(|rpc| json!(rpc.health().is_ok())),
        ),
        (
            "getSignatureStatuses",
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "context": { "slot": 100 },
                    "value": [
                        {
                            "slot": 92,
                            "confirmations": 7,
                            "err": null,
                            "status": { "Ok": null },
                            "confirmationStatus": "confirmed"
                        },
                        null
                    ]
                }
            }),
            Box::new(move |rpc| {
                let statuses = rpc
                    .get_signature_statuses(signatures.to_vec())
                    .expect("get_signature_statuses");
                json!(statuses
                    .into_iter()
                    .map(|status| match status {
                        None => Value::Null,
                        Some(status) => json!({
                            "slot": status.slot.to_string(),
                            "confirmations": status.confirmations,
                            "confirmationStatus": status.confirmation_status,
                            "ok": status.err.is_none(),
                        }),
                    })
                    .collect::<Vec<_>>())
            }),
        ),
    ];

    cases
        .into_iter()
        .map(|(id, response, call)| {
            let exchange = record(id, response, call)?;
            Ok(json!({
                "id": exchange.id,
                "request": exchange.request,
                "response": exchange.response,
                "decoded": exchange.decoded,
            }))
        })
        .collect()
}

fn record(
    id: &'static str,
    response: Value,
    call: Box<dyn Fn(&SolanaRpc) -> Value>,
) -> Result<Exchange> {
    let server = MockServer::start(response.clone());
    let rpc = SolanaRpc::new(server.url.clone());
    let decoded = call(&rpc);
    Ok(Exchange {
        id,
        request: server.finish()?,
        response,
        decoded,
    })
}

/// `create_and_send_transaction` reads a blockhash, compiles, signs and sends.
/// Recording the compiled transaction rather than mocking the confirmation
/// dance keeps the assertion on the part TypeScript reimplements.
fn create_and_send_transaction() -> Result<Value> {
    let payer = Keypair::new_from_array([5u8; 32]);
    let payer_pubkey = payer.pubkey();
    let writable = Pubkey::new_from_array([9u8; 32]);
    let program = Pubkey::new_from_array([3u8; 32]);
    let blockhash = Hash::new_from_array([7u8; 32]);
    // Two readonly unsigned accounts, introduced high address first. Ordering by
    // first appearance rather than by address puts them the other way round, so
    // the recorded message discriminates between the two compilers.
    let late_readonly = Pubkey::new_from_array([0xeeu8; 32]);
    let early_readonly = Pubkey::new_from_array([0x11u8; 32]);

    let instructions = [
        Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new_readonly(late_readonly, false),
                AccountMeta::new_readonly(early_readonly, false),
                AccountMeta::new_readonly(writable, false),
                AccountMeta::new(payer_pubkey, true),
            ],
            data: vec![1, 2, 3],
        },
        Instruction {
            program_id: program,
            accounts: vec![AccountMeta::new(writable, false)],
            data: vec![4],
        },
    ];

    let recorder = TransactionRecorder {
        blockhash,
        sent: RefCell::new(None),
    };
    let signature = recorder.create_and_send_transaction(
        &instructions,
        Address::new_from_array(payer_pubkey.to_bytes()),
        &[&payer],
    )?;
    let sent = recorder
        .sent
        .into_inner()
        .context("create_and_send_transaction did not send")?;

    Ok(json!({
        "feePayer": payer_pubkey.to_string(),
        "blockhash": blockhash.to_string(),
        "instructions": instructions
            .iter()
            .map(|instruction| json!({
                "programAddress": instruction.program_id.to_string(),
                "accounts": instruction.accounts
                    .iter()
                    .map(|meta| json!({
                        "address": meta.pubkey.to_string(),
                        "isSigner": meta.is_signer,
                        "isWritable": meta.is_writable,
                    }))
                    .collect::<Vec<_>>(),
                "data": hex(&instruction.data),
            }))
            .collect::<Vec<_>>(),
        "messageBytes": hex(&sent.message.serialize()),
        "signatureCount": sent.signatures.len(),
        "signature": signature.to_string(),
    }))
}

/// Implements the two methods `create_and_send_transaction`'s default body
/// calls, so the body itself is what runs.
struct TransactionRecorder {
    blockhash: Hash,
    sent: RefCell<Option<Transaction>>,
}

impl Rpc for TransactionRecorder {
    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Ok((self.blockhash, 1))
    }

    fn send_transaction(&self, transaction: &Transaction) -> Result<Signature, ClientError> {
        *self.sent.borrow_mut() = Some(transaction.clone());
        Ok(transaction.signatures[0])
    }
}

struct MockServer {
    url: String,
    request_rx: Receiver<Value>,
    handle: thread::JoinHandle<()>,
}

impl MockServer {
    fn start(response: Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let url = format!("http://{}", listener.local_addr().expect("local address"));
        let (request_tx, request_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let body = read_request_body(&mut stream);
            request_tx.send(body).expect("record request");
            write_response(&mut stream, &response);
        });
        Self {
            url,
            request_rx,
            handle,
        }
    }

    fn finish(self) -> Result<Value> {
        let request = self
            .request_rx
            .recv()
            .context("mock server received no request")?;
        self.handle
            .join()
            .map_err(|_| anyhow::anyhow!("mock server thread panicked"))?;
        Ok(request)
    }
}

fn read_request_body(stream: &mut TcpStream) -> Value {
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
                break;
            }
        }
    }
    let start = body_start.expect("request has headers");
    serde_json::from_slice(&data[start..]).expect("request body is JSON")
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

fn signature(seed: u8) -> Signature {
    Signature::from([seed; 64])
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
