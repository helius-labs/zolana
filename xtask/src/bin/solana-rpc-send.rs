//! Records what the Rust client puts on the wire when it sends a transaction,
//! with and without an `RpcSendTransactionConfig`.
//!
//! Row C03 counted `send_transaction_with_config` among the unimplemented trait
//! declarations. It is not one: both Solana adapters override it and hand a real
//! config to `send_and_confirm_transaction_with_spinner_and_config`. Which
//! fields that config puts on the wire, which it omits when unset, and what the
//! `CommitmentConfig` argument beside it contributes are all chosen by
//! `solana_rpc_client`, so they are recorded from a real `SolanaRpc` rather than
//! read off the source.
//!
//! Both entry points send and then confirm, so the listener has to answer more
//! than once and answer by method. Every request it serves is recorded, which is
//! also what pins the confirmation traffic the port has to reproduce.
//!
//! ```text
//! cargo run -p xtask --bin solana-rpc-send            # write the fixture
//! cargo run -p xtask --bin solana-rpc-send -- --check # fail on any drift
//! ```

use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    thread,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::{rpc::Rpc, SolanaRpc};

const FIXTURE: &str = "sdk-libs/ts/vectors/solana-rpc-send-v1.json";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("solana-rpc-send: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let transaction = transaction();
    let fixture = json!({
        "version": 1,
        "transaction": {
            "messageBytes": hex(&transaction.message.serialize()),
            "signature": transaction.signatures[0].to_string(),
        },
        "cases": cases(&transaction)?,
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

/// The three ways a caller reaches the node: the no-config entry point, the
/// configured one left at its default, and the configured one with every field
/// the config carries set to something other than its default.
fn cases(transaction: &Transaction) -> Result<Vec<Value>> {
    let configured = RpcSendTransactionConfig {
        skip_preflight: true,
        // Processed rather than Finalized so the case discriminates: an unset
        // preflight commitment resolves to Finalized, which the default-config
        // case above records.
        preflight_commitment: Some(solana_commitment_config::CommitmentLevel::Processed),
        encoding: Some(solana_transaction_status_client_types::UiTransactionEncoding::Base64),
        max_retries: Some(3),
        min_context_slot: Some(77),
    };

    [
        ("sendTransaction", None),
        (
            "sendTransactionWithDefaultConfig",
            Some(RpcSendTransactionConfig::default()),
        ),
        ("sendTransactionWithConfig", Some(configured)),
    ]
    .into_iter()
    .map(|(id, config)| {
        let server = MockServer::start(transaction.signatures[0].to_string());
        let rpc = SolanaRpc::new(server.url.clone());
        let sent = match config {
            None => rpc.send_transaction(transaction),
            Some(config) => rpc.send_transaction_with_config(transaction, config),
        };
        let requests = server.finish()?;
        let signature = sent.map_err(|error| anyhow::anyhow!("{id}: {error}"))?;
        Ok(json!({
            "id": id,
            "signature": signature.to_string(),
            "requests": requests,
        }))
    })
    .collect()
}

/// A signed transaction with a fixed keypair and blockhash, so the base64 body
/// the client encodes is stable across runs.
fn transaction() -> Transaction {
    let payer = Keypair::new_from_array([5u8; 32]);
    let program = Pubkey::new_from_array([3u8; 32]);
    let instruction = Instruction {
        program_id: program,
        accounts: vec![AccountMeta::new(payer.pubkey(), true)],
        data: vec![9, 8, 7],
    };
    let message = Message::new(&[instruction], Some(&payer.pubkey()));
    Transaction::new(&[&payer], message, Hash::new_from_array([7u8; 32]))
}

/// Answers by JSON-RPC method for as long as the client keeps asking, and hands
/// back every request it served in order.
struct MockServer {
    url: String,
    requests: Receiver<Value>,
    stop: Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
}

impl MockServer {
    fn start(signature: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let url = format!("http://{}", listener.local_addr().expect("local address"));
        listener
            .set_nonblocking(true)
            .expect("nonblocking mock server");
        let stop = Arc::new(AtomicBool::new(false));
        let (sender, requests) = mpsc::channel();
        let handle = thread::spawn({
            let stop = Arc::clone(&stop);
            move || serve(listener, &stop, &sender, &signature)
        });
        Self {
            url,
            requests,
            stop,
            handle,
        }
    }

    fn finish(self) -> Result<Vec<Value>> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle
            .join()
            .map_err(|_| anyhow::anyhow!("mock server thread panicked"))?;
        Ok(self.requests.try_iter().collect())
    }
}

fn serve(listener: TcpListener, stop: &AtomicBool, sender: &Sender<Value>, signature: &str) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("blocking accepted stream");
                let request = read_request_body(&mut stream);
                let response = answer(&request, signature);
                sender.send(request).expect("record request");
                write_response(&mut stream, &response);
            }
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    }
}

/// A node that accepts the transaction and reports it confirmed on the first
/// ask, so the recording stops at the traffic sending requires rather than at
/// whatever a slow confirmation would add.
fn answer(request: &Value, signature: &str) -> Value {
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let result = match method {
        "sendTransaction" => json!(signature),
        "getLatestBlockhash" => json!({
            "context": { "slot": 100 },
            "value": {
                "blockhash": Hash::new_from_array([7u8; 32]).to_string(),
                "lastValidBlockHeight": 400,
            },
        }),
        "getBlockHeight" => json!(300),
        "getSignatureStatuses" => json!({
            "context": { "slot": 100 },
            "value": [{
                "slot": 99,
                "confirmations": null,
                "err": null,
                "status": { "Ok": null },
                "confirmationStatus": "finalized",
            }],
        }),
        other => {
            return json!({
                "jsonrpc": "2.0",
                "id": request.get("id").cloned().unwrap_or(Value::Null),
                "error": { "code": -32601, "message": format!("unrecorded method {other}") },
            })
        }
    };
    json!({
        "jsonrpc": "2.0",
        "id": request.get("id").cloned().unwrap_or(Value::Null),
        "result": result,
    })
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
