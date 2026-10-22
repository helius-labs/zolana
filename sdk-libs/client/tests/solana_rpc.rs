#![cfg(feature = "solana-rpc")]

use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use solana_pubkey::Pubkey;
use solana_rpc_client::{
    mock_sender::MocksMap,
    nonblocking::rpc_client::RpcClient as NonblockingRpcClient,
    rpc_client::{Mocks, RpcClient},
};
use solana_rpc_client_api::{
    config::{RpcSendTransactionConfig, UiAccountEncoding},
    filter::{Memcmp, MemcmpEncodedBytes, RpcFilterType},
    request::RpcRequest,
};
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::EncodedConfirmedTransactionWithStatusMeta;
use zolana_client::{
    rpc::{compile_message, sign_transaction, ComputeBudgetConfig},
    AsyncSolanaRpc, ClientError, ConfirmedInstructionGroups, ProgramAccountsFilter, Rpc, SolanaRpc,
};
use zolana_interface::{
    pda,
    state::{discriminator::SPL_ASSET_COUNTER, SplAssetCounter, SplAssetRegistry},
    PROGRAM_ID_PUBKEY,
};
use zolana_transaction::{SOL_ASSET_ID, SOL_MINT};

#[test]
fn get_account_returns_none_for_missing_account() {
    let rpc = SolanaRpc::with_client(RpcClient::new_mock("succeeds".to_owned()));
    let address = Address::new_from_array(Pubkey::new_unique().to_bytes());

    let account = rpc.get_account(address).expect("get_account");

    assert!(account.is_none());
}

#[test]
fn get_program_accounts_wraps_the_underlying_client() {
    // The mock client returns an empty program-accounts set; this exercises the
    // wrapper + Pubkey->Address mapping end-to-end (used by the lazy registry
    // backfill in sync_wallet).
    let rpc = SolanaRpc::with_client(RpcClient::new_mock("succeeds".to_owned()));
    let program = Address::new_from_array(Pubkey::new_unique().to_bytes());

    // The wrapper must execute and map the underlying Vec<(Pubkey, Account)>
    // into Vec<(Address, Account)> without panicking; the mock's exact contents
    // are not the subject under test.
    let _accounts = rpc
        .get_program_accounts(program)
        .expect("get_program_accounts");
}

#[test]
fn latest_blockhash_preserves_last_valid_block_height() {
    let rpc = SolanaRpc::with_client(RpcClient::new_mock("succeeds".to_owned()));

    let (_blockhash, last_valid_block_height) =
        rpc.get_latest_blockhash().expect("get_latest_blockhash");

    assert_ne!(last_valid_block_height, 0);
}

#[test]
fn common_chain_state_methods_are_supported() {
    let rpc = SolanaRpc::with_client(RpcClient::new_mock("succeeds".to_owned()));
    let address = Address::new_from_array(Pubkey::new_unique().to_bytes());

    rpc.get_balance(address).expect("get_balance");
    rpc.get_block_height().expect("get_block_height");
    rpc.get_slot().expect("get_slot");
}

const DATA_SIZE: usize = 68;
const DISCRIMINATOR: u8 = 4;

fn keyed_account(address: &Address, owner: &Address, data: &[u8]) -> Value {
    json!({
        "pubkey": address.to_string(),
        "account": {
            "lamports": 1_000_000u64,
            "data": [STANDARD.encode(data), "base64"],
            "owner": owner.to_string(),
            "executable": false,
            "rentEpoch": 0u64,
            "space": data.len(),
        }
    })
}

fn program_accounts_mocks(accounts: Vec<Value>) -> Mocks {
    [(RpcRequest::GetProgramAccounts, Value::Array(accounts))]
        .into_iter()
        .collect()
}

fn account_data(discriminator: u8) -> Vec<u8> {
    let mut data = vec![0xAB; DATA_SIZE];
    data[0] = discriminator;
    data
}

fn filter() -> ProgramAccountsFilter {
    ProgramAccountsFilter::new(DATA_SIZE).with_memcmp(0, [DISCRIMINATOR])
}

#[test]
fn filter_maps_to_data_size_and_base64_memcmp() {
    let config = filter().with_memcmp(1, vec![7, 8]).rpc_config();

    assert_eq!(
        config.filters,
        Some(vec![
            RpcFilterType::DataSize(DATA_SIZE as u64),
            RpcFilterType::Memcmp(Memcmp::new(0, MemcmpEncodedBytes::Base64("BA==".into()))),
            RpcFilterType::Memcmp(Memcmp::new(1, MemcmpEncodedBytes::Base64("Bwg=".into()))),
        ])
    );
    assert_eq!(
        config.account_config.encoding,
        Some(UiAccountEncoding::Base64)
    );
    assert_eq!(
        config.account_config.commitment,
        Some(CommitmentConfig::confirmed())
    );
}

#[test]
fn filter_matches_size_and_every_window() {
    let filter = ProgramAccountsFilter::new(4).with_memcmp(1, [2u8, 3]);

    assert!(filter.matches(&[9, 2, 3, 9]));
    assert!(!filter.matches(&[9, 2, 3]));
    assert!(!filter.matches(&[9, 2, 4, 9]));
    assert!(!ProgramAccountsFilter::new(2)
        .with_memcmp(3, [1u8])
        .matches(&[1, 1]));
}

#[test]
fn filtered_query_decodes_matching_accounts() {
    let program = Address::new_unique();
    let pubkey = Address::new_unique();
    let data = account_data(DISCRIMINATOR);
    let rpc = SolanaRpc::with_client(RpcClient::new_mock_with_mocks(
        "succeeds",
        program_accounts_mocks(vec![keyed_account(&pubkey, &program, &data)]),
    ));

    let accounts = rpc
        .get_program_accounts_filtered(program, &filter())
        .expect("filtered query");

    let [(address, account)] = accounts.as_slice() else {
        panic!("expected one account, got {}", accounts.len());
    };
    assert_eq!(*address, pubkey);
    assert_eq!(account.data, data);
    assert_eq!(account.owner, program);
}

#[test]
fn filtered_query_rejects_an_account_outside_the_filter() {
    let program = Address::new_unique();
    let matching = keyed_account(
        &Address::new_unique(),
        &program,
        &account_data(DISCRIMINATOR),
    );
    let other = keyed_account(
        &Address::new_unique(),
        &program,
        &account_data(DISCRIMINATOR + 1),
    );
    let rpc = SolanaRpc::with_client(RpcClient::new_mock_with_mocks(
        "succeeds",
        program_accounts_mocks(vec![matching, other]),
    ));

    let err = rpc
        .get_program_accounts_filtered(program, &filter())
        .expect_err("account outside the filter");

    assert!(
        matches!(&err, ClientError::Rpc(message) if message.contains("outside the filter")),
        "{err}"
    );
}

#[tokio::test]
async fn async_filtered_query_decodes_matching_accounts() {
    let program = Address::new_unique();
    let pubkey = Address::new_unique();
    let data = account_data(DISCRIMINATOR);
    let rpc = AsyncSolanaRpc::with_client(NonblockingRpcClient::new_mock_with_mocks(
        "succeeds".to_owned(),
        program_accounts_mocks(vec![keyed_account(&pubkey, &program, &data)]),
    ));

    let accounts = rpc
        .get_program_accounts_filtered(program, &filter())
        .await
        .expect("filtered query");

    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].0, pubkey);
    assert_eq!(accounts[0].1.data, data);
}

fn registry_account(mint: Address, asset_id: u64) -> Value {
    keyed_account(
        &pda::spl_asset_registry(&mint),
        &PROGRAM_ID_PUBKEY,
        &SplAssetRegistry::account_bytes(mint, asset_id),
    )
}

/// The counter at `next_id` and one `getProgramAccounts` answer per page, in page order.
fn registry_mocks(next_id: u64, pages: Vec<Vec<Value>>) -> MocksMap {
    let mut data = vec![0; SplAssetCounter::SIZE];
    data[0] = SPL_ASSET_COUNTER;
    let start = std::mem::offset_of!(SplAssetCounter, next_id);
    data[start..start + 8].copy_from_slice(&next_id.to_le_bytes());
    let counter = keyed_account(
        &Address::new_from_array(pda::spl_asset_counter().to_bytes()),
        &PROGRAM_ID_PUBKEY,
        &data,
    );
    let mut mocks = MocksMap::default();
    mocks.insert(
        RpcRequest::GetAccountInfo,
        json!({ "context": { "slot": 1 }, "value": counter["account"] }),
    );
    for page in pages {
        mocks.insert(RpcRequest::GetProgramAccounts, Value::Array(page));
    }
    mocks
}

fn registry_rpc(next_id: u64, pages: Vec<Vec<Value>>) -> SolanaRpc {
    SolanaRpc::with_client(RpcClient::new_mock_with_mocks_map(
        "succeeds",
        registry_mocks(next_id, pages),
    ))
}

/// One registered mint per id of `ids`.
fn registered(ids: std::ops::Range<u64>) -> Vec<Value> {
    ids.map(|asset_id| registry_account(Address::new_unique(), asset_id))
        .collect()
}

#[test]
fn the_asset_registry_reads_every_registered_mint() {
    let mint = Address::new_unique();
    let mut page = registered(2..9);
    page.push(registry_account(mint, 9));
    let registry = registry_rpc(10, vec![page])
        .asset_registry()
        .expect("registry");
    assert_eq!(registry.asset_id(&mint).expect("mint"), 9);
    assert_eq!(registry.asset_id(&SOL_MINT).expect("sol"), SOL_ASSET_ID);
}

#[test]
fn an_unregistered_pool_reads_only_sol() {
    let rpc = SolanaRpc::with_client(RpcClient::new_mock("succeeds".to_owned()));
    let registry = rpc.asset_registry().expect("registry");
    assert_eq!(registry.asset_id(&SOL_MINT).expect("sol"), SOL_ASSET_ID);
}

/// An entry off its mint's address, owned elsewhere or outside the page's ids fails the read, never drops out.
#[test]
fn one_invalid_registry_account_fails_the_read() {
    let mint = Address::new_unique();
    let elsewhere = keyed_account(
        &Address::new_unique(),
        &PROGRAM_ID_PUBKEY,
        &SplAssetRegistry::account_bytes(mint, 2),
    );
    let foreign = keyed_account(
        &pda::spl_asset_registry(&mint),
        &Address::new_unique(),
        &SplAssetRegistry::account_bytes(mint, 2),
    );
    let reserved = registry_account(mint, SOL_ASSET_ID);
    for invalid in [elsewhere, foreign, reserved] {
        let error = registry_rpc(
            4,
            vec![vec![registry_account(Address::new_unique(), 3), invalid]],
        )
        .asset_registry()
        .expect_err("invalid entry");
        assert!(
            matches!(error, ClientError::InvalidAssetRegistryAccount { .. }),
            "{error:?}"
        );
    }
}

#[test]
fn a_registry_page_short_of_an_allocated_id_fails_the_read() {
    let error = registry_rpc(10, vec![registered(2..9)])
        .asset_registry()
        .expect_err("short page");
    assert!(
        matches!(
            error,
            ClientError::AssetRegistryPageIncomplete {
                first: 2,
                end: 10,
                found: 7
            }
        ),
        "{error:?}"
    );
}

#[test]
fn a_counter_owned_elsewhere_fails_the_read() {
    let mut mocks = registry_mocks(10, Vec::new());
    let mut counter = mocks
        .pop_front_with_request(&RpcRequest::GetAccountInfo)
        .expect("counter");
    counter["value"]["owner"] = json!(Address::new_unique().to_string());
    mocks.insert(RpcRequest::GetAccountInfo, counter);
    let rpc = SolanaRpc::with_client(RpcClient::new_mock_with_mocks_map("succeeds", mocks));
    assert!(matches!(
        rpc.asset_registry(),
        Err(ClientError::InvalidAssetCounter)
    ));
}

/// Open mint registration can pass any single response cap, the read pages the counter's ids.
#[tokio::test]
async fn the_async_asset_registry_reads_every_page_the_counter_spans() {
    let next_id: u64 = 2 + 4_097;
    let pages = (0..next_id.div_ceil(256))
        .map(|page| registered((page * 256).max(2)..((page + 1) * 256).min(next_id)))
        .collect();
    let rpc = AsyncSolanaRpc::with_client(NonblockingRpcClient::new_mock_with_mocks_map(
        "succeeds",
        registry_mocks(next_id, pages),
    ));
    let registry = rpc.asset_registry().await.expect("registry");
    for asset_id in [2, 255, 256, 4_098] {
        assert_eq!(
            registry.resolve(asset_id).expect("registered id").asset_id,
            asset_id
        );
    }
    assert!(registry.resolve(next_id).is_err());
}

/// A confirmed transaction with one inner instruction, as `getTransaction`
/// returns it. `err` and the inner `stackHeight` are the fields under test.
fn confirmed_transaction(
    err: serde_json::Value,
    inner_stack_height: serde_json::Value,
) -> EncodedConfirmedTransactionWithStatusMeta {
    let payer = Pubkey::new_unique();
    let program = Pubkey::new_unique();
    let status = if err.is_null() {
        serde_json::json!({ "Ok": null })
    } else {
        serde_json::json!({ "Err": err })
    };
    let json = serde_json::json!({
        "slot": 7,
        "blockTime": null,
        "transaction": {
            "signatures": [Signature::from([6u8; 64]).to_string()],
            "message": {
                "header": {
                    "numRequiredSignatures": 1,
                    "numReadonlySignedAccounts": 0,
                    "numReadonlyUnsignedAccounts": 1
                },
                "accountKeys": [payer.to_string(), program.to_string()],
                "recentBlockhash": Pubkey::default().to_string(),
                "instructions": [
                    { "programIdIndex": 1, "accounts": [0], "data": "", "stackHeight": null }
                ]
            }
        },
        "meta": {
            "err": err,
            "status": status,
            "fee": 5000,
            "preBalances": [1, 0],
            "postBalances": [0, 0],
            "innerInstructions": [
                {
                    "index": 0,
                    "instructions": [
                        { "programIdIndex": 1, "accounts": [0], "data": "", "stackHeight": inner_stack_height }
                    ]
                }
            ]
        },
        "version": "legacy"
    });
    serde_json::from_value(json).expect("rpc shape")
}

/// A transaction can record an event and then fail, rolling back its state, so
/// its instruction groups must not reach an indexer.
#[test]
fn failed_transaction_yields_no_instruction_groups() {
    let err = serde_json::json!({ "InstructionError": [0, { "Custom": 7000 }] });

    assert!(matches!(
        ConfirmedInstructionGroups::try_from(confirmed_transaction(err, serde_json::json!(2))),
        Err(ClientError::TransactionFailed(_))
    ));
}

/// Event discovery resolves an event's parent by stack height, so an inner
/// instruction without one cannot be placed.
#[test]
fn inner_instruction_without_stack_height_is_rejected() {
    let successful = serde_json::Value::Null;

    assert!(matches!(
        ConfirmedInstructionGroups::try_from(confirmed_transaction(
            successful.clone(),
            serde_json::Value::Null
        )),
        Err(ClientError::Rpc(_))
    ));
    let groups = ConfirmedInstructionGroups::try_from(confirmed_transaction(
        successful,
        serde_json::json!(2),
    ))
    .expect("complete metadata");
    assert_eq!(
        groups
            .groups
            .iter()
            .flat_map(|group| &group.inner)
            .map(|inner| inner.stack_height)
            .collect::<Vec<_>>(),
        vec![2]
    );
}

/// The bytes `sendTransaction` receives must be the v1 wire format: message
/// first, then a raw signature array. serde field order (signatures, then
/// message) is rejected on read with "invalid transaction config mask", which
/// is what solana-rpc-client 4.1 sent for every v1 transaction.
#[test]
fn a_v1_send_encodes_the_message_ahead_of_its_signatures() {
    let payer = Keypair::new();
    let instruction = Instruction::new_with_bytes(
        Pubkey::new_unique(),
        &[1, 2, 3],
        vec![AccountMeta::new(payer.pubkey(), true)],
    );
    let message = compile_message(
        &payer.pubkey(),
        core::slice::from_ref(&instruction),
        Hash::default(),
        ComputeBudgetConfig::new(200_000).with_priority_fee(5_000),
    )
    .expect("compile");
    let transaction = sign_transaction(message, &[&payer]).expect("sign");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("local address");
    let signature = transaction
        .signatures
        .first()
        .copied()
        .expect("signed transaction");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut payload = read_send_transaction(&listener);
        sender.send(payload.encoded).expect("test still listening");
        let body = json!({
            "jsonrpc": "2.0",
            "result": signature.to_string(),
            "id": payload.id,
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        payload
            .stream
            .write_all(response.as_bytes())
            .expect("write response");
    });

    let rpc = SolanaRpc::new(format!("http://{address}"));
    rpc.send_transaction_with_config(&transaction, RpcSendTransactionConfig::default())
        .expect("send");

    let encoded = receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("sendTransaction body");
    let bytes = STANDARD
        .decode(encoded)
        .expect("sendTransaction transaction is base64");
    let decoded: VersionedTransaction =
        wincode::deserialize(&bytes).expect("v1 wire bytes deserialize");
    assert_eq!(decoded, transaction);
}

#[test]
fn a_legacy_transaction_is_not_sent() {
    use solana_message::{Message, VersionedMessage};
    use solana_transaction::versioned::VersionedTransaction;

    let payer = Keypair::new();
    let message = VersionedMessage::Legacy(Message::new(&[], Some(&payer.pubkey())));
    let transaction = VersionedTransaction::try_new(message, &[&payer]).expect("legacy signs");
    let rpc = SolanaRpc::new("http://127.0.0.1:1");

    let error = rpc
        .send_transaction_with_config(&transaction, RpcSendTransactionConfig::default())
        .expect_err("legacy send");
    assert!(matches!(error, ClientError::UnsupportedTransactionVersion));
}

struct SendTransactionRequest {
    stream: TcpStream,
    id: Value,
    encoded: String,
}

fn read_send_transaction(listener: &TcpListener) -> SendTransactionRequest {
    let started = Instant::now();
    listener.set_nonblocking(true).expect("nonblocking");
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "timed out waiting for sendTransaction"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept sendTransaction: {error}"),
        }
    };
    stream.set_nonblocking(false).expect("blocking");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).expect("read request");
        assert!(read > 0, "client closed before sending a request");
        buf.extend_from_slice(&chunk[..read]);
        if let Some(end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
    };
    let headers = std::str::from_utf8(&buf[..header_end]).expect("request headers");
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if !name.eq_ignore_ascii_case("content-length") {
                return None;
            }
            value.trim().parse::<usize>().ok()
        })
        .expect("content-length");
    let body_at = header_end + 4;
    while buf.len() < body_at + content_length {
        let read = stream.read(&mut chunk).expect("read body");
        assert!(read > 0, "truncated sendTransaction body");
        buf.extend_from_slice(&chunk[..read]);
    }
    let body: Value = serde_json::from_slice(&buf[body_at..body_at + content_length])
        .expect("sendTransaction json");
    assert_eq!(body["method"].as_str(), Some("sendTransaction"));
    let encoded = body["params"]
        .get(0)
        .and_then(Value::as_str)
        .expect("base64 transaction")
        .to_owned();
    SendTransactionRequest {
        stream,
        id: body["id"].clone(),
        encoded,
    }
}
