#![cfg(feature = "solana-rpc")]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_pubkey::Pubkey;
use solana_rpc_client::{
    nonblocking::rpc_client::RpcClient as NonblockingRpcClient,
    rpc_client::{Mocks, RpcClient},
};
use solana_rpc_client_api::{
    config::UiAccountEncoding,
    filter::{Memcmp, MemcmpEncodedBytes, RpcFilterType},
    request::RpcRequest,
};
use zolana_client::{AsyncSolanaRpc, ClientError, ProgramAccountsFilter, Rpc, SolanaRpc};

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
