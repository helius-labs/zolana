#![cfg(feature = "solana-rpc")]

use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use zolana_client::{Rpc, SolanaRpc};

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
