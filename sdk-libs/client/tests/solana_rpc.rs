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
