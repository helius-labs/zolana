#![cfg(feature = "solana-rpc")]

use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_transaction_status_client_types::EncodedConfirmedTransactionWithStatusMeta;
use zolana_client::{ClientError, ConfirmedInstructionGroups, Rpc, SolanaRpc};

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
