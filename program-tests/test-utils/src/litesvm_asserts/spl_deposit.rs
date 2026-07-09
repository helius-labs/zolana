//! Post-instruction checks for a public SPL `deposit` deposit.

use rings_interface::instruction::DepositIxData;
use rings_program_test::{DepositOutput, RingsProgramTest};
use rings_transaction::{Wallet, DEFAULT_TAG_WINDOW};
use solana_pubkey::Pubkey;

/// Verify a settled SPL `deposit` against the integration-test
/// expectations: the emitted event faithfully mirrors the instruction data and
/// the mint, the deposit amount moved from the user token account into the
/// asset vault, the state tree advanced, the indexer agrees with the on-chain
/// root, and the recipient wallet discovers the new UTXO with the right asset.
///
/// `vault_before` / `user_token_before` are the token balances captured before
/// the deposit; `root_before` is the on-chain state root captured before it.
#[track_caller]
#[allow(clippy::too_many_arguments)]
pub fn litesvm_assert_spl_deposit(
    program_test: &mut RingsProgramTest,
    tree: &Pubkey,
    mint: &Pubkey,
    vault: &Pubkey,
    user_token: &Pubkey,
    event: &DepositOutput,
    data: &DepositIxData,
    expected_amount: u64,
    vault_before: u64,
    user_token_before: u64,
    root_before: [u8; 32],
    recipient: &mut Wallet,
) {
    assert_eq!(event.output.amount, expected_amount, "event amount");
    assert_eq!(
        event.output.asset,
        mint.to_bytes(),
        "event asset is the mint"
    );
    assert_eq!(event.output.owner, data.owner, "owner");
    assert_eq!(event.view_tag, data.view_tag, "view tag");
    assert_eq!(event.output.blinding, data.blinding, "blinding");

    assert_eq!(
        program_test.token_balance(vault),
        Some(vault_before + expected_amount),
        "vault grows by the deposit"
    );
    assert_eq!(
        program_test.token_balance(user_token),
        Some(user_token_before - expected_amount),
        "user token account shrinks by the deposit"
    );

    let root_after = program_test.state_root(tree).expect("state root");
    assert_ne!(root_after, root_before, "leaf must be appended");
    assert_eq!(
        program_test.indexer().root(),
        root_after,
        "indexer root must track the on-chain root"
    );

    let before = recipient.utxos.len();
    recipient
        .sync(
            &[event.to_shielded_transaction(solana_signature::Signature::default())],
            0,
            DEFAULT_TAG_WINDOW,
        )
        .expect("wallet discovery");
    assert_eq!(
        recipient.utxos.len(),
        before + 1,
        "recipient wallet must discover the SPL deposit"
    );
    let utxo = recipient.utxos.last().expect("discovered UTXO");
    assert_eq!(
        utxo.output_context.hash, event.utxo_hash,
        "wallet UTXO hash"
    );
    assert_eq!(
        utxo.utxo.asset.to_bytes(),
        mint.to_bytes(),
        "wallet UTXO asset is the mint"
    );
}
