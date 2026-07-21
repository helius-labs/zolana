//! Post-instruction checks for a public SPL `deposit` deposit.

use solana_pubkey::Pubkey;
use zolana_interface::instruction::DepositIxData;
use zolana_program_test::{DepositOutput, ZolanaProgramTest};
use zolana_transaction::{SyncWalletAuthority, Wallet, DEFAULT_TAG_WINDOW};

/// Verify a settled SPL `deposit` against the integration-test
/// expectations: the emitted event faithfully mirrors the instruction data and
/// the mint, the deposit amount moved from the user token account into the
/// asset vault, the state tree advanced, the indexer agrees with the on-chain
/// root, and the recipient wallet discovers the new UTXO with the right asset.
///
/// `vault_before` / `user_token_before` are the token balances captured before
/// the deposit; `root_before` is the on-chain state root captured before it.
pub struct SplDepositAssertArgs<'a, A: ?Sized> {
    pub tree: &'a Pubkey,
    pub mint: &'a Pubkey,
    pub vault: &'a Pubkey,
    pub user_token: &'a Pubkey,
    pub event: &'a DepositOutput,
    pub data: &'a DepositIxData,
    pub expected_amount: u64,
    pub vault_before: u64,
    pub user_token_before: u64,
    pub root_before: [u8; 32],
    pub authority: &'a A,
}

#[track_caller]
pub fn litesvm_assert_spl_deposit<A: SyncWalletAuthority + ?Sized>(
    program_test: &mut ZolanaProgramTest,
    recipient: &mut Wallet,
    args: SplDepositAssertArgs<'_, A>,
) {
    let SplDepositAssertArgs {
        tree,
        mint,
        vault,
        user_token,
        event,
        data,
        expected_amount,
        vault_before,
        user_token_before,
        root_before,
        authority,
    } = args;
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
            authority,
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
