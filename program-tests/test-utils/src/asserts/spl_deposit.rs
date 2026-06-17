//! Post-instruction checks for a public SPL `deposit` deposit.

use solana_pubkey::Pubkey;
use zolana_interface::{event::DepositView, instruction::DepositIxData};
use zolana_program_test::ZolanaProgramTest;
use zolana_transaction::{AssetRegistry, Wallet, DEFAULT_TAG_WINDOW};

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
pub fn assert_spl_deposit(
    program_test: &mut ZolanaProgramTest,
    tree: &Pubkey,
    mint: &Pubkey,
    vault: &Pubkey,
    user_token: &Pubkey,
    event: &DepositView,
    data: &DepositIxData,
    expected_amount: u64,
    vault_before: u64,
    user_token_before: u64,
    root_before: [u8; 32],
    recipient: &mut Wallet,
) {
    assert_eq!(event.amount, expected_amount, "event amount");
    assert_eq!(event.asset, mint.to_bytes(), "event asset is the mint");
    assert_eq!(
        event.owner_utxo_hash, data.owner_utxo_hash,
        "owner utxo hash"
    );
    assert_eq!(event.view_tag, data.view_tag, "view tag");

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
            &[],
            std::slice::from_ref(event),
            &AssetRegistry::default(),
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
    assert_eq!(utxo.hash, event.utxo_hash, "wallet UTXO hash");
    assert_eq!(
        utxo.utxo.asset.to_bytes(),
        mint.to_bytes(),
        "wallet UTXO asset is the mint"
    );
}
