//! Post-instruction checks for `proofless_shield` (SOL deposits).

use solana_pubkey::Pubkey;
use zolana_interface::instruction::{ProoflessShieldEvent, ProoflessShieldIxData};
use zolana_program_test::{proofless_event_for_wallet, ZolanaProgramTest};
use zolana_transaction::{AssetRegistry, Wallet, DEFAULT_TAG_WINDOW};

/// Verify a settled SOL `proofless_shield` against the integration-test
/// expectations: the emitted event faithfully mirrors the instruction data and
/// the settled amount, the state tree advanced, the in-memory indexer agrees
/// with the on-chain root, the recipient view tag locates exactly one deposit,
/// and the recipient wallet discovers the new UTXO.
///
/// `root_before` is the on-chain state root captured before the deposit.
#[track_caller]
#[allow(clippy::too_many_arguments)]
pub fn assert_proofless_shield(
    program_test: &mut ZolanaProgramTest,
    tree: &Pubkey,
    event: &ProoflessShieldEvent,
    data: &ProoflessShieldIxData,
    expected_amount: u64,
    expected_asset: [u8; 32],
    root_before: [u8; 32],
    recipient: &mut Wallet,
) {
    assert_eq!(event.amount, expected_amount, "event amount");
    assert_eq!(event.asset, expected_asset, "event asset");
    assert_eq!(
        event.owner_utxo_hash, data.owner_utxo_hash,
        "owner utxo hash"
    );
    assert_eq!(event.view_tag, data.view_tag, "view tag");
    assert_eq!(event.salt, data.salt, "salt");

    let root_after = program_test.state_root(tree).expect("state root");
    assert_ne!(root_after, root_before, "leaf must be appended");
    assert_eq!(
        program_test.indexer().root(),
        root_after,
        "indexer root must track the on-chain root"
    );

    let by_tag: Vec<_> = program_test
        .indexer()
        .fetch_by_view_tag(&data.view_tag)
        .collect();
    assert_eq!(by_tag.len(), 1, "recipient view tag locates the deposit");
    assert_eq!(
        by_tag[0]
            .proofless()
            .expect("proofless deposit")
            .owner_utxo_hash,
        data.owner_utxo_hash,
        "indexed record owner utxo hash"
    );

    let before = recipient.utxos.len();
    recipient
        .sync(
            &[],
            &[proofless_event_for_wallet(event)],
            &AssetRegistry::default(),
            0,
            DEFAULT_TAG_WINDOW,
        )
        .expect("wallet discovery");
    assert_eq!(
        recipient.utxos.len(),
        before + 1,
        "recipient wallet must discover the deposit"
    );
    let utxo = recipient.utxos.last().expect("discovered UTXO");
    assert_eq!(utxo.hash, event.utxo_hash, "wallet UTXO hash");
    assert_eq!(utxo.utxo.amount, event.amount, "wallet UTXO amount");
}
