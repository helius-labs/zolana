//! Post-instruction checks for `deposit` (SOL deposits).

use rings_interface::instruction::DepositIxData;
use rings_program_test::{DepositOutput, RingsProgramTest};
use rings_transaction::{Wallet, DEFAULT_TAG_WINDOW};
use solana_pubkey::Pubkey;

/// Verify a settled SOL `deposit` against the integration-test
/// expectations: the emitted event faithfully mirrors the instruction data and
/// the settled amount, the state tree advanced, the in-memory indexer agrees
/// with the on-chain root, the recipient view tag locates exactly one deposit,
/// and the recipient wallet discovers the new UTXO.
///
/// `root_before` is the on-chain state root captured before the deposit.
#[track_caller]
#[allow(clippy::too_many_arguments)]
pub fn litesvm_assert_deposit(
    program_test: &mut RingsProgramTest,
    tree: &Pubkey,
    event: &DepositOutput,
    data: &DepositIxData,
    expected_amount: u64,
    expected_asset: [u8; 32],
    root_before: [u8; 32],
    recipient: &mut Wallet,
) {
    assert_eq!(event.output.amount, expected_amount, "event amount");
    assert_eq!(event.output.asset, expected_asset, "event asset");
    assert_eq!(event.output.owner, data.owner, "owner");
    assert_eq!(event.view_tag, data.view_tag, "view tag");
    assert_eq!(event.output.blinding, data.blinding, "blinding");
    assert_eq!(
        event.output.memo, data.memo,
        "event memo mirrors instruction data"
    );

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
        by_tag[0].proofless().expect("proofless deposit").owner,
        data.owner,
        "indexed record owner"
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
        "recipient wallet must discover the deposit"
    );
    let utxo = recipient.utxos.last().expect("discovered UTXO");
    assert_eq!(
        utxo.output_context.hash, event.utxo_hash,
        "wallet UTXO hash"
    );
    assert_eq!(utxo.utxo.amount, event.output.amount, "wallet UTXO amount");
    assert_eq!(
        utxo.utxo.data.memo().map(<[u8]>::to_vec),
        data.memo,
        "wallet UTXO memo mirrors the deposited memo"
    );
}
