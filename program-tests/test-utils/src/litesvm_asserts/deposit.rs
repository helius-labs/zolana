//! Post-instruction checks for `deposit` (SOL deposits).

use solana_pubkey::Pubkey;
use zolana_interface::instruction::DepositIxData;
use zolana_program_test::{DepositOutput, ZolanaProgramTest};
use zolana_transaction::{SyncWalletAuthority, Wallet, DEFAULT_TAG_WINDOW};

/// Verify a settled SOL `deposit` against the integration-test
/// expectations: the emitted event faithfully mirrors the instruction data and
/// the settled amount, the state tree advanced, the in-memory indexer agrees
/// with the on-chain root, the recipient view tag locates exactly one deposit,
/// and the recipient wallet discovers the new UTXO.
///
/// `root_before` is the on-chain state root captured before the deposit.
pub struct DepositAssertArgs<'a, A: ?Sized> {
    pub tree: &'a Pubkey,
    pub event: &'a DepositOutput,
    pub data: &'a DepositIxData,
    pub expected_amount: u64,
    pub expected_asset: [u8; 32],
    pub root_before: [u8; 32],
    pub authority: &'a A,
}

#[track_caller]
pub fn litesvm_assert_deposit<A: SyncWalletAuthority + ?Sized>(
    program_test: &mut ZolanaProgramTest,
    recipient: &mut Wallet,
    args: DepositAssertArgs<'_, A>,
) {
    let DepositAssertArgs {
        tree,
        event,
        data,
        expected_amount,
        expected_asset,
        root_before,
        authority,
    } = args;
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
    let indexed = by_tag.first().expect("one indexed deposit");
    assert_eq!(
        indexed.proofless().expect("proofless deposit").owner,
        data.owner,
        "indexed record owner"
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
