//! Post-instruction checks for `ring_deposit` (policy-ring deposits).

use solana_pubkey::Pubkey;
use zolana_interface::instruction::RingAssetDeposit;
use zolana_program_test::{ZolanaProgramTest, RingDepositOutput};
use zolana_transaction::{SyncWalletAuthority, Wallet, DEFAULT_TAG_WINDOW};

/// Verify a settled `ring_deposit` against the integration-test
/// expectations: the emitted owner-hidden event faithfully mirrors the
/// instruction data and the settled amount, the created UTXO is owned by the
/// ring program and carries its policy hash, the state tree advanced, the
/// indexer agrees with the on-chain root, the recipient view tag locates
/// exactly one deposit, and the recipient wallet discovers the new ring-owned
/// UTXO.
///
/// `expected_ring_program_id` is the ring wrapper program id; `root_before` is
/// the on-chain state root captured before the deposit.
pub struct RingDepositAssertArgs<'a, A: ?Sized> {
    pub tree: &'a Pubkey,
    pub event: &'a RingDepositOutput,
    pub data: &'a RingAssetDeposit,
    pub expected_amount: u64,
    pub expected_asset: [u8; 32],
    pub expected_ring_program_id: [u8; 32],
    pub root_before: [u8; 32],
    pub authority: &'a A,
}

#[track_caller]
pub fn litesvm_assert_ring_deposit<A: SyncWalletAuthority + ?Sized>(
    program_test: &mut ZolanaProgramTest,
    recipient: &mut Wallet,
    args: RingDepositAssertArgs<'_, A>,
) {
    let RingDepositAssertArgs {
        tree,
        event,
        data,
        expected_amount,
        expected_asset,
        expected_ring_program_id,
        root_before,
        authority,
    } = args;
    let expected = RingDepositOutput {
        view_tag: data.view_tag,
        utxo_hash: event.utxo_hash,
        output_tree: event.output_tree,
        leaf_index: event.leaf_index,
        output: zolana_event::EncryptedRingDepositOutput {
            owner_utxo_hash: data.owner_utxo_hash,
            asset: expected_asset,
            amount: expected_amount,
            data_hash: data.data_hash,
            ring_program_id: expected_ring_program_id,
            ring_data_hash: data.ring_data_hash,
            encrypted: zolana_event::EncryptedRingDepositData {
                tx_viewing_pk: data.encrypted.tx_viewing_pk,
                salt: data.encrypted.salt,
                ciphertext: data.encrypted.ciphertext.clone(),
            },
        },
    };
    assert_eq!(*event, expected, "ring deposit event");

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
        "recipient wallet must discover the ring deposit"
    );
    let utxo = recipient.utxos.last().expect("discovered UTXO");
    assert_eq!(
        utxo.output_context.hash, event.utxo_hash,
        "wallet UTXO hash"
    );
    assert_eq!(
        utxo.utxo.ring_program_id.map(|id| id.to_bytes()),
        Some(expected_ring_program_id),
        "wallet UTXO is owned by the ring program"
    );
}
