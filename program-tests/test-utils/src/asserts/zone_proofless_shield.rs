//! Post-instruction checks for `zone_proofless_shield` (policy-zone deposits).

use solana_pubkey::Pubkey;
use zolana_interface::instruction::{ProoflessShieldEvent, ZoneProoflessShieldIxData};
use zolana_program_test::{proofless_event_for_wallet, ZolanaProgramTest};
use zolana_transaction::Wallet;

/// Verify a settled `zone_proofless_shield` against the integration-test
/// expectations: the emitted event faithfully mirrors the instruction data and
/// the settled amount, the created UTXO is owned by the zone program and
/// carries its policy hash, the state tree advanced, the indexer agrees with
/// the on-chain root, the recipient view tag locates exactly one deposit, and
/// the recipient wallet discovers the new zone-owned UTXO.
///
/// `expected_zone_program_id` is the zone wrapper program id; `root_before` is
/// the on-chain state root captured before the deposit.
#[track_caller]
#[allow(clippy::too_many_arguments)]
pub fn assert_zone_proofless_shield(
    program_test: &mut ZolanaProgramTest,
    tree: &Pubkey,
    event: &ProoflessShieldEvent,
    data: &ZoneProoflessShieldIxData,
    expected_amount: u64,
    expected_asset: [u8; 32],
    expected_zone_program_id: [u8; 32],
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
    assert_eq!(
        event.zone_program_id,
        Some(expected_zone_program_id),
        "UTXO is owned by the zone program"
    );
    assert_eq!(
        event.policy_data_hash, data.policy_data_hash,
        "UTXO carries the zone policy hash"
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

    assert!(
        recipient
            .sync_proofless_deposit(&proofless_event_for_wallet(event))
            .expect("wallet discovery"),
        "recipient wallet must discover the zone deposit"
    );
    let utxo = recipient.utxos.last().expect("discovered UTXO");
    assert_eq!(utxo.hash, event.utxo_hash, "wallet UTXO hash");
    assert_eq!(
        utxo.utxo.zone_program_id.map(|id| id.to_bytes()),
        Some(expected_zone_program_id),
        "wallet UTXO is owned by the zone program"
    );
}
