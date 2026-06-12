//! zone_proofless_shield matrix (spec tag 15): policy-zone public deposit,
//! authorized by the zone program's `zone_auth` signer.
//!
//! Cases:
//!  1. Functional: a SOL deposit driven through the zone test program (which
//!     signs with its `zone_auth` PDA) creates a zone-owned UTXO; the event
//!     carries the zone program id + policy hash, and the indexer's
//!     recomputation + root parity hold (exercising the pk_field-encoded
//!     zone_program_id in the UTXO hash).
//!  2. Invalid signer: `zone_proofless_shield` sent directly to the pool with a
//!     real signer that is not the derived `zone_auth` PDA — reject.

mod common;

use common::{assert_custom, rig_with_tree};
use light_program_test::{PoolIndexer, PoolTestRig, RigError, ZONE_TEST_PROGRAM_ID};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::instruction::{encode_instruction, tag};

// Stable on-chain error codes (programs/shielded-pool/src/error.rs).
const INVALID_SETTLEMENT_ACCOUNTS: u32 = 13;

#[test]
fn zone_proofless_shield_succeeds_and_event_is_faithful() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    if rig.load_zone_test_program().is_err() {
        eprintln!("skipping: zone_test_program.so missing — run `cargo build-sbf -p zone-test-program`");
        return;
    }
    let depositor = Keypair::new();
    rig.airdrop(&depositor.pubkey(), 5_000_000_000).expect("fund");

    let mut data = rig.zone_sol_shield_data(750_000_000, [7u8; 32]);
    data.view_tag = [9u8; 32];
    data.policy_data_hash = Some([5u8; 32]);

    let root_before = rig.state_root(&tree.pubkey()).expect("root");
    let event = rig
        .zone_proofless_shield(&tree, &depositor, &data)
        .expect("zone deposit");

    assert_eq!(event.amount, 750_000_000);
    assert_eq!(event.asset, [0u8; 32]);
    assert_eq!(event.owner_utxo_hash, [7u8; 32]);
    assert_eq!(event.view_tag, [9u8; 32]);
    // The created UTXO is owned by the zone program, with its policy hash.
    assert_eq!(event.zone_program_id, Some(ZONE_TEST_PROGRAM_ID));
    assert_eq!(event.policy_data_hash, Some([5u8; 32]));
    assert_ne!(
        rig.state_root(&tree.pubkey()).expect("root"),
        root_before,
        "leaf must be appended"
    );

    // The indexer recomputes the utxo_hash (pk_field-encoding zone_program_id)
    // and its reference root must equal the on-chain root.
    let mut indexer = PoolIndexer::new();
    indexer.record_proofless_shield(&event);
    assert_eq!(indexer.root(), rig.state_root(&tree.pubkey()).expect("root"));
}

#[test]
fn rejects_zone_proofless_with_wrong_signer() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    let depositor = Keypair::new();
    rig.airdrop(&depositor.pubkey(), 5_000_000_000).expect("fund");

    // Send zone_proofless_shield straight to the pool with the depositor (a
    // real signer, but NOT the zone_auth PDA) in the zone_auth slot. cpi_signer
    // still names the zone test program, so the PDA re-derivation mismatches.
    let data = rig.zone_sol_shield_data(1_000_000, [3u8; 32]);
    let accounts = vec![
        AccountMeta::new(tree.pubkey(), false),
        AccountMeta::new(depositor.pubkey(), true),
        AccountMeta::new_readonly(depositor.pubkey(), true), // not the zone_auth PDA
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new(rig.cpi_authority(), false),
        AccountMeta::new(depositor.pubkey(), false),
        AccountMeta::new_readonly(rig.program_id, false),
    ];
    let ix = Instruction {
        program_id: rig.program_id,
        accounts,
        data: encode_instruction(tag::ZONE_PROOFLESS_SHIELD, &data),
    };
    let payer = rig.payer.insecure_clone();
    let payer_pk = payer.pubkey();
    let blockhash = rig.svm.latest_blockhash();
    let msg = solana_message::Message::new(&[ix], Some(&payer_pk));
    let tx = solana_transaction::Transaction::new(&[&payer, &depositor], msg, blockhash);
    let err = rig
        .svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| RigError::Litesvm(format!("send_transaction: {e:?}")))
        .unwrap_err();
    assert_custom(err, INVALID_SETTLEMENT_ACCOUNTS);
}
