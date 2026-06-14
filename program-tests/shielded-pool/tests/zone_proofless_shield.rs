//! Policy-zone proofless deposit coverage through the test zone wrapper.

mod common;

use common::{assert_pool_error, rig_with_tree};
use shielded_pool_program::error::ShieldedPoolError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::instruction::{encode_instruction, tag};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::{proofless_event_for_wallet, RigError, ZONE_TEST_PROGRAM_ID};
use zolana_transaction::Wallet;

#[test]
fn zone_proofless_shield_succeeds_and_event_is_faithful() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    if rig.load_zone_test_program().is_err() {
        eprintln!(
            "skipping: zone_test_program.so missing — run `cargo build-sbf -p zone-test-program`"
        );
        return;
    }
    let depositor = Keypair::new();
    rig.airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("fund");
    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");

    let seed = [5u8; BLINDING_LEN];
    let mut data = rig
        .wallet_zone_sol_shield_data(750_000_000, &recipient, &seed, 0)
        .expect("wallet zone deposit data");
    data.policy_data_hash = Some([5u8; 32]);

    let root_before = rig.state_root(&tree.pubkey()).expect("root");
    let event = rig
        .zone_proofless_shield(&tree, &depositor, &data)
        .expect("zone deposit");

    assert_eq!(event.amount, 750_000_000);
    assert_eq!(event.asset, [0u8; 32]);
    assert_eq!(event.owner_utxo_hash, data.owner_utxo_hash);
    assert_eq!(event.view_tag, data.view_tag);
    // The created UTXO is owned by the zone program, with its policy hash.
    assert_eq!(event.zone_program_id, Some(ZONE_TEST_PROGRAM_ID));
    assert_eq!(event.policy_data_hash, Some([5u8; 32]));
    assert_ne!(
        rig.state_root(&tree.pubkey()).expect("root"),
        root_before,
        "leaf must be appended"
    );

    assert_eq!(
        rig.indexer().root(),
        rig.state_root(&tree.pubkey()).expect("root")
    );
    let by_tag: Vec<_> = rig.indexer().fetch_by_view_tag(&data.view_tag).collect();
    assert_eq!(by_tag.len(), 1, "recipient view tag locates the deposit");
    assert!(
        recipient
            .sync_proofless_deposit(&proofless_event_for_wallet(&event))
            .expect("wallet discovery"),
        "recipient wallet must discover the zone deposit"
    );
    assert_eq!(recipient.utxos[0].hash, event.utxo_hash);
    assert_eq!(
        recipient.utxos[0]
            .utxo
            .zone_program_id
            .map(|id| id.to_bytes()),
        Some(ZONE_TEST_PROGRAM_ID)
    );
}

#[test]
fn rejects_zone_proofless_with_wrong_signer() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    let depositor = Keypair::new();
    rig.airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("fund");

    // Send zone_proofless_shield straight to the pool with the depositor (a
    // real signer, but NOT the zone_auth PDA) in the zone_auth slot. cpi_signer
    // still names the zone wrapper program, so the PDA re-derivation mismatches.
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
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
}
