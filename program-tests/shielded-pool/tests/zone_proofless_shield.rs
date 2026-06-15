//! Policy-zone proofless deposit coverage through the test zone wrapper.

mod common;

use common::{assert_pool_error, program_test_with_tree};
use shielded_pool_program::error::ShieldedPoolError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::instruction::{encode_instruction, tag};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::ZONE_TEST_PROGRAM_ID;
use zolana_test_utils::asserts::assert_zone_proofless_shield;
use zolana_transaction::Wallet;

#[test]
fn zone_proofless_shield_succeeds_and_event_is_faithful() {
    let Some((mut program_test, _authority, tree)) = program_test_with_tree() else {
        return;
    };
    if program_test.load_zone_test_program().is_err() {
        eprintln!(
            "skipping: zone_test_program.so missing — run `cargo build-sbf -p zone-test-program`"
        );
        return;
    }
    let depositor = Keypair::new();
    program_test
        .airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("fund");
    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");

    let seed = [5u8; BLINDING_LEN];
    let mut data = program_test
        .wallet_zone_sol_shield_data(750_000_000, &recipient, &seed, 0)
        .expect("wallet zone deposit data");
    data.policy_data_hash = Some([5u8; 32]);

    let root_before = program_test.state_root(&tree.pubkey()).expect("root");
    let event = program_test
        .zone_proofless_shield(&tree, &depositor, &data)
        .expect("zone deposit");

    assert_zone_proofless_shield(
        &mut program_test,
        &tree.pubkey(),
        &event,
        &data,
        750_000_000,
        [0u8; 32],
        ZONE_TEST_PROGRAM_ID,
        root_before,
        &mut recipient,
    );
}

#[test]
fn rejects_zone_proofless_with_wrong_signer() {
    let Some((mut program_test, _authority, tree)) = program_test_with_tree() else {
        return;
    };
    let depositor = Keypair::new();
    program_test
        .airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("fund");

    // Send zone_proofless_shield straight to the pool with the depositor (a
    // real signer, but NOT the zone_auth PDA) in the zone_auth slot. cpi_signer
    // still names the zone wrapper program, so the PDA re-derivation mismatches.
    let data = program_test.zone_sol_shield_data(1_000_000, [3u8; 32]);
    let accounts = vec![
        AccountMeta::new(tree.pubkey(), false),
        AccountMeta::new(depositor.pubkey(), true),
        AccountMeta::new_readonly(depositor.pubkey(), true), // not the zone_auth PDA
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new(program_test.cpi_authority(), false),
        AccountMeta::new(depositor.pubkey(), false),
        AccountMeta::new_readonly(program_test.program_id, false),
    ];
    let ix = Instruction {
        program_id: program_test.program_id,
        accounts,
        data: encode_instruction(tag::ZONE_PROOFLESS_SHIELD, &data),
    };
    let err = program_test
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidSettlementAccounts);
}
