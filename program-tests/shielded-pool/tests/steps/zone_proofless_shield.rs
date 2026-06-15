//! Policy-zone proofless deposit steps. Faithful port of
//! `tests/zone_proofless_shield.rs`.

use cucumber::when;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::instruction::tag;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::ZONE_TEST_PROGRAM_ID;
use zolana_test_utils::asserts::assert_zone_proofless_shield;
use zolana_transaction::Wallet;

use crate::PoolWorld;

#[when(expr = "the depositor zone-shields {int} lamports to a fresh recipient")]
fn zone_shield(world: &mut PoolWorld, amount: u64) {
    world
        .rig()
        .load_zone_test_program()
        .expect("zone_test_program.so must be built");

    let tree = world.tree().pubkey();
    let depositor = Keypair::new();
    world
        .rig()
        .airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("fund");
    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");

    let seed = [5u8; BLINDING_LEN];
    let mut data = world
        .rig()
        .wallet_zone_sol_shield_data(amount, &recipient, &seed, 0)
        .expect("wallet zone deposit data");
    data.policy_data_hash = Some([5u8; 32]);

    let root_before = world.rig().state_root(&tree).expect("root");
    let event = world
        .rig()
        .zone_proofless_shield(&tree, &depositor, &data)
        .expect("zone deposit");

    assert_zone_proofless_shield(
        world.rig(),
        &tree,
        &event,
        &data,
        amount,
        [0u8; 32],
        ZONE_TEST_PROGRAM_ID,
        root_before,
        &mut recipient,
    );
    world.depositor = Some(depositor);
    world.recipient = Some(recipient);
}

#[when(expr = "a zone proofless deposit is sent straight to the pool with the wrong signer")]
fn zone_shield_wrong_signer(world: &mut PoolWorld) {
    let tree = world.tree().pubkey();
    let depositor = Keypair::new();
    world
        .rig()
        .airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("fund");

    let data = world.rig().zone_sol_shield_data(1_000_000, [3u8; 32]);
    let cpi_authority = world.rig().cpi_authority();
    let program_id = world.rig().program_id;
    let accounts = vec![
        AccountMeta::new(tree, false),
        AccountMeta::new(depositor.pubkey(), true),
        AccountMeta::new_readonly(depositor.pubkey(), true),
        AccountMeta::new_readonly(Pubkey::default(), false),
        AccountMeta::new(cpi_authority, false),
        AccountMeta::new(depositor.pubkey(), false),
        AccountMeta::new_readonly(program_id, false),
    ];
    let mut instruction_data = vec![tag::ZONE_PROOFLESS_SHIELD];
    instruction_data.extend_from_slice(
        &data
            .serialize()
            .expect("zone proofless ix data serialization is infallible"),
    );
    let ix = Instruction {
        program_id,
        accounts,
        data: instruction_data,
    };
    let err = world
        .rig()
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .unwrap_err();
    world.last_error = Some(err);
}
