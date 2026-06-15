//! Policy-zone proofless deposit steps.

use cucumber::when;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_interface::instruction::zone_proofless_shield_cpi;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::ZONE_TEST_PROGRAM_ID;
use zolana_test_utils::asserts::assert_zone_proofless_shield;
use zolana_transaction::Wallet;

use crate::ShieldedPoolWorld;

#[when(expr = "the depositor zone-shields {int} lamports to a fresh recipient")]
fn zone_shield(world: &mut ShieldedPoolWorld, amount: u64) {
    world
        .rpc()
        .load_zone_test_program()
        .expect("zone_test_program.so must be built");

    let tree = world.tree().pubkey();
    let depositor = Keypair::new();
    world
        .rpc()
        .airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("fund");
    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");

    let seed = [5u8; BLINDING_LEN];
    let mut data = world
        .rpc()
        .wallet_zone_sol_shield_data(amount, &recipient, &seed, 0)
        .expect("wallet zone deposit data");
    data.policy_data_hash = Some([5u8; 32]);

    let root_before = world.rpc().state_root(&tree).expect("root");
    let event = world
        .rpc()
        .zone_proofless_shield(&tree, &depositor, &data)
        .expect("zone deposit");

    assert_zone_proofless_shield(
        world.rpc(),
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
fn zone_shield_wrong_signer(world: &mut ShieldedPoolWorld) {
    let tree = world.tree().pubkey();
    let depositor = Keypair::new();
    world
        .rpc()
        .airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("fund");

    let data = world.rpc().zone_sol_shield_data(1_000_000, [3u8; 32]);
    let ix = zone_proofless_shield_cpi(depositor.pubkey(), tree, depositor.pubkey(), &data);
    let err = world
        .rpc()
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .unwrap_err();
    world.last_error = Some(err);
}
