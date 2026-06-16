//! Shared setup and assertion steps.

use cucumber::{given, then};
use solana_keypair::Keypair;
use solana_signer::Signer;

use crate::common::{assert_instruction_error, assert_pool_error, program_test, tree_account_size};
use crate::ShieldedPoolWorld;

use shielded_pool_program::error::ShieldedPoolError;

#[given(expr = "a booted shielded pool")]
fn boot_pool(world: &mut ShieldedPoolWorld) {
    world.rpc = Some(program_test().expect("shielded_pool_program.so must be built"));
}

#[given(expr = "a protocol config")]
fn protocol_config(world: &mut ShieldedPoolWorld) {
    if world.rpc.is_none() {
        boot_pool(world);
    }
    let authority = Keypair::new();
    world
        .rpc()
        .create_protocol_config(&authority)
        .expect("create_protocol_config");
    world.authority = Some(authority);
}

#[given(expr = "a pool with a tree")]
fn pool_with_tree(world: &mut ShieldedPoolWorld) {
    protocol_config(world);
    let authority = world.authority().insecure_clone();
    let tree = world
        .rpc()
        .create_tree(tree_account_size(), &authority)
        .expect("create_tree");
    world.tree = Some(tree);
}

#[given(expr = "a depositor funded with {int} lamports")]
fn funded_depositor(world: &mut ShieldedPoolWorld, lamports: u64) {
    let depositor = Keypair::new();
    world
        .rpc()
        .airdrop(&depositor.pubkey(), lamports)
        .expect("airdrop");
    world.depositor = Some(depositor);
}

// === shared error-assertion steps (one canonical phrasing each) ===

#[then(expr = "the operation is rejected as unauthorized")]
fn rejected_unauthorized(world: &mut ShieldedPoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::UnauthorizedCaller);
}

#[then(expr = "the operation is rejected as invalid protocol config")]
fn rejected_invalid_config(world: &mut ShieldedPoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::InvalidProtocolConfig);
}

#[then(expr = "the operation is rejected as invalid tree accounts")]
fn rejected_invalid_tree(world: &mut ShieldedPoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::InvalidTreeAccounts);
}

#[then(expr = "the operation is rejected as an invalid transact shape")]
fn rejected_invalid_shape(world: &mut ShieldedPoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::InvalidTransactShape);
}

#[then(expr = "the operation is rejected as invalid settlement accounts")]
fn rejected_invalid_settlement(world: &mut ShieldedPoolWorld) {
    assert_pool_error(
        world.last_error(),
        ShieldedPoolError::InvalidSettlementAccounts,
    );
}

#[then(expr = "the operation is rejected as invalid instruction data")]
fn rejected_invalid_instruction_data(world: &mut ShieldedPoolWorld) {
    assert_pool_error(
        world.last_error(),
        ShieldedPoolError::InvalidInstructionData,
    );
}

#[then(expr = "no event is indexed")]
fn no_event_indexed(world: &mut ShieldedPoolWorld) {
    assert!(world.rpc().indexer().utxos().is_empty());
}

#[then(expr = "the operation is rejected as an invalid SPL asset registry")]
fn rejected_invalid_spl_registry(world: &mut ShieldedPoolWorld) {
    assert_pool_error(
        world.last_error(),
        ShieldedPoolError::InvalidSplAssetRegistry,
    );
}

#[then(expr = "the operation is rejected as an invalid zone config")]
fn rejected_invalid_zone_config(world: &mut ShieldedPoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::InvalidZoneConfig);
}

#[then(expr = "the operation fails with not enough account keys")]
fn rejected_not_enough_accounts(world: &mut ShieldedPoolWorld) {
    assert_instruction_error(world.last_error(), "NotEnoughAccountKeys");
}
