//! Shared `Given` steps: boot the pool, create the protocol config, create a
//! tree, and fund a depositor. These mirror `common::program_test` and
//! `common::program_test_with_tree` from the original per-file litesvm tests.

use cucumber::{given, then};
use solana_keypair::Keypair;
use solana_signer::Signer;

use crate::common::{assert_instruction_error, assert_pool_error, program_test, tree_account_size};
use crate::PoolWorld;

use shielded_pool_program::error::ShieldedPoolError;

/// Boot a fresh litesvm rig with the shielded-pool program loaded.
///
/// The original tests skipped silently when the `.so` was missing; CI builds it
/// first (`just build-programs`), so the BDD harness `.expect`s it instead.
#[given(expr = "a booted shielded pool")]
fn boot_pool(world: &mut PoolWorld) {
    world.rig = Some(program_test().expect("shielded_pool_program.so must be built"));
}

/// Boot the pool and create the protocol config under a fresh authority.
#[given(expr = "a protocol config")]
fn protocol_config(world: &mut PoolWorld) {
    if world.rig.is_none() {
        boot_pool(world);
    }
    let authority = Keypair::new();
    world
        .rig()
        .create_protocol_config(&authority)
        .expect("create_protocol_config");
    world.authority = Some(authority);
}

/// Boot the pool, create the protocol config, and create a state tree.
///
/// Equivalent to `program_test_with_tree()` used by most original tests.
#[given(expr = "a pool with a tree")]
fn pool_with_tree(world: &mut PoolWorld) {
    protocol_config(world);
    let authority = world.authority().insecure_clone();
    let tree = world
        .rig()
        .create_tree(tree_account_size(), &authority)
        .expect("create_tree");
    world.tree = Some(tree);
}

/// Fund a fresh depositor with the given number of lamports.
#[given(expr = "a depositor funded with {int} lamports")]
fn funded_depositor(world: &mut PoolWorld, lamports: u64) {
    let depositor = Keypair::new();
    world
        .rig()
        .airdrop(&depositor.pubkey(), lamports)
        .expect("airdrop");
    world.depositor = Some(depositor);
}

// === shared error-assertion steps (one canonical phrasing each) ===

#[then(expr = "the operation is rejected as unauthorized")]
fn rejected_unauthorized(world: &mut PoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::UnauthorizedCaller);
}

#[then(expr = "the operation is rejected as invalid protocol config")]
fn rejected_invalid_config(world: &mut PoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::InvalidProtocolConfig);
}

#[then(expr = "the operation is rejected as invalid tree accounts")]
fn rejected_invalid_tree(world: &mut PoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::InvalidTreeAccounts);
}

#[then(expr = "the operation is rejected as an invalid transact shape")]
fn rejected_invalid_shape(world: &mut PoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::InvalidTransactShape);
}

#[then(expr = "the operation is rejected as invalid settlement accounts")]
fn rejected_invalid_settlement(world: &mut PoolWorld) {
    assert_pool_error(
        world.last_error(),
        ShieldedPoolError::InvalidSettlementAccounts,
    );
}

#[then(expr = "the operation is rejected as invalid instruction data")]
fn rejected_invalid_instruction_data(world: &mut PoolWorld) {
    assert_pool_error(
        world.last_error(),
        ShieldedPoolError::InvalidInstructionData,
    );
}

#[then(expr = "no event is indexed")]
fn no_event_indexed(world: &mut PoolWorld) {
    assert!(world.rig().indexer().utxos().is_empty());
}

#[then(expr = "the operation is rejected as an invalid SPL asset registry")]
fn rejected_invalid_spl_registry(world: &mut PoolWorld) {
    assert_pool_error(
        world.last_error(),
        ShieldedPoolError::InvalidSplAssetRegistry,
    );
}

#[then(expr = "the operation is rejected as an invalid zone config")]
fn rejected_invalid_zone_config(world: &mut PoolWorld) {
    assert_pool_error(world.last_error(), ShieldedPoolError::InvalidZoneConfig);
}

#[then(expr = "the operation fails with not enough account keys")]
fn rejected_not_enough_accounts(world: &mut PoolWorld) {
    assert_instruction_error(world.last_error(), "NotEnoughAccountKeys");
}
