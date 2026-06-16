//! Admin steps: protocol config, tree creation, authority rotation, pause.

use cucumber::{then, when};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{create_protocol_config as create_protocol_config_ix, CreateProtocolConfigData},
    state::PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES,
};
use zolana_test_utils::asserts::assert_protocol_config;

use crate::common::{assert_pool_error, tree_account_size};
use crate::ShieldedPoolWorld;

use shielded_pool_program::error::ShieldedPoolError;

// === create protocol config ===

#[when(expr = "the authority creates the protocol config")]
fn create_protocol_config(world: &mut ShieldedPoolWorld) {
    let authority = Keypair::new();
    let config = world
        .rpc()
        .create_protocol_config(&authority)
        .expect("create_protocol_config");
    world.authority = Some(authority);
    world.protocol_config = Some(config);
}

#[then(expr = "the protocol config has the authority and no merge authorities")]
fn assert_config_no_merge(world: &mut ShieldedPoolWorld) {
    let config = world.protocol_config.expect("config created");
    let authority = world.authority().pubkey();
    let rpc = world.rpc_ref();
    assert_protocol_config(rpc, &config, &authority, &[]);
}

#[then(expr = "creating the protocol config again is rejected as invalid")]
fn create_again_rejected(world: &mut ShieldedPoolWorld) {
    world.rpc().svm.expire_blockhash();
    let authority = world.authority().insecure_clone();
    let err = world.rpc().create_protocol_config(&authority).unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidProtocolConfig);
}

#[when(expr = "lamports are donated to the protocol config address")]
fn donate_to_config(world: &mut ShieldedPoolWorld) {
    let config = world.rpc().protocol_config_pda();
    world
        .rpc()
        .airdrop(&config, 1_000_000)
        .expect("donate lamports to config PDA");
    world.prefunded_protocol_config = Some(config);
}

#[when(expr = "the authority creates the protocol config on the pre-funded address")]
fn create_config_prefunded(world: &mut ShieldedPoolWorld) {
    let authority = Keypair::new();
    let created = world
        .rpc()
        .create_protocol_config(&authority)
        .expect("create_protocol_config must survive a pre-funded PDA");
    assert_eq!(
        created,
        world
            .prefunded_protocol_config
            .expect("donated config address")
    );
    world.authority = Some(authority);
    world.protocol_config = Some(created);
}

#[when(expr = "the authority creates the protocol config with one merge authority")]
fn create_config_with_merge(world: &mut ShieldedPoolWorld) {
    let authority = Keypair::new();
    let merge_a = Pubkey::new_unique().to_bytes();
    let config = world
        .rpc()
        .create_protocol_config_with_merge_authorities(&authority, vec![merge_a])
        .expect("create_protocol_config");
    world.authority = Some(authority);
    world.protocol_config = Some(config);
    world.merge_authority = Some(merge_a);
}

#[then(expr = "the protocol config records that merge authority")]
fn assert_config_one_merge(world: &mut ShieldedPoolWorld) {
    let config = world.protocol_config.expect("config created");
    let merge = world.merge_authority.expect("merge authority created");
    let authority = world.authority().pubkey();
    let rpc = world.rpc_ref();
    assert_protocol_config(rpc, &config, &authority, &[merge]);
}

#[when(expr = "the authority rotates to a new authority with a new merge authority")]
fn update_config_with_merge(world: &mut ShieldedPoolWorld) {
    let next = Keypair::new();
    let merge_b = Pubkey::new_unique().to_bytes();
    world
        .rpc()
        .airdrop(&next.pubkey(), 1_000_000_000)
        .expect("fund");
    let authority = world.authority().insecure_clone();
    world
        .rpc()
        .update_protocol_config_with_merge_authorities(&authority, &next.pubkey(), vec![merge_b])
        .expect("update_protocol_config");
    world.authority = Some(next);
    world.merge_authority = Some(merge_b);
}

#[when(expr = "the authority tries to create a protocol config with too many merge authorities")]
fn create_config_too_many_merge(world: &mut ShieldedPoolWorld) {
    let authority = Keypair::new();
    let merge_authorities = vec![[9u8; 32]; PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES + 1];
    let err = world
        .rpc()
        .create_protocol_config_with_merge_authorities(&authority, merge_authorities)
        .unwrap_err();
    world.last_error = Some(err);
}

#[when(expr = "a signer creates a protocol config naming a different authority")]
fn create_config_mismatched_authority(world: &mut ShieldedPoolWorld) {
    let signer = Keypair::new();
    world
        .rpc()
        .airdrop(&signer.pubkey(), 1_000_000_000)
        .expect("fund");
    let named = Keypair::new();
    let ix = create_protocol_config_ix(
        signer.pubkey(),
        CreateProtocolConfigData {
            authority: named.pubkey().to_bytes(),
            merge_authorities: Vec::new(),
        },
    );
    let err = world
        .rpc()
        .create_and_send_default_payer_transaction(&[ix], &[&signer])
        .unwrap_err();
    world.last_error = Some(err);
}

// === tree creation ===

#[when(expr = "a non-authority tries to create a tree")]
fn impostor_creates_tree(world: &mut ShieldedPoolWorld) {
    let impostor = Keypair::new();
    world
        .rpc()
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = world
        .rpc()
        .create_tree(tree_account_size(), &impostor)
        .unwrap_err();
    world.last_error = Some(err);
}

#[when(expr = "the authority tries to create an undersized tree")]
fn create_undersized_tree(world: &mut ShieldedPoolWorld) {
    let authority = world.authority().insecure_clone();
    let err = world.rpc().create_tree(10_000, &authority).unwrap_err();
    world.last_error = Some(err);
}

// === update protocol config (rotate) ===

#[when(expr = "the authority rotates to a new authority")]
fn rotate_authority(world: &mut ShieldedPoolWorld) {
    let next = Keypair::new();
    world
        .rpc()
        .airdrop(&next.pubkey(), 1_000_000_000)
        .expect("fund");
    let authority = world.authority().insecure_clone();
    world
        .rpc()
        .update_protocol_config(&authority, &next.pubkey())
        .expect("rotate");
    world.rotated_authority = Some(next);
}

#[then(expr = "the old authority can no longer update the config")]
fn old_authority_rejected(world: &mut ShieldedPoolWorld) {
    let authority = world.authority().insecure_clone();
    let err = world
        .rpc()
        .update_protocol_config(&authority, &authority.pubkey())
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[then(expr = "the new authority can update the config and create trees")]
fn new_authority_works(world: &mut ShieldedPoolWorld) {
    let next = world
        .rotated_authority
        .as_ref()
        .expect("rotated authority")
        .insecure_clone();
    world
        .rpc()
        .update_protocol_config(&next, &next.pubkey())
        .expect("new authority works");
    world
        .rpc()
        .create_tree(tree_account_size(), &next)
        .expect("create_tree under new authority");
}

#[when(expr = "a non-authority tries to update the config")]
fn impostor_updates_config(world: &mut ShieldedPoolWorld) {
    let impostor = Keypair::new();
    world
        .rpc()
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = world
        .rpc()
        .update_protocol_config(&impostor, &impostor.pubkey())
        .unwrap_err();
    world.last_error = Some(err);
}

// === pause tree ===

#[when(expr = "a non-authority tries to pause the tree")]
fn impostor_pauses_tree(world: &mut ShieldedPoolWorld) {
    let impostor = Keypair::new();
    world
        .rpc()
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let tree = world.tree().insecure_clone();
    let err = world.rpc().pause_tree(&impostor, &tree, true).unwrap_err();
    world.last_error = Some(err);
}

#[when(expr = "someone tries to pause a tree without a protocol config")]
fn pause_without_config(world: &mut ShieldedPoolWorld) {
    let impostor = Keypair::new();
    world
        .rpc()
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let tree = Keypair::new();
    let err = world.rpc().pause_tree(&impostor, &tree, true).unwrap_err();
    world.last_error = Some(err);
}
