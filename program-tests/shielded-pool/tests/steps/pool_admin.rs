//! Admin steps: protocol config, tree creation, authority rotation, pause.
//! Faithful port of `tests/pool_admin.rs`.

use cucumber::{then, when};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{encode_instruction, tag, CreateProtocolConfigData},
    state::PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES,
};
use zolana_test_utils::asserts::assert_protocol_config;

use crate::common::{assert_pool_error, tree_account_size};
use crate::PoolWorld;

use shielded_pool_program::error::ShieldedPoolError;

// === create protocol config ===

#[when(expr = "the authority creates the protocol config")]
fn create_protocol_config(world: &mut PoolWorld) {
    let authority = Keypair::new();
    let config = world
        .rig()
        .create_protocol_config(&authority)
        .expect("create_protocol_config");
    world.authority = Some(authority);
    world.registry = Some(config);
}

#[then(expr = "the protocol config has the authority and no merge authorities")]
fn assert_config_no_merge(world: &mut PoolWorld) {
    let config = world.registry.expect("config created");
    let authority = world.authority().pubkey();
    let rig = world.rig.as_ref().expect("pool booted");
    assert_protocol_config(rig, &config, &authority, &[]);
}

#[then(expr = "creating the protocol config again is rejected as invalid")]
fn create_again_rejected(world: &mut PoolWorld) {
    world.rig().svm.expire_blockhash();
    let authority = world.authority().insecure_clone();
    let err = world.rig().create_protocol_config(&authority).unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidProtocolConfig);
}

#[when(expr = "lamports are donated to the protocol config address")]
fn donate_to_config(world: &mut PoolWorld) {
    let config = world.rig().protocol_config_pda();
    world
        .rig()
        .airdrop(&config, 1_000_000)
        .expect("donate lamports to config PDA");
    world.vault = Some(config);
}

#[when(expr = "the authority creates the protocol config on the pre-funded address")]
fn create_config_prefunded(world: &mut PoolWorld) {
    let authority = Keypair::new();
    let created = world
        .rig()
        .create_protocol_config(&authority)
        .expect("create_protocol_config must survive a pre-funded PDA");
    assert_eq!(created, world.vault.expect("donated config address"));
    world.authority = Some(authority);
    world.registry = Some(created);
}

#[when(expr = "the authority creates the protocol config with one merge authority")]
fn create_config_with_merge(world: &mut PoolWorld) {
    let authority = Keypair::new();
    let merge_a = Pubkey::new_unique().to_bytes();
    let config = world
        .rig()
        .create_protocol_config_with_merge_authorities(&authority, vec![merge_a])
        .expect("create_protocol_config");
    world.authority = Some(authority);
    world.registry = Some(config);
    // Stash the first merge authority bytes for the assertion.
    world.root_before = Some(merge_a);
}

#[then(expr = "the protocol config records that merge authority")]
fn assert_config_one_merge(world: &mut PoolWorld) {
    let config = world.registry.expect("config created");
    let merge = world.root_before.expect("merge authority stashed");
    let authority = world.authority().pubkey();
    let rig = world.rig.as_ref().expect("pool booted");
    assert_protocol_config(rig, &config, &authority, &[merge]);
}

#[when(expr = "the authority rotates to a new authority with a new merge authority")]
fn update_config_with_merge(world: &mut PoolWorld) {
    let next = Keypair::new();
    let merge_b = Pubkey::new_unique().to_bytes();
    world
        .rig()
        .airdrop(&next.pubkey(), 1_000_000_000)
        .expect("fund");
    let authority = world.authority().insecure_clone();
    world
        .rig()
        .update_protocol_config_with_merge_authorities(&authority, &next.pubkey(), vec![merge_b])
        .expect("update_protocol_config");
    world.authority = Some(next);
    world.root_before = Some(merge_b);
}

#[when(expr = "the authority tries to create a protocol config with too many merge authorities")]
fn create_config_too_many_merge(world: &mut PoolWorld) {
    let authority = Keypair::new();
    let merge_authorities = vec![[9u8; 32]; PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES + 1];
    let err = world
        .rig()
        .create_protocol_config_with_merge_authorities(&authority, merge_authorities)
        .unwrap_err();
    world.last_error = Some(err);
}

#[when(expr = "a signer creates a protocol config naming a different authority")]
fn create_config_mismatched_authority(world: &mut PoolWorld) {
    let signer = Keypair::new();
    world
        .rig()
        .airdrop(&signer.pubkey(), 1_000_000_000)
        .expect("fund");
    let named = Keypair::new();
    let program_id = world.rig().program_id;
    let config_pda = world.rig().protocol_config_pda();
    let data = encode_instruction(
        tag::CREATE_PROTOCOL_CONFIG,
        &CreateProtocolConfigData {
            authority: named.pubkey().to_bytes(),
            merge_authorities: Vec::new(),
        },
    );
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new(config_pda, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data,
    };
    let err = world
        .rig()
        .create_and_send_default_payer_transaction(&[ix], &[&signer])
        .unwrap_err();
    world.last_error = Some(err);
}

// === tree creation ===

#[when(expr = "a non-authority tries to create a tree")]
fn impostor_creates_tree(world: &mut PoolWorld) {
    let impostor = Keypair::new();
    world
        .rig()
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = world
        .rig()
        .create_tree(tree_account_size(), &impostor)
        .unwrap_err();
    world.last_error = Some(err);
}

#[when(expr = "the authority tries to create an undersized tree")]
fn create_undersized_tree(world: &mut PoolWorld) {
    let authority = world.authority().insecure_clone();
    let err = world.rig().create_tree(10_000, &authority).unwrap_err();
    world.last_error = Some(err);
}

// === update protocol config (rotate) ===

#[when(expr = "the authority rotates to a new authority")]
fn rotate_authority(world: &mut PoolWorld) {
    let next = Keypair::new();
    world
        .rig()
        .airdrop(&next.pubkey(), 1_000_000_000)
        .expect("fund");
    let authority = world.authority().insecure_clone();
    world
        .rig()
        .update_protocol_config(&authority, &next.pubkey())
        .expect("rotate");
    world.zone_authority = Some(next);
}

#[then(expr = "the old authority can no longer update the config")]
fn old_authority_rejected(world: &mut PoolWorld) {
    let authority = world.authority().insecure_clone();
    let err = world
        .rig()
        .update_protocol_config(&authority, &authority.pubkey())
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[then(expr = "the new authority can update the config and create trees")]
fn new_authority_works(world: &mut PoolWorld) {
    let next = world
        .zone_authority
        .as_ref()
        .expect("rotated authority")
        .insecure_clone();
    world
        .rig()
        .update_protocol_config(&next, &next.pubkey())
        .expect("new authority works");
    world
        .rig()
        .create_tree(tree_account_size(), &next)
        .expect("create_tree under new authority");
}

#[when(expr = "a non-authority tries to update the config")]
fn impostor_updates_config(world: &mut PoolWorld) {
    let impostor = Keypair::new();
    world
        .rig()
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = world
        .rig()
        .update_protocol_config(&impostor, &impostor.pubkey())
        .unwrap_err();
    world.last_error = Some(err);
}

// === pause tree ===

#[when(expr = "a non-authority tries to pause the tree")]
fn impostor_pauses_tree(world: &mut PoolWorld) {
    let impostor = Keypair::new();
    world
        .rig()
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let tree = world.tree().insecure_clone();
    let err = world.rig().pause_tree(&impostor, &tree, true).unwrap_err();
    world.last_error = Some(err);
}

#[when(expr = "someone tries to pause a tree without a protocol config")]
fn pause_without_config(world: &mut PoolWorld) {
    let impostor = Keypair::new();
    world
        .rig()
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let tree = Keypair::new();
    let err = world.rig().pause_tree(&impostor, &tree, true).unwrap_err();
    world.last_error = Some(err);
}
