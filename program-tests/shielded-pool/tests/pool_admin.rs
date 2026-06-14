//! Admin coverage for protocol config, tree creation, and pause authority.

mod common;

use common::{assert_pool_error, program_test, program_test_with_tree, tree_account_size};
use shielded_pool_program::error::ShieldedPoolError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{encode_instruction, tag, CreateProtocolConfigData},
    state::{
        CONFIG_AUTHORITY_END, CONFIG_AUTHORITY_OFFSET, PROTOCOL_CONFIG_ACCOUNT_LEN,
        PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES, PROTOCOL_CONFIG_MERGE_AUTHORITIES_OFFSET,
        PROTOCOL_CONFIG_MERGE_AUTHORITY_COUNT_OFFSET,
    },
};

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

fn config_authority(data: &[u8]) -> &[u8] {
    &data[CONFIG_AUTHORITY_OFFSET..CONFIG_AUTHORITY_END]
}

fn merge_authority_count(data: &[u8]) -> u64 {
    read_u64(data, PROTOCOL_CONFIG_MERGE_AUTHORITY_COUNT_OFFSET)
}

fn merge_authority(data: &[u8], index: usize) -> &[u8] {
    let offset = PROTOCOL_CONFIG_MERGE_AUTHORITIES_OFFSET + index * 32;
    &data[offset..offset + 32]
}

#[test]
fn create_protocol_config_succeeds_once() {
    let Some(mut program_test) = program_test() else {
        return;
    };
    let authority = Keypair::new();

    let config = program_test
        .create_protocol_config(&authority)
        .expect("create_protocol_config");
    let config_data = program_test
        .account_data(&config)
        .expect("config PDA exists");
    assert_eq!(config_data.len(), PROTOCOL_CONFIG_ACCOUNT_LEN);
    assert_eq!(config_authority(&config_data), authority.pubkey().as_ref());
    assert_eq!(merge_authority_count(&config_data), 0);

    program_test.svm.expire_blockhash();
    let again = program_test.create_protocol_config(&authority).unwrap_err();
    assert_pool_error(again, ShieldedPoolError::InvalidProtocolConfig);
}

#[test]
fn create_protocol_config_survives_donated_lamports() {
    // The config PDA address is deterministic, so anyone can transfer lamports
    // to it before the authority creates it. A raw system CreateAccount fails on
    // a target that already holds lamports, which would permanently DoS pool
    // bring-up; the minimum-balance helper must take the cold path (top-up +
    // allocate + assign) and still create the account. This test fails against
    // a raw-CreateAccount implementation and passes with the cold-path helper.
    let Some(mut program_test) = program_test() else {
        return;
    };
    let authority = Keypair::new();
    let config = program_test.protocol_config_pda();

    // Attacker griefs the not-yet-created PDA with a lamport donation.
    program_test
        .airdrop(&config, 1_000_000)
        .expect("donate lamports to config PDA");

    // Creation must still succeed despite the pre-funded balance.
    let created = program_test
        .create_protocol_config(&authority)
        .expect("create_protocol_config must survive a pre-funded PDA");
    assert_eq!(created, config);

    let config_data = program_test
        .account_data(&config)
        .expect("config PDA exists");
    assert_eq!(config_data.len(), PROTOCOL_CONFIG_ACCOUNT_LEN);
    assert_eq!(config_authority(&config_data), authority.pubkey().as_ref());
}

#[test]
fn protocol_config_persists_merge_authorities() {
    let Some(mut program_test) = program_test() else {
        return;
    };
    let authority = Keypair::new();
    let merge_a = Pubkey::new_unique().to_bytes();
    let merge_b = Pubkey::new_unique().to_bytes();

    let config = program_test
        .create_protocol_config_with_merge_authorities(&authority, vec![merge_a])
        .expect("create_protocol_config");
    let config_data = program_test
        .account_data(&config)
        .expect("config PDA exists");
    assert_eq!(config_authority(&config_data), authority.pubkey().as_ref());
    assert_eq!(merge_authority_count(&config_data), 1);
    assert_eq!(merge_authority(&config_data, 0), &merge_a);

    let next = Keypair::new();
    program_test
        .airdrop(&next.pubkey(), 1_000_000_000)
        .expect("fund");
    program_test
        .update_protocol_config_with_merge_authorities(&authority, &next.pubkey(), vec![merge_b])
        .expect("update_protocol_config");
    let config_data = program_test
        .account_data(&config)
        .expect("config PDA exists");
    assert_eq!(config_authority(&config_data), next.pubkey().as_ref());
    assert_eq!(merge_authority_count(&config_data), 1);
    assert_eq!(merge_authority(&config_data, 0), &merge_b);
}

#[test]
fn protocol_config_rejects_too_many_merge_authorities() {
    let Some(mut program_test) = program_test() else {
        return;
    };
    let authority = Keypair::new();
    let merge_authorities = vec![[9u8; 32]; PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES + 1];

    let err = program_test
        .create_protocol_config_with_merge_authorities(&authority, merge_authorities)
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidProtocolConfig);
}

#[test]
fn create_protocol_config_rejects_mismatched_authority() {
    let Some(mut program_test) = program_test() else {
        return;
    };
    let signer = Keypair::new();
    program_test
        .airdrop(&signer.pubkey(), 1_000_000_000)
        .expect("fund");
    let named = Keypair::new();
    let data = encode_instruction(
        tag::CREATE_PROTOCOL_CONFIG,
        &CreateProtocolConfigData {
            authority: named.pubkey().to_bytes(),
            merge_authorities: Vec::new(),
        },
    );
    let ix = Instruction {
        program_id: program_test.program_id,
        accounts: vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new(program_test.protocol_config_pda(), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data,
    };
    let err = program_test
        .create_and_send_default_payer_transaction(&[ix], &[&signer])
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn create_tree_rejects_non_authority() {
    let Some(mut program_test) = program_test() else {
        return;
    };
    let authority = Keypair::new();
    program_test
        .create_protocol_config(&authority)
        .expect("create_protocol_config");

    let impostor = Keypair::new();
    program_test
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = program_test
        .create_tree(tree_account_size(), &impostor)
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn update_protocol_config_rotates_authority() {
    let Some((mut program_test, authority, _tree)) = program_test_with_tree() else {
        return;
    };
    let next = Keypair::new();
    program_test
        .airdrop(&next.pubkey(), 1_000_000_000)
        .expect("fund");

    program_test
        .update_protocol_config(&authority, &next.pubkey())
        .expect("rotate");
    let err = program_test
        .update_protocol_config(&authority, &authority.pubkey())
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
    program_test
        .update_protocol_config(&next, &next.pubkey())
        .expect("new authority works");

    // The new authority can also create trees.
    program_test
        .create_tree(tree_account_size(), &next)
        .expect("create_tree under new authority");
}

#[test]
fn update_protocol_config_rejects_non_authority() {
    let Some((mut program_test, _authority, _tree)) = program_test_with_tree() else {
        return;
    };
    let impostor = Keypair::new();
    program_test
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = program_test
        .update_protocol_config(&impostor, &impostor.pubkey())
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn pause_tree_rejects_non_authority() {
    let Some((mut program_test, _authority, tree)) = program_test_with_tree() else {
        return;
    };
    let impostor = Keypair::new();
    program_test
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = program_test.pause_tree(&impostor, &tree, true).unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn pause_tree_requires_existing_config() {
    let Some(mut program_test) = program_test() else {
        return;
    };
    // Without a protocol config, pause cannot resolve the authority oracle.
    let impostor = Keypair::new();
    program_test
        .airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let tree = Keypair::new();
    let err = program_test.pause_tree(&impostor, &tree, true).unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidProtocolConfig);
}

#[test]
fn create_tree_rejects_undersized_account() {
    let Some(mut program_test) = program_test() else {
        return;
    };
    let authority = Keypair::new();
    program_test
        .create_protocol_config(&authority)
        .expect("create_protocol_config");
    let err = program_test.create_tree(10_000, &authority).unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidTreeAccounts);
}
