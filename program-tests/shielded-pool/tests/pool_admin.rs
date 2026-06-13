//! Admin coverage for protocol config, tree creation, and pause authority.

mod common;

use common::{assert_pool_error, rig, rig_with_tree, TREE_ACCOUNT_SIZE};
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
    let Some(mut rig) = rig() else {
        return;
    };
    let authority = Keypair::new();

    let config = rig
        .create_protocol_config(&authority)
        .expect("create_protocol_config");
    let config_data = rig.account_data(&config).expect("config PDA exists");
    assert_eq!(config_data.len(), PROTOCOL_CONFIG_ACCOUNT_LEN);
    assert_eq!(config_authority(&config_data), authority.pubkey().as_ref());
    assert_eq!(merge_authority_count(&config_data), 0);

    rig.svm.expire_blockhash();
    let again = rig.create_protocol_config(&authority).unwrap_err();
    assert_pool_error(again, ShieldedPoolError::InvalidProtocolConfig);
}

#[test]
fn protocol_config_persists_merge_authorities() {
    let Some(mut rig) = rig() else {
        return;
    };
    let authority = Keypair::new();
    let merge_a = Pubkey::new_unique().to_bytes();
    let merge_b = Pubkey::new_unique().to_bytes();

    let config = rig
        .create_protocol_config_with_merge_authorities(&authority, vec![merge_a])
        .expect("create_protocol_config");
    let config_data = rig.account_data(&config).expect("config PDA exists");
    assert_eq!(config_authority(&config_data), authority.pubkey().as_ref());
    assert_eq!(merge_authority_count(&config_data), 1);
    assert_eq!(merge_authority(&config_data, 0), &merge_a);

    let next = Keypair::new();
    rig.airdrop(&next.pubkey(), 1_000_000_000).expect("fund");
    rig.update_protocol_config_with_merge_authorities(&authority, &next.pubkey(), vec![merge_b])
        .expect("update_protocol_config");
    let config_data = rig.account_data(&config).expect("config PDA exists");
    assert_eq!(config_authority(&config_data), next.pubkey().as_ref());
    assert_eq!(merge_authority_count(&config_data), 1);
    assert_eq!(merge_authority(&config_data, 0), &merge_b);
}

#[test]
fn protocol_config_rejects_too_many_merge_authorities() {
    let Some(mut rig) = rig() else {
        return;
    };
    let authority = Keypair::new();
    let merge_authorities = vec![[9u8; 32]; PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES + 1];

    let err = rig
        .create_protocol_config_with_merge_authorities(&authority, merge_authorities)
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidProtocolConfig);
}

#[test]
fn create_protocol_config_rejects_mismatched_authority() {
    let Some(mut rig) = rig() else {
        return;
    };
    let signer = Keypair::new();
    rig.airdrop(&signer.pubkey(), 1_000_000_000).expect("fund");
    let named = Keypair::new();
    let data = encode_instruction(
        tag::CREATE_PROTOCOL_CONFIG,
        &CreateProtocolConfigData {
            authority: named.pubkey().to_bytes(),
            merge_authorities: Vec::new(),
        },
    );
    let ix = Instruction {
        program_id: rig.program_id,
        accounts: vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new(rig.protocol_config_pda(), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data,
    };
    let payer = rig.payer.insecure_clone();
    let payer_pk = payer.pubkey();
    let blockhash = rig.svm.latest_blockhash();
    let msg = solana_message::Message::new(&[ix], Some(&payer_pk));
    let tx = solana_transaction::Transaction::new(&[&payer, &signer], msg, blockhash);
    let err = rig
        .svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| zolana_program_test::RigError::Litesvm(format!("{e:?}")))
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn create_tree_rejects_non_authority() {
    let Some(mut rig) = rig() else {
        return;
    };
    let authority = Keypair::new();
    rig.create_protocol_config(&authority)
        .expect("create_protocol_config");

    let impostor = Keypair::new();
    rig.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = rig.create_tree(TREE_ACCOUNT_SIZE, &impostor).unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn update_protocol_config_rotates_authority() {
    let Some((mut rig, authority, _tree)) = rig_with_tree() else {
        return;
    };
    let next = Keypair::new();
    rig.airdrop(&next.pubkey(), 1_000_000_000).expect("fund");

    rig.update_protocol_config(&authority, &next.pubkey())
        .expect("rotate");
    let err = rig
        .update_protocol_config(&authority, &authority.pubkey())
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
    rig.update_protocol_config(&next, &next.pubkey())
        .expect("new authority works");

    // The new authority can also create trees.
    rig.create_tree(TREE_ACCOUNT_SIZE, &next)
        .expect("create_tree under new authority");
}

#[test]
fn update_protocol_config_rejects_non_authority() {
    let Some((mut rig, _authority, _tree)) = rig_with_tree() else {
        return;
    };
    let impostor = Keypair::new();
    rig.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = rig
        .update_protocol_config(&impostor, &impostor.pubkey())
        .unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn pause_tree_rejects_non_authority() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    let impostor = Keypair::new();
    rig.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = rig.pause_tree(&impostor, &tree, true).unwrap_err();
    assert_pool_error(err, ShieldedPoolError::UnauthorizedCaller);
}

#[test]
fn pause_tree_requires_existing_config() {
    let Some(mut rig) = rig() else {
        return;
    };
    // Without a protocol config, pause cannot resolve the authority oracle.
    let impostor = Keypair::new();
    rig.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let tree = Keypair::new();
    let err = rig.pause_tree(&impostor, &tree, true).unwrap_err();
    assert_pool_error(err, ShieldedPoolError::InvalidProtocolConfig);
}

#[test]
fn create_tree_uses_tree_account_size_helper() {
    // PoolTestRig and the program agree on the account layout: an undersized
    // account must be rejected by init.
    let Some(mut rig) = rig() else {
        return;
    };
    let authority = Keypair::new();
    rig.create_protocol_config(&authority)
        .expect("create_protocol_config");
    let err = rig.create_tree(10_000, &authority).unwrap_err();
    let msg = format!("{err}");
    assert!(!msg.is_empty(), "undersized tree account must fail: {msg}");
}
