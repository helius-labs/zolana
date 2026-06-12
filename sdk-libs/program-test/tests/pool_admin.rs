//! Admin instruction matrix: create_protocol_config, update_protocol_config,
//! pause_tree, create_tree (spec instruction table tags 5-8).
//!
//! Cases:
//!  1. create_protocol_config succeeds at the canonical PDA.
//!  2. create_protocol_config with a non-matching authority signer — reject.
//!  3. create_protocol_config twice — reject (PDA exists).
//!  4. create_tree by the config authority succeeds (in common setup).
//!  5. create_tree by a non-authority signer — reject.
//!  6. update_protocol_config rotates the authority; the old authority is
//!     rejected afterwards and the new one works.
//!  7. update_protocol_config by a non-authority — reject.
//!  8. pause_tree by a non-authority — reject.
//!  9. pause/unpause round-trip gates deposits (proofless_shield.rs case 14).

mod common;

use common::{assert_custom, rig, rig_with_tree, TREE_ACCOUNT_SIZE};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::instruction::{encode_instruction, tag, CreateProtocolConfigData};

// Stable on-chain error codes (programs/shielded-pool/src/error.rs).
const UNAUTHORIZED_CALLER: u32 = 5;
const INVALID_PROTOCOL_CONFIG: u32 = 16;

#[test]
fn create_protocol_config_succeeds_once() {
    let Some(mut rig) = rig() else {
        return;
    };
    let authority = Keypair::new();

    // 1: create at the canonical PDA.
    let config = rig
        .create_protocol_config(&authority)
        .expect("create_protocol_config");
    assert!(rig.account_data(&config).is_some(), "config PDA exists");

    // 3: a second create must fail — the PDA already exists.
    let again = rig.create_protocol_config(&authority).unwrap_err();
    let msg = format!("{again}");
    assert!(
        !msg.is_empty(),
        "second create must fail (PDA exists): {msg}"
    );
}

#[test]
fn create_protocol_config_rejects_mismatched_authority() {
    let Some(mut rig) = rig() else {
        return;
    };
    // 2: data names one authority, a different key signs.
    let signer = Keypair::new();
    rig.airdrop(&signer.pubkey(), 1_000_000_000).expect("fund");
    let named = Keypair::new();
    let data = encode_instruction(
        tag::CREATE_PROTOCOL_CONFIG,
        &CreateProtocolConfigData {
            authority: named.pubkey().to_bytes(),
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
        .map_err(|e| light_program_test::RigError::Litesvm(format!("{e:?}")))
        .unwrap_err();
    assert_custom(err, UNAUTHORIZED_CALLER);
}

#[test]
fn create_tree_rejects_non_authority() {
    let Some(mut rig) = rig() else {
        return;
    };
    let authority = Keypair::new();
    rig.create_protocol_config(&authority)
        .expect("create_protocol_config");

    // 5: an impostor signs create_tree.
    let impostor = Keypair::new();
    rig.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = rig.create_tree(TREE_ACCOUNT_SIZE, &impostor).unwrap_err();
    assert_custom(err, UNAUTHORIZED_CALLER);
}

#[test]
fn update_protocol_config_rotates_authority() {
    let Some((mut rig, authority, _tree)) = rig_with_tree() else {
        return;
    };
    let next = Keypair::new();
    rig.airdrop(&next.pubkey(), 1_000_000_000).expect("fund");

    // 6: rotate, then the old authority must be rejected and the new accepted.
    rig.update_protocol_config(&authority, &next.pubkey())
        .expect("rotate");
    let err = rig
        .update_protocol_config(&authority, &authority.pubkey())
        .unwrap_err();
    assert_custom(err, UNAUTHORIZED_CALLER);
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
    // 7: a random signer cannot rotate.
    let impostor = Keypair::new();
    rig.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = rig
        .update_protocol_config(&impostor, &impostor.pubkey())
        .unwrap_err();
    assert_custom(err, UNAUTHORIZED_CALLER);
}

#[test]
fn pause_tree_rejects_non_authority() {
    let Some((mut rig, _authority, tree)) = rig_with_tree() else {
        return;
    };
    // 8: a random signer cannot pause.
    let impostor = Keypair::new();
    rig.airdrop(&impostor.pubkey(), 1_000_000_000)
        .expect("fund");
    let err = rig.pause_tree(&impostor, &tree, true).unwrap_err();
    assert_custom(err, UNAUTHORIZED_CALLER);
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
    assert_custom(err, INVALID_PROTOCOL_CONFIG);
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
