use custom_ring_interface::{tag, CustomRingProof, CustomRingTransactIxData, AUDITOR_MESSAGE_LEN};
use custom_ring_program::CustomRingError;
use solana_program_error::ProgramError;
use zolana_interface::N_PUBLIC_SLOTS;
use zolana_interface::{
    event::RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
    instruction::{
        instruction_data::transact::{
            CircuitId, OwnerTag, TransactIxData, TransactOutput, TransactProof,
        },
        MessageData,
    },
};

use solana_pubkey::Pubkey;

use crate::common::{
    account, audit_only_config_account, audit_transact_fixture, auditor_pubkey, authority,
    entries_tree, entries_tree_account, initialized_config_account,
    initialized_policy_config_account, setup_mollusk, transact_fixture, Fixture,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

fn confidential_output() -> TransactOutput {
    let mut key = [0u8; 33];
    key[0] = 0x02;
    let mut body = vec![RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG];
    body.extend_from_slice(&key);
    body.extend_from_slice(&[9u8; 32]);
    let mut data = vec![1u8];
    data.extend_from_slice(&(body.len() as u32).to_le_bytes());
    data.extend_from_slice(&body);
    TransactOutput {
        utxo_hash: [1u8; 32],
        owner_tag: OwnerTag::Inline([2u8; 32]),
        data: Some(data),
    }
}

fn transact_data() -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [3u8; 32],
        circuit: CircuitId::RingEddsa(1, 1, N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        proof: TransactProof::zeroed(),
        inputs: Vec::new(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![confidential_output()],
        messages: vec![MessageData {
            view_tag: auditor_pubkey(2)[1..33].try_into().expect("view tag"),
            data: {
                let mut data = vec![0u8; AUDITOR_MESSAGE_LEN];
                data[0] = 0x02;
                data
            },
        }],
    }
}

fn transact_body(state_root_index: u16, nullifier_root_index: u16) -> Vec<u8> {
    let mut data = vec![tag::TRANSACT];
    data.extend_from_slice(
        &wincode::serialize(&CustomRingTransactIxData {
            proof: CustomRingProof {
                proof_a: [0; 32],
                proof_b: [0; 64],
                proof_c: [0; 32],
                commitment: [0xFF; 32],
                commitment_pok: [0xFF; 32],
            },
            state_root_index,
            nullifier_root_index,
            transact: transact_data(),
        })
        .expect("serialize policy transact body"),
    );
    data
}

fn policy_fixture(state_root_index: u16, nullifier_root_index: u16) -> Fixture {
    transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        transact_body(state_root_index, nullifier_root_index),
    )
}

/// An audit-only ring dispatches to the audit verifying key with no policy
/// accounts present.
#[test]
fn an_audit_only_ring_reaches_the_audit_proof() {
    let (mollusk, _) = setup_mollusk();
    let fixture = audit_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(2)),
        transact_body(0, 0),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// A policy ring cannot spend through the audit layout, the tier is read from
/// the config and the absent policy config is refused.
#[test]
fn a_policy_ring_cannot_spend_through_the_audit_layout() {
    let (mollusk, _) = setup_mollusk();
    let fixture = audit_transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        transact_body(0, 0),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::PolicyConfigNotInitialized));
}

/// The stored hash is what a rebuilt table must reproduce.
#[test]
fn a_drifted_policy_hash_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    let mut config = initialized_policy_config_account();
    config.data[1] ^= 0xFF;
    fixture.set_account("policy_config", config);
    fixture.expect_err(&mollusk, custom(CustomRingError::PolicyHashMismatch));
}

/// The roots come from a real tree account at the configured address, a stub
/// there never yields one.
#[test]
fn an_entries_tree_that_is_not_a_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    fixture.set_account("entries_tree", entries_tree_account());
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidEntriesTree));
}

/// The roots load from the dedicated entries account, not the SPP money tree.
#[test]
fn a_mismatched_entries_tree_address_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    fixture.substitute("entries_tree", Pubkey::new_from_array([78; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidEntriesTree));
}

/// The transact path loads the policy config unconditionally, an uninitialized
/// one at the canonical address is refused before any proof work.
#[test]
fn an_uninitialized_policy_config_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    fixture.set_account("policy_config", account(0));
    fixture.expect_err(&mollusk, custom(CustomRingError::PolicyConfigNotInitialized));
}

/// A nullifier root the entries tree has not written is stale and the transact
/// path refuses it.
#[test]
fn a_stale_nullifier_root_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = policy_fixture(0, 5);
    fixture.expect_err(&mollusk, custom(CustomRingError::StalePolicyRoot));
}

/// The default fixture's money tree already differs from the entries tree.
#[test]
fn a_money_tree_apart_from_the_entries_tree_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let fixture = policy_fixture(0, 0);
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// An existing ring passes one account as both the entries tree and the SPP
/// input tree.
#[test]
fn an_entries_tree_aliasing_the_input_tree_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    fixture.substitute("input_tree", entries_tree());
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn the_entries_tree_address_is_the_configured_one() {
    assert_eq!(
        initialized_policy_config_account().data[33..65],
        entries_tree().to_bytes()
    );
}
