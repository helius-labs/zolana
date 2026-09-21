use custom_ring_interface::{
    tag, CustomRingProof, CustomRingTransactIxData, PlainGroth16Proof, PolicyConfig,
    AUDITOR_MESSAGE_LEN,
};
use custom_ring_program::{CustomRingError, NULLIFIER_ROOT_WINDOW};
use pinocchio::cpi::MAX_CPI_ACCOUNTS;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use zolana_interface::{
    event::RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
    instruction::{
        instruction_data::transact::{
            CircuitId, OwnerTag, TransactIxData, TransactOutput, TransactProof, TreeContext,
        },
        MessageData,
    },
};
use zolana_interface::{pda, N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID};

use solana_pubkey::Pubkey;
use zolana_interface::state::NULLIFIER_TREE_ROOT_HISTORY_CAPACITY;

use crate::common::{
    account, audit_only_config_account, audit_transact_fixture, auditor_pubkey, authority,
    entries_tree, entries_tree_account, initialized_config_account,
    initialized_entries_tree_account, initialized_entries_tree_account_with_roots,
    initialized_entries_tree_account_with_state_roots, initialized_policy_config_account,
    nullifier_root_cursor, paused_entries_tree_account, setup_mollusk, transact_fixture,
    utxo_root_cursor, Fixture, Slot,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

pub(crate) fn confidential_output() -> TransactOutput {
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

pub(crate) fn transact_data() -> TransactIxData {
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
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }],
    }
}

fn transact_body(state_root_index: u16, nullifier_root_index: u16) -> Vec<u8> {
    body(state_root_index, nullifier_root_index, 0, transact_data())
}

pub(crate) fn body(
    state_root_index: u16,
    nullifier_root_index: u16,
    approval_required: u8,
    transact: TransactIxData,
) -> Vec<u8> {
    body_with_targets(
        state_root_index,
        nullifier_root_index,
        approval_required,
        [[0; 32]; zolana_ring_policy::ANSWER_SLOTS],
        transact,
    )
}

fn body_with_targets(
    state_root_index: u16,
    nullifier_root_index: u16,
    approval_required: u8,
    revocation_targets: [[u8; 32]; zolana_ring_policy::ANSWER_SLOTS],
    transact: TransactIxData,
) -> Vec<u8> {
    let mut data = vec![tag::TRANSACT];
    data.extend_from_slice(
        &wincode::serialize(&CustomRingTransactIxData {
            proof: CustomRingProof {
                groth16: PlainGroth16Proof {
                    proof_a: [0; 32],
                    proof_b: [0; 64],
                    proof_c: [0; 32],
                },
                commitment: [0xFF; 32],
                commitment_pok: [0xFF; 32],
            },
            state_root_index,
            nullifier_root_index,
            approval_required,
            head_transition: None,
            revocation_targets,
            transact,
        })
        .expect("serialize policy transact body"),
    );
    data
}

fn revocation_fixture(target_account: Pubkey, target_state: solana_account::Account) -> Fixture {
    let mut target = [0u8; 32];
    target[31] = 7;
    let mut targets = [[0u8; 32]; zolana_ring_policy::ANSWER_SLOTS];
    targets[0] = target;
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        body_with_targets(0, 0, 0, targets, transact_data()),
    );
    fixture.insert_windows(vec![Slot {
        label: "revocation_target",
        meta: AccountMeta::new_readonly(target_account, false),
        account: target_state,
    }]);
    fixture
}

#[test]
fn an_unused_canonical_revocation_target_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut target = [0u8; 32];
    target[31] = 7;
    let address = pda::nullifier_pda(&entries_tree(), &target).0;
    revocation_fixture(address, account(0))
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_substituted_revocation_target_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    revocation_fixture(Pubkey::new_from_array([91; 32]), account(0))
        .expect_err(&mollusk, custom(CustomRingError::InvalidRevocationTarget));
}

#[test]
fn a_queued_revocation_target_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut target = [0u8; 32];
    target[31] = 7;
    let address = pda::nullifier_pda(&entries_tree(), &target).0;
    let mut queued = account(1_000_000);
    queued.owner = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    queued.data = vec![1];
    revocation_fixture(address, queued)
        .expect_err(&mollusk, custom(CustomRingError::PolicyFactRevoked));
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
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::PolicyConfigNotInitialized),
    );
}

#[test]
fn a_drifted_policy_hash_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    let mut config = initialized_policy_config_account();
    config.data[32] ^= 0x01;
    fixture.set_account("policy_config", config);
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
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
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::PolicyConfigNotInitialized),
    );
}

/// A nullifier root the entries tree has not written is stale and the transact
/// path refuses it.
#[test]
fn a_stale_nullifier_root_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = policy_fixture(0, 5);
    fixture.expect_err(&mollusk, custom(CustomRingError::StalePolicyRoot));
}

/// The oldest admitted root is `NULLIFIER_ROOT_WINDOW` rotations behind the cursor.
#[test]
fn a_nullifier_root_at_the_window_edge_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let tree = initialized_entries_tree_account_with_roots(NULLIFIER_ROOT_WINDOW as u16 + 1);
    let edge = nullifier_root_cursor(&tree) - NULLIFIER_ROOT_WINDOW as u16;
    let mut fixture = policy_fixture(0, edge);
    fixture.set_account("entries_tree", tree);
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_nullifier_root_one_rotation_past_the_window_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let tree = initialized_entries_tree_account_with_roots(NULLIFIER_ROOT_WINDOW as u16 + 1);
    let past = nullifier_root_cursor(&tree) - NULLIFIER_ROOT_WINDOW as u16 - 1;
    let mut fixture = policy_fixture(0, past);
    fixture.set_account("entries_tree", tree);
    fixture.expect_err(&mollusk, custom(CustomRingError::StalePolicyRoot));
}

/// The history wraps, a slot inside the window that no rotation has written
/// holds zero and is refused.
#[test]
fn an_unwritten_slot_inside_the_window_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let last = u16::try_from(NULLIFIER_TREE_ROOT_HISTORY_CAPACITY - 1).unwrap();
    let fixture = policy_fixture(0, last);
    fixture.expect_err(&mollusk, custom(CustomRingError::StalePolicyRoot));
}

/// A paused entries tree yields no root, the same fixture reaches the proof
/// once the tree is live again.
#[test]
fn a_paused_entries_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    fixture.set_account("entries_tree", paused_entries_tree_account());
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidEntriesTree));
    fixture.set_account("entries_tree", initialized_entries_tree_account());
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
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

/// State roots use history bounds without the nullifier freshness window.
#[test]
fn a_state_root_index_past_the_history_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = policy_fixture(u16::MAX, 0);
    fixture.expect_err(&mollusk, custom(CustomRingError::StalePolicyRoot));
}

#[test]
fn an_old_live_state_root_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let tree = initialized_entries_tree_account_with_state_roots(3);
    let oldest = utxo_root_cursor(&tree) - 3;
    let mut fixture = policy_fixture(oldest, 0);
    fixture.set_account("entries_tree", tree);
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// The stored id enters the statement, not the live tree's.
#[test]
fn a_drifted_entries_tree_id_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    let mut config = initialized_policy_config_account();
    config.data[core::mem::offset_of!(PolicyConfig, entries_tree_id)] ^= 0x01;
    fixture.set_account("policy_config", config);
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// `ring_auth` and the list size are checked at the CPI, after the proof.
#[test]
fn a_forwarded_list_without_ring_auth_still_fails_at_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    fixture.substitute("ring_config", Pubkey::new_from_array([72; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn an_oversized_forwarded_list_still_fails_at_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    for index in 0..MAX_CPI_ACCOUNTS {
        fixture.push(Slot {
            label: "extra",
            meta: AccountMeta::new_readonly(Pubkey::new_from_array([index as u8 + 100; 32]), false),
            account: account(1),
        });
    }
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}
