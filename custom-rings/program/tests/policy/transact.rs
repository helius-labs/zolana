use custom_ring_interface::{
    tag, CustomRingProof, CustomRingTransactIxData, PlainGroth16Proof, PolicyConfig,
    AUDITOR_MESSAGE_LEN, KEY_REGISTRY_ROOT_HISTORY,
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
use zolana_interface::{pda, INPUT_TREES, N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID};

use solana_pubkey::Pubkey;
use zolana_interface::state::NULLIFIER_TREE_ROOT_HISTORY_CAPACITY;

use crate::common::{
    account, address_tree, address_tree_account, audit_ix_data, audit_only_config_account,
    audit_transact_fixture, auditor_pubkey, authority, encode_transact, escrowed_config_account,
    initialized_address_tree_account, initialized_address_tree_account_with_roots,
    initialized_address_tree_account_with_state_roots, initialized_config_account,
    initialized_policy_config_account, initialized_tree_account, insert_after_policy_trees,
    key_registry_root_slot, nullifier_root_cursor, other_tree, other_tree_slot,
    paused_address_tree_account, policy_ix_data, setup_mollusk, transact_fixture, utxo_root_cursor,
    Fixture, Slot,
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

fn bogus_proof() -> CustomRingProof {
    CustomRingProof {
        groth16: PlainGroth16Proof {
            proof_a: [0; 32],
            proof_b: [0; 64],
            proof_c: [0; 32],
        },
        commitment: [0xFF; 32],
        commitment_pok: [0xFF; 32],
    }
}

/// One policy tree read at the given root indexes.
pub(crate) fn ix_data(
    state_root_index: u16,
    nullifier_root_index: u16,
    approval_required: u8,
    transact: TransactIxData,
) -> CustomRingTransactIxData {
    CustomRingTransactIxData {
        policy_trees: vec![TreeContext {
            utxo_tree_root_index: state_root_index,
            nullifier_tree_root_index: nullifier_root_index,
        }],
        approval_required,
        ..policy_ix_data(bogus_proof(), transact)
    }
}

pub(crate) fn body(
    state_root_index: u16,
    nullifier_root_index: u16,
    approval_required: u8,
    transact: TransactIxData,
) -> Vec<u8> {
    encode_transact(
        tag::TRANSACT,
        &ix_data(
            state_root_index,
            nullifier_root_index,
            approval_required,
            transact,
        ),
    )
}

struct RevocationTarget {
    address: Pubkey,
    state: solana_account::Account,
}

fn revocation_target_bytes() -> [u8; 32] {
    let mut target = [0u8; 32];
    target[31] = 7;
    target
}

fn canonical_target(state: solana_account::Account) -> RevocationTarget {
    target_under(address_tree(), state)
}

fn target_under(tree: Pubkey, state: solana_account::Account) -> RevocationTarget {
    RevocationTarget {
        address: pda::nullifier_pda(&tree, &revocation_target_bytes()).0,
        state,
    }
}

fn queued_target() -> RevocationTarget {
    let mut queued = account(1_000_000);
    queued.owner = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    queued.data = vec![1];
    canonical_target(queued)
}

fn revocation_fixture(nullifier_root_index: u16, target: RevocationTarget) -> Fixture {
    revocation_fixture_with(ix_data(0, nullifier_root_index, 0, transact_data()), target)
}

fn revocation_fixture_with(mut ix: CustomRingTransactIxData, target: RevocationTarget) -> Fixture {
    ix.revocation_targets[0] = revocation_target_bytes();
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        encode_transact(tag::TRANSACT, &ix),
    );
    fixture.insert_windows(vec![Slot {
        label: "revocation_target",
        meta: AccountMeta::new_readonly(target.address, false),
        account: target.state,
    }]);
    fixture
}

#[test]
fn an_unused_canonical_revocation_target_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    revocation_fixture(0, canonical_target(account(0)))
        .expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_substituted_revocation_target_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let target = RevocationTarget {
        address: Pubkey::new_from_array([91; 32]),
        state: account(0),
    };
    revocation_fixture(0, target)
        .expect_err(&mollusk, custom(CustomRingError::InvalidRevocationTarget));
}

#[test]
fn a_queued_revocation_target_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    revocation_fixture(0, queued_target())
        .expect_err(&mollusk, custom(CustomRingError::PolicyFactRevoked));
}

#[test]
fn a_revocation_behind_an_older_admitted_root_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let tree = initialized_address_tree_account_with_roots(NULLIFIER_ROOT_WINDOW as u16 + 1);
    let edge = nullifier_root_cursor(&tree) - NULLIFIER_ROOT_WINDOW as u16;
    let mut fixture = revocation_fixture(edge, queued_target());
    fixture.set_account("policy_tree", tree);
    fixture.expect_err(&mollusk, custom(CustomRingError::PolicyFactRevoked));
}

fn policy_fixture(state_root_index: u16, nullifier_root_index: u16) -> Fixture {
    transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        transact_body(state_root_index, nullifier_root_index),
    )
}

fn policy_fixture_with(ix: CustomRingTransactIxData) -> Fixture {
    transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        encode_transact(tag::TRANSACT, &ix),
    )
}

/// An audit-only ring dispatches to the audit verifying key with no policy
/// accounts present.
#[test]
fn an_audit_only_ring_reaches_the_audit_proof() {
    let (mollusk, _) = setup_mollusk();
    let fixture = audit_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(2)),
        encode_transact(
            tag::TRANSACT,
            &audit_ix_data(bogus_proof(), transact_data()),
        ),
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

/// The roots come from a real tree account, a stub never yields one.
#[test]
fn a_policy_tree_that_is_not_a_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    fixture.set_account("policy_tree", address_tree_account());
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidPolicyTrees));
    let mut foreign = policy_fixture(0, 0);
    foreign.substitute("policy_tree", Pubkey::new_from_array([78; 32]));
    foreign.expect_err(&mollusk, custom(CustomRingError::InvalidPolicyTrees));
}

#[test]
fn a_policy_tree_count_outside_the_slots_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    for count in [0, INPUT_TREES + 1] {
        let mut ix = ix_data(0, 0, 0, transact_data());
        ix.policy_trees = vec![ix.policy_trees[0]; count];
        transact_fixture(
            initialized_config_account(authority(), auditor_pubkey(2)),
            encode_transact(tag::TRANSACT, &ix),
        )
        .expect_err(&mollusk, custom(CustomRingError::InvalidPolicyTrees));
    }
}

/// A second context without its account reads the forwarded payer as a tree.
#[test]
fn more_contexts_than_tree_accounts_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = ix_data(0, 0, 0, transact_data());
    ix.policy_trees.push(ix.policy_trees[0]);
    transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        encode_transact(tag::TRANSACT, &ix),
    )
    .expect_err(&mollusk, custom(CustomRingError::InvalidPolicyTrees));
}

#[test]
fn a_repeated_policy_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = ix_data(0, 0, 0, transact_data());
    ix.policy_trees.push(ix.policy_trees[0]);
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        encode_transact(tag::TRANSACT, &ix),
    );
    insert_after_policy_trees(
        &mut fixture,
        Slot {
            label: "policy_tree",
            meta: AccountMeta::new_readonly(address_tree(), false),
            account: initialized_address_tree_account(),
        },
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidPolicyTrees));
}

#[test]
fn a_second_policy_tree_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = ix_data(0, 0, 0, transact_data());
    ix.policy_trees.push(ix.policy_trees[0]);
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        encode_transact(tag::TRANSACT, &ix),
    );
    insert_after_policy_trees(&mut fixture, other_tree_slot());
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_stale_index_into_a_second_policy_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = ix_data(0, 0, 0, transact_data());
    ix.policy_trees.push(TreeContext {
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 5,
    });
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(2)),
        encode_transact(tag::TRANSACT, &ix),
    );
    insert_after_policy_trees(&mut fixture, other_tree_slot());
    fixture.expect_err(&mollusk, custom(CustomRingError::StalePolicyRoot));
}

/// Each fact's revocation nullifier derives under the tree its slot names.
#[test]
fn a_revocation_target_derives_under_its_slot_tree() {
    let (mollusk, _) = setup_mollusk();
    let two_trees = || {
        let mut ix = ix_data(0, 0, 0, transact_data());
        ix.policy_trees.push(ix.policy_trees[0]);
        ix.revocation_tree_indexes[0] = 1;
        ix
    };
    let mut under_slot =
        revocation_fixture_with(two_trees(), target_under(other_tree(), account(0)));
    insert_after_policy_trees(&mut under_slot, other_tree_slot());
    under_slot.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));

    let mut under_address = revocation_fixture_with(two_trees(), canonical_target(account(0)));
    insert_after_policy_trees(&mut under_address, other_tree_slot());
    under_address.expect_err(&mollusk, custom(CustomRingError::InvalidRevocationTarget));
}

#[test]
fn a_revocation_tree_index_past_the_policy_trees_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = ix_data(0, 0, 0, transact_data());
    ix.revocation_tree_indexes[0] = 1;
    revocation_fixture_with(ix, canonical_target(account(0))).expect_err(
        &mollusk,
        custom(CustomRingError::InvalidRevocationTreeIndex),
    );
}

#[test]
fn an_index_on_an_empty_revocation_slot_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = ix_data(0, 0, 0, transact_data());
    ix.revocation_tree_indexes[1] = 1;
    policy_fixture_with(ix).expect_err(
        &mollusk,
        custom(CustomRingError::InvalidRevocationTreeIndex),
    );
    let mut audit = audit_ix_data(bogus_proof(), transact_data());
    audit.revocation_tree_indexes[0] = 1;
    audit_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(2)),
        encode_transact(tag::TRANSACT, &audit),
    )
    .expect_err(
        &mollusk,
        custom(CustomRingError::InvalidRevocationTreeIndex),
    );
}

#[test]
fn an_audit_only_ring_takes_no_policy_trees() {
    let (mollusk, _) = setup_mollusk();
    audit_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(2)),
        transact_body(0, 0),
    )
    .expect_err(&mollusk, custom(CustomRingError::InvalidPolicyTrees));
}

#[test]
fn an_escrowed_ring_reads_the_registry_root_at_its_index() {
    let (mollusk, _) = setup_mollusk();
    let escrowed = |index: u8| {
        let mut ix = ix_data(0, 0, 0, transact_data());
        ix.key_registry_root_index = index;
        let mut fixture = transact_fixture(
            escrowed_config_account(),
            encode_transact(tag::TRANSACT, &ix),
        );
        insert_after_policy_trees(&mut fixture, key_registry_root_slot());
        fixture
    };
    escrowed(0).expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    escrowed(1).expect_err(&mollusk, custom(CustomRingError::StaleKeyRegistryRoot));
    escrowed(KEY_REGISTRY_ROOT_HISTORY as u8)
        .expect_err(&mollusk, custom(CustomRingError::StaleKeyRegistryRoot));

    let mut missing = transact_fixture(escrowed_config_account(), transact_body(0, 0));
    missing.expect_err(&mollusk, custom(CustomRingError::InvalidKeyRegistryRoot));
    missing = escrowed(0);
    missing.substitute("key_registry_root", Pubkey::new_from_array([79; 32]));
    missing.expect_err(&mollusk, custom(CustomRingError::InvalidKeyRegistryRoot));
}

#[test]
fn a_registry_index_without_escrow_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = ix_data(0, 0, 0, transact_data());
    ix.key_registry_root_index = 1;
    policy_fixture_with(ix).expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
    let mut audit = audit_ix_data(bogus_proof(), transact_data());
    audit.key_registry_root_index = 1;
    audit_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(2)),
        encode_transact(tag::TRANSACT, &audit),
    )
    .expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
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

/// A nullifier root the policy tree has not written is stale and the transact
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
    let tree = initialized_address_tree_account_with_roots(NULLIFIER_ROOT_WINDOW as u16 + 1);
    let edge = nullifier_root_cursor(&tree) - NULLIFIER_ROOT_WINDOW as u16;
    let mut fixture = policy_fixture(0, edge);
    fixture.set_account("policy_tree", tree);
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_nullifier_root_one_rotation_past_the_window_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let tree = initialized_address_tree_account_with_roots(NULLIFIER_ROOT_WINDOW as u16 + 1);
    let past = nullifier_root_cursor(&tree) - NULLIFIER_ROOT_WINDOW as u16 - 1;
    let mut fixture = policy_fixture(0, past);
    fixture.set_account("policy_tree", tree);
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

/// A paused tree yields no root, the same fixture reaches the proof once the
/// tree is live again.
#[test]
fn a_paused_policy_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    fixture.set_account("policy_tree", paused_address_tree_account());
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidPolicyTrees));
    fixture.set_account("policy_tree", initialized_address_tree_account());
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// The default fixture's money tree already differs from the address tree.
#[test]
fn a_money_tree_apart_from_the_address_tree_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let fixture = policy_fixture(0, 0);
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// One account may be both a policy tree and the SPP input tree.
#[test]
fn a_policy_tree_aliasing_the_input_tree_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    fixture.substitute("input_tree", address_tree());
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn the_address_tree_is_the_configured_one() {
    assert_eq!(
        initialized_policy_config_account().data[33..65],
        address_tree().to_bytes()
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
    let tree = initialized_address_tree_account_with_state_roots(3);
    let oldest = utxo_root_cursor(&tree) - 3;
    let mut fixture = policy_fixture(oldest, 0);
    fixture.set_account("policy_tree", tree);
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// The stored id enters the statement, not the live tree's.
#[test]
fn a_drifted_address_tree_id_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = policy_fixture(0, 0);
    let mut config = initialized_policy_config_account();
    config.data[core::mem::offset_of!(PolicyConfig, address_tree_id)] ^= 0x01;
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

/// Every policy tree slot and the escrow registry, verified up to the pairing.
#[test]
fn five_policy_trees_and_the_registry_fit_the_transaction_budget() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = ix_data(0, 0, 0, transact_data());
    ix.proof.commitment = [0; 32];
    ix.proof.commitment_pok = [0; 32];
    ix.policy_trees = vec![ix.policy_trees[0]; INPUT_TREES];
    let mut fixture = transact_fixture(
        escrowed_config_account(),
        encode_transact(tag::TRANSACT, &ix),
    );
    insert_after_policy_trees(&mut fixture, key_registry_root_slot());
    for byte in 1..INPUT_TREES as u8 {
        let address = Pubkey::new_from_array([43 + byte; 32]);
        insert_after_policy_trees(
            &mut fixture,
            Slot {
                label: "policy_tree",
                meta: AccountMeta::new_readonly(address, false),
                account: initialized_tree_account(address, u16::from(byte)),
            },
        );
    }
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(
        result.program_result,
        mollusk_svm::result::ProgramResult::Failure(custom(
            CustomRingError::ProofVerificationFailed
        ))
    );
    eprintln!(
        "policy transact with {INPUT_TREES} trees and the registry: {} CU",
        result.compute_units_consumed
    );
}
