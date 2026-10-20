use custom_ring_interface::CustomRingError;
use custom_ring_interface::{
    tag, CustomRingProof, CustomRingTransactIxData, PlainGroth16Proof, PolicyConfig,
    MEMBER_REGISTRY_ROOT_HISTORY,
};
use pinocchio::cpi::MAX_CPI_ACCOUNTS;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use zolana_interface::{
    event::RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
    instruction::{
        instruction_data::transact::{
            CircuitId, InputUtxo, OwnerTag, TransactIxData, TransactOutput, TransactProof,
            TreeContext,
        },
        MessageData,
    },
};
use zolana_interface::{INPUT_TREES, N_PUBLIC_SLOTS};

use solana_pubkey::Pubkey;
use zolana_interface::state::NULLIFIER_TREE_ROOT_HISTORY_CAPACITY;

use crate::common::{
    account, address_tree, address_tree_account, audit_ix_data, audit_only_config_account,
    audit_transact_fixture, auditor_message_len, auditor_pubkey, authority, curator_slot,
    encode_transact, escrowed_config_account, initialized_address_tree_account,
    initialized_address_tree_account_with_roots, initialized_address_tree_account_with_state_roots,
    initialized_config_account, initialized_curator_registry_account,
    initialized_policy_config_account, initialized_tree_account, insert_after_policy_trees,
    mixed_sources, nullifier_root_cursor, other_tree_slot, paused_address_tree_account,
    policy_config_account_with, policy_ix_data, setup_mollusk, transact_fixture, utxo_root_cursor,
    Fixture, Slot, RELEASED_RULES,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

pub(crate) fn confidential_output() -> TransactOutput {
    let key = auditor_pubkey(4);
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
        circuit: CircuitId::ConfidentialRingEddsa(1, 2, N_PUBLIC_SLOTS as u8),
        tx_viewing_pk: auditor_pubkey(4),
        salt: [0u8; 16],
        proof: TransactProof::zeroed(),
        inputs: Vec::new(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: vec![confidential_output()],
        messages: vec![MessageData {
            view_tag: auditor_pubkey(4)[1..33].try_into().expect("view tag"),
            data: {
                let mut data = vec![0u8; auditor_message_len(1)];
                data[..33].copy_from_slice(&auditor_pubkey(4));
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
    body(
        state_root_index,
        nullifier_root_index,
        false,
        transact_data(),
    )
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
    approval_required: bool,
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
    approval_required: bool,
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

/// Roots written after the init root in slot 0. The cursor starts at 1, so this
/// is the most that fit without wrapping it, and `cursor - NULLIFIER_ROTATIONS`
/// is then slot 1: the oldest root that is still live.
const NULLIFIER_ROTATIONS: u16 = (NULLIFIER_TREE_ROOT_HISTORY_CAPACITY - 2) as u16;

fn policy_fixture(state_root_index: u16, nullifier_root_index: u16) -> Fixture {
    transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(4)),
        transact_body(state_root_index, nullifier_root_index),
    )
}

fn policy_fixture_with(ix: CustomRingTransactIxData) -> Fixture {
    transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(4)),
        encode_transact(tag::TRANSACT, &ix),
    )
}

/// Shaped test instructions carry real input slots in their forwarded SPP layout.
/// Keep the account fixture aligned so pre-proof account checks reach the proof.
fn shaped_fixture(tag: u8, ix: CustomRingTransactIxData) -> Fixture {
    let input_count = ix.transact.inputs.len();
    let mut fixture = transact_fixture(escrowed_config_account(), encode_transact(tag, &ix));
    for index in 0..input_count {
        fixture.push(Slot {
            label: "input_nullifier",
            meta: AccountMeta::new(Pubkey::new_from_array([index as u8 + 100; 32]), false),
            account: account(1_000_000_000),
        });
    }
    fixture
}

#[test]
fn the_fixed_policy_tag_refuses_other_shapes_and_audit_only_rings() {
    let (mollusk, _) = setup_mollusk();
    let mut policy = policy_fixture(0, 0);
    policy.data_mut()[0] = tag::TRANSACT_TWO_BY_THREE;
    policy.expect_err(&mollusk, custom(CustomRingError::UnsupportedCircuit));
    let audit = audit_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(4)),
        encode_transact(
            tag::TRANSACT_TWO_BY_THREE,
            &audit_ix_data(bogus_proof(), transact_data()),
        ),
    );
    audit.expect_err(&mollusk, custom(CustomRingError::UnsupportedCircuit));
}

/// An audit-only ring dispatches to the audit verifying key with no policy
/// accounts present.
#[test]
fn an_audit_only_ring_reaches_the_audit_proof() {
    let (mollusk, _) = setup_mollusk();
    let fixture = audit_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(4)),
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
        initialized_config_account(authority(), auditor_pubkey(4)),
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
        let mut ix = ix_data(0, 0, false, transact_data());
        ix.policy_trees = vec![ix.policy_trees[0]; count];
        transact_fixture(
            initialized_config_account(authority(), auditor_pubkey(4)),
            encode_transact(tag::TRANSACT, &ix),
        )
        .expect_err(&mollusk, custom(CustomRingError::InvalidPolicyTrees));
    }
}

/// A second context without its account reads the forwarded payer as a tree.
#[test]
fn more_contexts_than_tree_accounts_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = ix_data(0, 0, false, transact_data());
    ix.policy_trees.push(ix.policy_trees[0]);
    transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(4)),
        encode_transact(tag::TRANSACT, &ix),
    )
    .expect_err(&mollusk, custom(CustomRingError::InvalidPolicyTrees));
}

#[test]
fn a_repeated_policy_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = ix_data(0, 0, false, transact_data());
    ix.policy_trees.push(ix.policy_trees[0]);
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(4)),
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
    let mut ix = ix_data(0, 0, false, transact_data());
    ix.policy_trees.push(ix.policy_trees[0]);
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(4)),
        encode_transact(tag::TRANSACT, &ix),
    );
    insert_after_policy_trees(&mut fixture, other_tree_slot());
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_stale_index_into_a_second_policy_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = ix_data(0, 0, false, transact_data());
    ix.policy_trees.push(TreeContext {
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 5,
    });
    let mut fixture = transact_fixture(
        initialized_config_account(authority(), auditor_pubkey(4)),
        encode_transact(tag::TRANSACT, &ix),
    );
    insert_after_policy_trees(&mut fixture, other_tree_slot());
    fixture.expect_err(&mollusk, custom(CustomRingError::StalePolicyRoot));
}

#[test]
fn an_audit_only_ring_takes_no_policy_trees() {
    let (mollusk, _) = setup_mollusk();
    audit_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(4)),
        transact_body(0, 0),
    )
    .expect_err(&mollusk, custom(CustomRingError::InvalidPolicyTrees));
}

#[test]
fn a_policy_ring_reads_the_registry_root_at_its_index() {
    let (mollusk, _) = setup_mollusk();
    let bound = |index: u8| {
        let mut ix = ix_data(0, 0, false, transact_data());
        ix.registry_root_index = index;
        transact_fixture(
            escrowed_config_account(),
            encode_transact(tag::TRANSACT, &ix),
        )
    };
    bound(0).expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    bound(1).expect_err(&mollusk, custom(CustomRingError::StaleMemberRegistryRoot));
    bound(MEMBER_REGISTRY_ROOT_HISTORY as u8)
        .expect_err(&mollusk, custom(CustomRingError::StaleMemberRegistryRoot));

    let mut missing = bound(0);
    missing.remove("member_registry_root");
    missing.expect_err(&mollusk, custom(CustomRingError::InvalidMemberRegistryRoot));
    let mut other = bound(0);
    other.substitute("member_registry_root", Pubkey::new_from_array([79; 32]));
    other.expect_err(&mollusk, custom(CustomRingError::InvalidMemberRegistryRoot));
}

/// The curator's registry root follows the ring's own.
#[test]
fn a_curated_policy_reads_the_curator_root_at_its_index() {
    let (mollusk, _) = setup_mollusk();
    let curated = |index: u8| {
        let mut ix = ix_data(0, 0, false, transact_data());
        ix.foreign_root_indexes = [index];
        let mut fixture = transact_fixture(
            initialized_config_account(authority(), auditor_pubkey(4)),
            encode_transact(tag::TRANSACT, &ix),
        );
        fixture.set_account(
            "policy_config",
            policy_config_account_with(&RELEASED_RULES, mixed_sources()),
        );
        let at = fixture.position("member_registry_root") + 1;
        fixture.insert(at, curator_slot(initialized_curator_registry_account()));
        fixture
    };
    curated(0).expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
    curated(1).expect_err(&mollusk, custom(CustomRingError::StaleMemberRegistryRoot));
    let mut missing = curated(0);
    missing.remove("curator");
    missing.expect_err(&mollusk, custom(CustomRingError::InvalidCuratorRegistry));
    let mut other = curated(0);
    other.substitute("curator", Pubkey::new_from_array([79; 32]));
    other.expect_err(&mollusk, custom(CustomRingError::InvalidCuratorRegistry));
}

#[test]
fn a_registry_index_without_a_binding_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = ix_data(0, 0, false, transact_data());
    ix.foreign_root_indexes = [1];
    policy_fixture_with(ix).expect_err(
        &mollusk,
        custom(CustomRingError::UnexpectedMemberRegistryRoot),
    );
    let mut audit = audit_ix_data(bogus_proof(), transact_data());
    audit.registry_root_index = 1;
    audit_transact_fixture(
        audit_only_config_account(authority(), auditor_pubkey(4)),
        encode_transact(tag::TRANSACT, &audit),
    )
    .expect_err(
        &mollusk,
        custom(CustomRingError::UnexpectedMemberRegistryRoot),
    );
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

#[test]
fn an_old_live_nullifier_root_reaches_the_proof() {
    let (mollusk, _) = setup_mollusk();
    let tree = initialized_address_tree_account_with_roots(NULLIFIER_ROTATIONS);
    let oldest = nullifier_root_cursor(&tree) - NULLIFIER_ROTATIONS;
    let mut fixture = policy_fixture(0, oldest);
    fixture.set_account("policy_tree", tree);
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

#[test]
fn a_nullifier_root_index_past_the_history_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = policy_fixture(0, u16::MAX);
    fixture.expect_err(&mollusk, custom(CustomRingError::StalePolicyRoot));
}

/// The history wraps, a slot no rotation has written holds zero and is
/// refused.
#[test]
fn an_unwritten_history_slot_is_rejected_exactly() {
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
            meta: AccountMeta::new_readonly(Pubkey::new_from_array([index as u8 + 100; 32]), true),
            account: account(1),
        });
    }
    fixture.expect_err(&mollusk, custom(CustomRingError::ProofVerificationFailed));
}

/// Every policy tree slot and the escrow registry, verified up to the pairing.
#[test]
fn five_policy_trees_and_the_registry_fit_the_transaction_budget() {
    let (mollusk, _) = setup_mollusk();
    let mut ix = ix_data(0, 0, false, transact_data());
    ix.proof.commitment = [0; 32];
    ix.proof.commitment_pok = [0; 32];
    ix.policy_trees = vec![ix.policy_trees[0]; INPUT_TREES];
    let mut fixture = transact_fixture(
        escrowed_config_account(),
        encode_transact(tag::TRANSACT, &ix),
    );
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

/// Exercises public-table loading, all 78 scalar multiplications and the
/// Groth16 pairing in SBF. The deliberately false proof then stops before CPI.
#[test]
fn the_fixed_policy_verifier_fits_the_transaction_budget() {
    let (mollusk, _) = setup_mollusk();
    let mut transact = transact_data();
    transact.circuit = CircuitId::ConfidentialRingEddsa(2, 4, N_PUBLIC_SLOTS as u8);
    transact.inputs = vec![
        InputUtxo {
            nullifier_hash: [1; 32],
            tree_index: 0
        };
        2
    ];
    transact.outputs = vec![confidential_output(); 3];
    transact.messages[0].data.resize(auditor_message_len(3), 0);
    let mut ix = ix_data(0, 0, false, transact);
    ix.proof.commitment = [0; 32];
    ix.proof.commitment_pok = [0; 32];
    let fixture = shaped_fixture(tag::TRANSACT_TWO_BY_THREE, ix);
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(
        result.program_result,
        mollusk_svm::result::ProgramResult::Failure(custom(
            CustomRingError::ProofVerificationFailed
        ))
    );
    assert!(
        result.compute_units_consumed > 400_000,
        "must reach the public-input MSM and pairing"
    );
    assert!(
        result.compute_units_consumed < 900_000,
        "leave room for commitment verification and SPP"
    );
    eprintln!(
        "fixed policy transact through Groth16 pairing: {} CU",
        result.compute_units_consumed
    );
}

#[test]
fn both_shaped_policy_keys_reach_the_pairing_within_the_budget() {
    let (mollusk, _) = setup_mollusk();
    for tag in [tag::TRANSACT_SHAPED, tag::TRANSACT_SHAPED_SUBTREE] {
        let mut transact = transact_data();
        transact.circuit = CircuitId::ConfidentialRingEddsa(16, 4, N_PUBLIC_SLOTS as u8);
        transact.inputs = (1..=16)
            .map(|i| InputUtxo {
                nullifier_hash: [i; 32],
                tree_index: 0,
            })
            .collect();
        transact.outputs = vec![confidential_output(); 4];
        transact.messages[0].data.resize(auditor_message_len(4), 0);
        let mut ix = ix_data(0, 0, false, transact);
        ix.proof.commitment = [0; 32];
        ix.proof.commitment_pok = [0; 32];
        let fixture = shaped_fixture(tag, ix);
        let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
        assert_eq!(
            result.program_result,
            mollusk_svm::result::ProgramResult::Failure(custom(
                CustomRingError::ProofVerificationFailed
            ))
        );
        assert!(result.compute_units_consumed > 400_000);
        assert!(result.compute_units_consumed < 900_000);
        eprintln!(
            "shaped policy tag {tag} through pairing: {} CU",
            result.compute_units_consumed
        );
    }
}

#[test]
fn shaped_tags_reject_audit_only_rings_and_unshipped_or_overfull_shapes() {
    let (mollusk, _) = setup_mollusk();
    for tag in [tag::TRANSACT_SHAPED, tag::TRANSACT_SHAPED_SUBTREE] {
        let audit = audit_transact_fixture(
            audit_only_config_account(authority(), auditor_pubkey(4)),
            encode_transact(tag, &audit_ix_data(bogus_proof(), transact_data())),
        );
        audit.expect_err(&mollusk, custom(CustomRingError::UnsupportedCircuit));
        for (capacity, actual) in [(1, 2), (24, 24)] {
            let mut transact = transact_data();
            transact.circuit = CircuitId::ConfidentialRingEddsa(capacity, 2, N_PUBLIC_SLOTS as u8);
            transact.inputs = (1..=actual)
                .map(|i| InputUtxo {
                    nullifier_hash: [i; 32],
                    tree_index: 0,
                })
                .collect();
            let fixture = shaped_fixture(tag, ix_data(0, 0, false, transact));
            fixture.expect_err(&mollusk, custom(CustomRingError::UnsupportedCircuit));
        }
    }
}
