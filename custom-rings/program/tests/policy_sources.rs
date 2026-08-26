//! Shared record source suites. The binary compiles only with the rule
//! features, so the host `POLICY` table matches the featured image in
//! `target/deploy-ring-rules`.

mod common;

use custom_ring_interface::{
    PolicyConfig, PolicySourceSlot, PolicySourceSpec, N_POLICY_SOURCE_SLOTS, POLICY,
};
use custom_ring_program::CustomRingError;
use mollusk_svm::{result::ProgramResult, Mollusk};
use pinocchio::Address;
use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_ring_policy::{RecordKind, RuleSource};

use crate::common::{
    authority, create_policy_fixture_with, create_record_fixture,
    curator_policy_config_account_with, curator_policy_config_pda, curator_records_pda,
    curator_source_slots, initialized_curator_policy_config_account,
    initialized_policy_config_account, own_source_slots, policy_config_account_with,
    policy_config_pda, policy_hash_for, records_tree, set_policy_source_fixture,
    setup_mollusk_rules, Fixture, Slot,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

fn referenced_kinds() -> Vec<u8> {
    let mut kinds: Vec<u8> = POLICY
        .rules()
        .iter()
        .filter_map(|rule| match rule.source {
            RuleSource::Records(kind) => Some(kind as u8),
            RuleSource::InlineAssets(_) => None,
        })
        .collect();
    kinds.sort_unstable();
    kinds.dedup();
    kinds
}

fn own_specs() -> Vec<PolicySourceSpec> {
    referenced_kinds()
        .into_iter()
        .map(|kind| PolicySourceSpec { kind, source: 0 })
        .collect()
}

fn specs_with_block_source(source: u8) -> Vec<PolicySourceSpec> {
    let mut specs = own_specs();
    for spec in &mut specs {
        if spec.kind == RecordKind::Block as u8 {
            spec.source = source;
        }
    }
    specs
}

fn mixed_sources() -> [PolicySourceSlot; N_POLICY_SOURCE_SLOTS] {
    let mut sources = own_source_slots();
    sources[RecordKind::Block as usize - 1].records =
        Address::new_from_array(curator_records_pda().0.to_bytes());
    sources
}

fn curator_slot(account: Account) -> Slot {
    Slot {
        label: "curator",
        meta: AccountMeta::new_readonly(curator_policy_config_pda().0, false),
        account,
    }
}

#[track_caller]
fn stored_policy_config(mollusk: &Mollusk, fixture: &Fixture) -> PolicyConfig {
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);
    let written = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &policy_config_pda().0)
        .map(|(_, account)| account.clone())
        .expect("policy config account");
    *bytemuck::from_bytes(&written.data)
}

/// The suite's premise, Recovery stays unreferenced.
#[test]
fn the_featured_table_references_allow_block_frozen() {
    assert_eq!(referenced_kinds(), [1, 2, 3]);
}

#[test]
fn create_policy_stores_the_own_mode_map() {
    let (mollusk, _) = setup_mollusk_rules();
    let fixture = create_policy_fixture_with(&own_specs());
    let config = stored_policy_config(&mollusk, &fixture);
    assert_eq!(config.sources, own_source_slots());
    assert_eq!(config.policy_hash, policy_hash_for(&own_source_slots()));
}

/// The stored slot is the curator's resolved owner, not the curator config.
#[test]
fn create_policy_copies_the_curators_resolved_owner() {
    let (mollusk, _) = setup_mollusk_rules();
    let mut fixture = create_policy_fixture_with(&specs_with_block_source(1));
    fixture.push(curator_slot(initialized_curator_policy_config_account()));
    let config = stored_policy_config(&mollusk, &fixture);
    assert_eq!(
        config.sources[RecordKind::Block as usize - 1].records,
        Address::new_from_array(curator_records_pda().0.to_bytes())
    );
    assert_eq!(config.sources, mixed_sources());
    assert_eq!(config.policy_hash, policy_hash_for(&mixed_sources()));
}

#[test]
fn a_duplicate_kind_spec_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let mut specs = own_specs();
    specs.push(PolicySourceSpec {
        kind: RecordKind::Allow as u8,
        source: 0,
    });
    let fixture = create_policy_fixture_with(&specs);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidPolicySource));
}

#[test]
fn a_missing_referenced_kind_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let specs: Vec<PolicySourceSpec> = own_specs()
        .into_iter()
        .filter(|spec| spec.kind != RecordKind::Frozen as u8)
        .collect();
    let fixture = create_policy_fixture_with(&specs);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidPolicySource));
}

#[test]
fn a_source_index_past_the_curator_list_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let mut fixture = create_policy_fixture_with(&specs_with_block_source(2));
    fixture.push(curator_slot(initialized_curator_policy_config_account()));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidPolicySource));
}

#[test]
fn a_curator_owned_by_the_system_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let mut curator = initialized_curator_policy_config_account();
    curator.owner = Pubkey::default();
    let mut fixture = create_policy_fixture_with(&specs_with_block_source(1));
    fixture.push(curator_slot(curator));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::InvalidCuratorPolicyConfig),
    );
}

#[test]
fn a_curator_at_a_foreign_address_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let mut fixture = create_policy_fixture_with(&specs_with_block_source(1));
    fixture.push(Slot {
        label: "curator",
        meta: AccountMeta::new_readonly(Pubkey::new_from_array([99; 32]), false),
        account: initialized_curator_policy_config_account(),
    });
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::InvalidCuratorPolicyConfig),
    );
}

#[test]
fn a_curator_without_the_policy_discriminator_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let mut curator = initialized_curator_policy_config_account();
    curator.data[0] = 0;
    let mut fixture = create_policy_fixture_with(&specs_with_block_source(1));
    fixture.push(curator_slot(curator));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::InvalidCuratorPolicyConfig),
    );
}

/// A 67-byte image is the sourceless layout of a stale curator build.
#[test]
fn a_legacy_curator_image_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let mut curator = initialized_curator_policy_config_account();
    curator.data.truncate(67);
    let mut fixture = create_policy_fixture_with(&specs_with_block_source(1));
    fixture.push(curator_slot(curator));
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::InvalidCuratorPolicyConfig),
    );
}

#[test]
fn a_curator_in_a_different_records_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let curator = curator_policy_config_account_with(
        Pubkey::new_from_array([55; 32]),
        curator_source_slots(),
    );
    let mut fixture = create_policy_fixture_with(&specs_with_block_source(1));
    fixture.push(curator_slot(curator));
    fixture.expect_err(&mollusk, custom(CustomRingError::CuratorTreeMismatch));
}

/// The loader reads the curator's map without rechecking the curator's hash,
/// so a map with an emptied Block slot still reaches the missing-source check.
#[test]
fn a_curator_without_the_requested_kind_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let mut curator = initialized_curator_policy_config_account();
    let mut state: PolicyConfig = *bytemuck::from_bytes(&curator.data);
    state.sources[RecordKind::Block as usize - 1] = PolicySourceSlot {
        kind: 0,
        records: Address::new_from_array([0; 32]),
    };
    curator.data = bytemuck::bytes_of(&state).to_vec();
    let mut fixture = create_policy_fixture_with(&specs_with_block_source(1));
    fixture.push(curator_slot(curator));
    fixture.expect_err(&mollusk, custom(CustomRingError::CuratorSourceMissing));
}

#[test]
fn set_policy_source_repoints_block_to_the_curator() {
    let (mollusk, _) = setup_mollusk_rules();
    let mut fixture = set_policy_source_fixture(
        policy_config_account_with(own_source_slots()),
        RecordKind::Block as u8,
        1,
    );
    fixture.push(curator_slot(initialized_curator_policy_config_account()));
    let config = stored_policy_config(&mollusk, &fixture);
    assert_eq!(config.sources, mixed_sources());
    assert_eq!(config.policy_hash, policy_hash_for(&mixed_sources()));
}

#[test]
fn set_policy_source_repoints_block_back_to_own() {
    let (mollusk, _) = setup_mollusk_rules();
    let fixture = set_policy_source_fixture(
        policy_config_account_with(mixed_sources()),
        RecordKind::Block as u8,
        0,
    );
    let config = stored_policy_config(&mollusk, &fixture);
    assert_eq!(config.sources, own_source_slots());
    assert_eq!(config.policy_hash, policy_hash_for(&own_source_slots()));
}

#[test]
fn set_policy_source_by_a_non_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let mut fixture = set_policy_source_fixture(
        policy_config_account_with(own_source_slots()),
        RecordKind::Block as u8,
        0,
    );
    fixture.substitute("authority", Pubkey::new_from_array([66; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

/// A stored hash the compiled table cannot reproduce blocks every re-point.
#[test]
fn a_drifted_stored_policy_hash_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let mut policy_config = policy_config_account_with(own_source_slots());
    policy_config.data[1] ^= 0xFF;
    let fixture = set_policy_source_fixture(policy_config, RecordKind::Block as u8, 0);
    fixture.expect_err(&mollusk, custom(CustomRingError::PolicyHashMismatch));
}

#[test]
fn an_unknown_kind_byte_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let fixture = set_policy_source_fixture(policy_config_account_with(own_source_slots()), 99, 0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidRecordKind));
}

/// Recovery is a valid kind the featured table does not reference.
#[test]
fn an_unreferenced_kind_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let fixture = set_policy_source_fixture(
        policy_config_account_with(own_source_slots()),
        RecordKind::Recovery as u8,
        0,
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidPolicySource));
}

#[test]
fn a_trailing_curator_with_an_own_source_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let mut fixture = set_policy_source_fixture(
        policy_config_account_with(own_source_slots()),
        RecordKind::Block as u8,
        0,
    );
    fixture.push(curator_slot(initialized_curator_policy_config_account()));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidPolicySource));
}

#[test]
fn a_shared_source_without_a_curator_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let fixture = set_policy_source_fixture(
        policy_config_account_with(own_source_slots()),
        RecordKind::Block as u8,
        1,
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidPolicySource));
}

#[test]
fn a_curator_served_kind_refuses_local_mutation_exactly() {
    let (mollusk, _) = setup_mollusk_rules();
    let fixture = create_record_fixture(
        policy_config_account_with(mixed_sources()),
        RecordKind::Block as u8,
        authority(),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::ForeignRecordSource));
}

/// An own slot passes the source gate, the fixture then dies in the SPP CPI.
#[test]
fn an_own_served_kind_passes_the_source_gate() {
    let (mollusk, _) = setup_mollusk_rules();
    let fixture = create_record_fixture(
        policy_config_account_with(mixed_sources()),
        RecordKind::Allow as u8,
        authority(),
    );
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_ne!(result.program_result, ProgramResult::Success);
    assert_ne!(
        result.program_result,
        ProgramResult::Failure(custom(CustomRingError::ForeignRecordSource))
    );
}

#[test]
fn the_layout_keeps_records_tree_and_sources_fixed() {
    let account = initialized_policy_config_account();
    assert_eq!(PolicyConfig::SIZE, 331);
    assert_eq!(account.data.len(), PolicyConfig::SIZE);
    assert_eq!(account.data[33..65], records_tree().to_bytes());
    let sources = own_source_slots();
    assert_eq!(&account.data[67..], bytemuck::bytes_of(&sources));
}
