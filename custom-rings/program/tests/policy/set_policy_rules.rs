//! The upgrade authority's table re-pin.

use bytemuck::Zeroable;
use custom_ring_interface::{PolicyConfig, SourceSlot, SET_POLICY_RULES_COMPUTE_UNIT_LIMIT};
use custom_ring_program::CustomRingError;
use solana_account::Account;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_account_checks::AccountError;
use zolana_ring_policy::{ListId, Rule, RuleTable, Subject};

use crate::common::{
    account, consumed, curator_policy_config_account_with, curator_slot, curator_source_slots,
    entries_tree, initialized_curator_policy_config_account, largest_table, mixed_sources,
    namespace_pda, own_source_slots, own_specs, policy_config_account_with, policy_hash_for,
    program_data_account, rent_recipient, set_policy_rules_fixture, setup_mollusk,
    specs_with_block_source, stored_policy_config, table_ix_data, PINNED_RULES, RELEASED_RULES,
    WARPED_SLOT,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

const ALLOW_ONLY: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
    .build();

fn released_config() -> Account {
    policy_config_account_with(&RELEASED_RULES, own_source_slots(&RELEASED_RULES))
}

/// Pins the green re-pin, the negatives below fail for their own reason.
#[test]
fn a_re_pin_replaces_the_rows_under_the_next_generation() {
    let (mut mollusk, _) = setup_mollusk();
    mollusk.warp_to_slot(WARPED_SLOT);
    let table = table_ix_data(&PINNED_RULES, &own_specs(&PINNED_RULES));
    let config = stored_policy_config(
        &mollusk,
        &set_policy_rules_fixture(released_config(), &table),
    );
    assert_eq!(config.rules, PINNED_RULES.encode());
    let sources = own_source_slots(&PINNED_RULES);
    assert_eq!(config.sources, sources);
    assert_eq!(config.policy_hash, policy_hash_for(&PINNED_RULES, &sources));
    assert_eq!(config.generation(), 2);
    assert_eq!(config.generation_slot(), WARPED_SLOT);
    assert_eq!(config.entries_tree.to_bytes(), entries_tree().to_bytes());
    assert_eq!(config.namespace_bump, namespace_pda().1);
}

#[test]
fn a_re_pin_by_a_non_upgrade_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let table = table_ix_data(&PINNED_RULES, &own_specs(&PINNED_RULES));
    let mut fixture = set_policy_rules_fixture(released_config(), &table);
    fixture.set_account(
        "program_data",
        program_data_account(Some(&rent_recipient())),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

#[test]
fn invalid_rows_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut table = table_ix_data(&PINNED_RULES, &own_specs(&PINNED_RULES));
    table.rules[0][31] = 9;
    let fixture = set_policy_rules_fixture(released_config(), &table);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidPolicyRules));
}

#[test]
fn a_list_dropped_from_the_table_empties_its_slot() {
    let (mollusk, _) = setup_mollusk();
    let table = table_ix_data(&ALLOW_ONLY, &own_specs(&ALLOW_ONLY));
    let config = stored_policy_config(
        &mollusk,
        &set_policy_rules_fixture(released_config(), &table),
    );
    assert_eq!(config.sources, own_source_slots(&ALLOW_ONLY));
    assert_eq!(config.sources[ListId::Block.slot()], SourceSlot::zeroed());
    assert_eq!(config.sources[ListId::Frozen.slot()], SourceSlot::zeroed());
}

/// The stored slot is the curator's resolved owner, not the curator config.
#[test]
fn a_list_added_with_a_curator_names_it() {
    let (mollusk, _) = setup_mollusk();
    let stored = policy_config_account_with(&ALLOW_ONLY, own_source_slots(&ALLOW_ONLY));
    let table = table_ix_data(&RELEASED_RULES, &specs_with_block_source(1));
    let mut fixture = set_policy_rules_fixture(stored, &table);
    fixture.push(curator_slot(initialized_curator_policy_config_account()));
    let config = stored_policy_config(&mollusk, &fixture);
    assert_eq!(config.sources, mixed_sources());
    assert_eq!(
        config.policy_hash,
        policy_hash_for(&RELEASED_RULES, &mixed_sources())
    );
}

#[test]
fn a_curated_list_kept_without_its_curator_account_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let stored = policy_config_account_with(&RELEASED_RULES, mixed_sources());
    let table = table_ix_data(&RELEASED_RULES, &specs_with_block_source(1));
    let fixture = set_policy_rules_fixture(stored, &table);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSource));
}

#[test]
fn a_curator_in_a_different_entries_tree_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let table = table_ix_data(&RELEASED_RULES, &specs_with_block_source(1));
    let mut fixture = set_policy_rules_fixture(released_config(), &table);
    fixture.push(curator_slot(curator_policy_config_account_with(
        Pubkey::new_from_array([55; 32]),
        curator_source_slots(&RELEASED_RULES),
    )));
    fixture.expect_err(&mollusk, custom(CustomRingError::CuratorTreeMismatch));
}

#[test]
fn a_generation_at_the_ceiling_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut stored = released_config();
    let mut state: PolicyConfig = *bytemuck::from_bytes(&stored.data);
    state.generation = u32::MAX.to_le_bytes();
    stored.data = bytemuck::bytes_of(&state).to_vec();
    let table = table_ix_data(&PINNED_RULES, &own_specs(&PINNED_RULES));
    let fixture = set_policy_rules_fixture(stored, &table);
    fixture.expect_err(&mollusk, custom(CustomRingError::PolicyGenerationOverflow));
}

#[test]
fn the_largest_table_with_one_curator_fits_the_set_policy_rules_budget() {
    let (mollusk, _) = setup_mollusk();
    let rules = largest_table();
    let mut specs = own_specs(&rules);
    for spec in &mut specs {
        if spec.list_id == ListId::Block as u8 {
            spec.source = 1;
        }
    }
    let mut fixture = set_policy_rules_fixture(released_config(), &table_ix_data(&rules, &specs));
    fixture.push(curator_slot(initialized_curator_policy_config_account()));
    assert!(consumed(&mollusk, &fixture) <= u64::from(SET_POLICY_RULES_COMPUTE_UNIT_LIMIT));
}

#[test]
fn set_policy_rules_rejects_trailing_instruction_data() {
    let (mollusk, _) = setup_mollusk();
    let table = table_ix_data(&PINNED_RULES, &own_specs(&PINNED_RULES));
    let mut fixture = set_policy_rules_fixture(released_config(), &table);
    fixture.push_data(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn an_uninitialized_policy_config_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let table = table_ix_data(&PINNED_RULES, &own_specs(&PINNED_RULES));
    let fixture = set_policy_rules_fixture(account(0), &table);
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::PolicyConfigNotInitialized),
    );
}

/// Missing accounts must not reach the table hash.
#[test]
fn a_short_account_list_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let table = table_ix_data(&PINNED_RULES, &own_specs(&PINNED_RULES));
    let mut fixture = set_policy_rules_fixture(released_config(), &table);
    fixture.truncate(2);
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::NotEnoughAccountKeys)),
    );
}
