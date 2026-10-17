//! Shared list source suites over `RELEASED_RULES`.

mod common;

use custom_ring_interface::CustomRingError;
use custom_ring_interface::{MemberRegistryRoot, PolicyConfig, SourceSpec};
use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_ring_policy::{ListId, ListNamespace, ListSet};

use crate::common::{
    address_tree, create_policy_fixture_with, curator_registry_address, curator_slot,
    initialized_curator_registry_account, mixed_sources, namespace_pda, own_source_slots,
    own_specs, policy_config_account_with, policy_hash_for, set_policy_source_fixture,
    setup_mollusk, specs_with_block_source, stored_policy_config, table_ix_data, Fixture,
    ADDRESS_TREE_ID, RELEASED_RULES, WARPED_SLOT,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

fn released_config() -> Account {
    policy_config_account_with(&RELEASED_RULES, own_source_slots(&RELEASED_RULES))
}

fn create_released_fixture(specs: &[SourceSpec]) -> Fixture {
    create_policy_fixture_with(&table_ix_data(&RELEASED_RULES, specs))
}

/// The suite's premise, Recovery stays unreferenced.
#[test]
fn the_released_table_references_allow_block_frozen() {
    assert_eq!(
        RELEASED_RULES.referenced(),
        ListSet::of(&[ListId::Allow, ListId::Block, ListId::Frozen])
    );
}

#[test]
fn create_policy_stores_the_own_mode_map() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_released_fixture(&own_specs(&RELEASED_RULES));
    let config = stored_policy_config(&mollusk, &fixture);
    assert_eq!(config.sources, own_source_slots(&RELEASED_RULES));
    assert_eq!(
        config.policy_hash,
        policy_hash_for(&RELEASED_RULES, &own_source_slots(&RELEASED_RULES))
    );
}

/// The stored slot is the curator's registry root account.
#[test]
fn create_policy_stores_the_curators_registry() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_released_fixture(&specs_with_block_source(1));
    fixture.push(curator_slot(initialized_curator_registry_account()));
    let config = stored_policy_config(&mollusk, &fixture);
    assert_eq!(
        config.sources[ListId::Block.slot()].registry,
        curator_registry_address()
    );
    assert_eq!(config.sources, mixed_sources());
    assert_eq!(
        config.policy_hash,
        policy_hash_for(&RELEASED_RULES, &mixed_sources())
    );
}

#[test]
fn a_duplicate_kind_spec_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut specs = own_specs(&RELEASED_RULES);
    specs.push(SourceSpec {
        list_id: ListId::Allow as u8,
        source: 0,
    });
    let fixture = create_released_fixture(&specs);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSource));
}

#[test]
fn a_missing_referenced_kind_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let specs: Vec<SourceSpec> = own_specs(&RELEASED_RULES)
        .into_iter()
        .filter(|spec| spec.list_id != ListId::Frozen as u8)
        .collect();
    let fixture = create_released_fixture(&specs);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSource));
}

#[test]
fn a_source_index_past_the_curator_list_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_released_fixture(&specs_with_block_source(2));
    fixture.push(curator_slot(initialized_curator_registry_account()));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSource));
}

/// A registry owned by another program derives to another address.
#[test]
fn a_curator_registry_owned_by_the_system_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut curator = initialized_curator_registry_account();
    curator.owner = Pubkey::default();
    let mut fixture = create_released_fixture(&specs_with_block_source(1));
    fixture.push(curator_slot(curator));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidCuratorRegistry));
}

#[test]
fn a_curator_registry_at_a_foreign_address_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_released_fixture(&specs_with_block_source(1));
    fixture.push(common::Slot {
        label: "curator",
        meta: AccountMeta::new_readonly(Pubkey::new_from_array([99; 32]), false),
        account: initialized_curator_registry_account(),
    });
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidCuratorRegistry));
}

#[test]
fn a_curator_registry_without_the_discriminator_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut curator = initialized_curator_registry_account();
    curator.data[0] = 0;
    let mut fixture = create_released_fixture(&specs_with_block_source(1));
    fixture.push(curator_slot(curator));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidCuratorRegistry));
}

#[test]
fn a_truncated_curator_registry_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut curator = initialized_curator_registry_account();
    curator.data.truncate(MemberRegistryRoot::SIZE - 1);
    let mut fixture = create_released_fixture(&specs_with_block_source(1));
    fixture.push(curator_slot(curator));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidCuratorRegistry));
}

#[test]
fn set_policy_source_repoints_block_to_the_curator() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_policy_source_fixture(released_config(), ListId::Block as u8, 1);
    fixture.push(curator_slot(initialized_curator_registry_account()));
    let config = stored_policy_config(&mollusk, &fixture);
    assert_eq!(config.sources, mixed_sources());
    assert_eq!(
        config.policy_hash,
        policy_hash_for(&RELEASED_RULES, &mixed_sources())
    );
    assert_eq!(config.rules, RELEASED_RULES.encode());
}

#[test]
fn set_policy_source_repoints_block_back_to_own() {
    let (mollusk, _) = setup_mollusk();
    let fixture = set_policy_source_fixture(
        policy_config_account_with(&RELEASED_RULES, mixed_sources()),
        ListId::Block as u8,
        0,
    );
    let config = stored_policy_config(&mollusk, &fixture);
    assert_eq!(config.sources, own_source_slots(&RELEASED_RULES));
    assert_eq!(
        config.policy_hash,
        policy_hash_for(&RELEASED_RULES, &own_source_slots(&RELEASED_RULES))
    );
}

#[test]
fn set_policy_source_bumps_the_generation_and_slot() {
    let (mut mollusk, _) = setup_mollusk();
    mollusk.warp_to_slot(WARPED_SLOT);
    let mut fixture = set_policy_source_fixture(released_config(), ListId::Block as u8, 1);
    fixture.push(curator_slot(initialized_curator_registry_account()));
    let config = stored_policy_config(&mollusk, &fixture);
    assert_eq!(config.generation(), 2);
    assert_eq!(config.generation_slot(), WARPED_SLOT);
}

#[test]
fn a_source_write_at_the_generation_ceiling_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut stored = released_config();
    let mut state: PolicyConfig = *bytemuck::from_bytes(&stored.data);
    state.generation = u32::MAX.to_le_bytes();
    stored.data = bytemuck::bytes_of(&state).to_vec();
    let fixture = set_policy_source_fixture(stored, ListId::Block as u8, 0);
    fixture.expect_err(&mollusk, custom(CustomRingError::PolicyGenerationOverflow));
}

#[test]
fn set_policy_source_by_a_non_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_policy_source_fixture(released_config(), ListId::Block as u8, 0);
    fixture.substitute("authority", Pubkey::new_from_array([66; 32]));
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedAuthority));
}

#[test]
fn an_unknown_kind_byte_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = set_policy_source_fixture(released_config(), 99, 0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidListId));
}

/// Recovery is a valid list the released table does not reference.
#[test]
fn an_unreferenced_kind_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = set_policy_source_fixture(released_config(), ListId::Recovery as u8, 0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSource));
}

#[test]
fn a_trailing_curator_with_an_own_source_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = set_policy_source_fixture(released_config(), ListId::Block as u8, 0);
    fixture.push(curator_slot(initialized_curator_registry_account()));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSource));
}

#[test]
fn a_shared_source_without_a_curator_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let fixture = set_policy_source_fixture(released_config(), ListId::Block as u8, 1);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSource));
}

/// Every curator slot names one registry, a second curator cannot share the table.
#[test]
fn a_second_curator_registry_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut sources = own_source_slots(&RELEASED_RULES);
    sources[ListId::Frozen.slot()].registry =
        pinocchio::Address::new_from_array(Pubkey::new_from_array([77; 32]).to_bytes());
    let mut fixture = set_policy_source_fixture(
        policy_config_account_with(&RELEASED_RULES, sources),
        ListId::Block as u8,
        1,
    );
    fixture.push(curator_slot(initialized_curator_registry_account()));
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidSource));
}

#[test]
fn the_layout_pins_every_field_offset() {
    let account = released_config();
    assert_eq!(PolicyConfig::SIZE, 1596);
    assert_eq!(account.data.len(), PolicyConfig::SIZE);
    assert_eq!(account.data[33..65], address_tree().to_bytes());
    assert_eq!(account.data[65..67], ADDRESS_TREE_ID.to_le_bytes());
    assert_eq!(
        account.data[69..101],
        ListNamespace::new(namespace_pda().0.as_array())
            .expect("namespace owner")
            .owner_hash
    );
    let sources = own_source_slots(&RELEASED_RULES);
    assert_eq!(&account.data[101..365], bytemuck::bytes_of(&sources));
    assert_eq!(
        &account.data[365..1584],
        bytemuck::bytes_of(&RELEASED_RULES.encode())
    );
    assert_eq!(account.data[1584..1588], 1u32.to_le_bytes());
    assert_eq!(account.data[1588..1596], 0u64.to_le_bytes());
}
