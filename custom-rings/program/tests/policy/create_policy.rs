use custom_ring_interface::{PolicyTableIxData, CREATE_POLICY_COMPUTE_UNIT_LIMIT, POLICY_CONFIG};
use custom_ring_program::CustomRingError;
use mollusk_svm::result::ProgramResult;
use solana_program_error::ProgramError;
use zolana_account_checks::AccountError;
use zolana_ring_policy::{EncodedRuleTable, ListId, Rule, RuleTable, Subject};

use crate::common::{
    consumed, create_policy_fixture, create_policy_fixture_with, entries_tree,
    entries_tree_account, largest_table, namespace_pda, own_source_slots, own_specs,
    policy_hash_for, program_id, setup_mollusk, stored_policy_config, table_ix_data, PINNED_RULES,
    WARPED_SLOT,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

/// Pins the green fixture, without it the negatives could pass for the wrong
/// reason.
#[test]
fn create_policy_pins_an_empty_table_at_generation_one() {
    let (mut mollusk, _) = setup_mollusk();
    mollusk.warp_to_slot(WARPED_SLOT);
    let config = stored_policy_config(&mollusk, &create_policy_fixture());
    let empty = RuleTable::empty();
    assert_eq!(config.discriminator, POLICY_CONFIG);
    assert_eq!(config.sources, own_source_slots(&empty));
    assert_eq!(config.rules, EncodedRuleTable::empty());
    assert_eq!(config.policy_hash, policy_hash_for(&empty, &config.sources));
    assert_eq!(config.entries_tree.to_bytes(), entries_tree().to_bytes());
    assert_eq!(config.namespace_bump, namespace_pda().1);
    assert_eq!(config.generation(), 1);
    assert_eq!(config.generation_slot(), WARPED_SLOT);
}

#[test]
fn create_policy_stores_rows_and_members_verbatim() {
    let (mut mollusk, _) = setup_mollusk();
    mollusk.warp_to_slot(WARPED_SLOT);
    let table = table_ix_data(&PINNED_RULES, &own_specs(&PINNED_RULES));
    let config = stored_policy_config(&mollusk, &create_policy_fixture_with(&table));
    assert_eq!(config.rules, PINNED_RULES.encode());
    assert_eq!(usize::from(config.rules.rule_count), table.rules.len());
    assert_eq!(
        &config.rules.rules[..table.rules.len()],
        table.rules.as_slice()
    );
    assert_eq!(
        usize::from(config.rules.inline_count),
        table.inline_assets.len()
    );
    assert_eq!(
        &config.rules.inline_assets[..table.inline_assets.len()],
        table.inline_assets.as_slice()
    );
    let sources = own_source_slots(&PINNED_RULES);
    assert_eq!(config.sources, sources);
    assert_eq!(config.policy_hash, policy_hash_for(&PINNED_RULES, &sources));
    assert_eq!(config.generation(), 1);
    assert_eq!(config.generation_slot(), WARPED_SLOT);
}

#[test]
fn create_policy_stores_per_asset_limits_verbatim() {
    const RULES: RuleTable = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset())
        .inline_assets(&[[3u8; 32], [4u8; 32]])
        .inline_limits(&[5, 7])
        .build();
    let (mollusk, _) = setup_mollusk();
    let table = table_ix_data(&RULES, &own_specs(&RULES));
    let config = stored_policy_config(&mollusk, &create_policy_fixture_with(&table));
    assert_eq!(config.rules, RULES.encode());
    assert_eq!(config.rules.inline_limits[0], 5u64.to_be_bytes());
    assert_eq!(config.rules.inline_limits[1], 7u64.to_be_bytes());
    assert_eq!(config.policy_hash, policy_hash_for(&RULES, &config.sources));
}

type Tamper = fn(&mut PolicyTableIxData);

#[test]
fn create_policy_refuses_rows_the_circuit_cannot_enforce() {
    let (mollusk, _) = setup_mollusk();
    let cases: [(&str, Tamper); 9] = [
        ("unknown subject", |table| table.rules[0][31] = 9),
        ("list in both sets", |table| {
            table.rules[0][19] = table.rules[0][29];
        }),
        ("alternative beside an absent primary", |table| {
            table.rules[1][19] = 0b0000_0010;
        }),
        ("seventeen rows", |table| {
            let row = table.rules[0];
            table.rules.resize(17, row);
        }),
        ("nine inline members", |table| {
            table.inline_assets.resize(9, [9u8; 32]);
        }),
        ("too many answers", |table| {
            table.rules = [
                Rule::require(Subject::OutputOwner, ListId::Allow),
                Rule::forbid(Subject::OutputOwner, ListId::Block),
                Rule::require(Subject::OutputOwner, ListId::Approval),
            ]
            .iter()
            .map(Rule::encoded)
            .collect();
            table.inline_assets.clear();
        }),
        ("members without an inline rule", |table| {
            table.rules.truncate(2);
        }),
        ("per-asset guard without limits", |table| {
            table.rules[0][28] = 2;
        }),
        ("limits without a per-asset guard", |table| {
            table.inline_limits = vec![5, 7];
        }),
    ];
    for (label, tamper) in cases {
        let mut table = table_ix_data(&PINNED_RULES, &own_specs(&PINNED_RULES));
        tamper(&mut table);
        let fixture = create_policy_fixture_with(&table);
        let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
        assert_eq!(
            result.program_result,
            ProgramResult::Failure(custom(CustomRingError::InvalidPolicyRules)),
            "{label}"
        );
    }
}

#[test]
fn the_largest_table_with_no_curator_fits_the_create_policy_budget() {
    let (mollusk, _) = setup_mollusk();
    let rules = largest_table();
    let fixture = create_policy_fixture_with(&table_ix_data(&rules, &own_specs(&rules)));
    assert!(consumed(&mollusk, &fixture) <= u64::from(CREATE_POLICY_COMPUTE_UNIT_LIMIT));
}

#[test]
fn an_entries_tree_owned_by_another_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_policy_fixture();
    let mut foreign = entries_tree_account();
    foreign.owner = program_id();
    fixture.set_account("entries_tree", foreign);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidEntriesTree));
}

#[test]
fn an_entries_tree_without_the_tree_discriminator_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_policy_fixture();
    let mut wrong = entries_tree_account();
    wrong.data[0] = 0;
    fixture.set_account("entries_tree", wrong);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidEntriesTree));
}

#[test]
fn a_second_create_policy_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_policy_fixture();
    fixture.set_account(
        "policy_config",
        crate::common::initialized_policy_config_account(),
    );
    fixture.expect_err(
        &mollusk,
        custom(CustomRingError::PolicyConfigAlreadyInitialized),
    );
}

#[test]
fn create_policy_by_a_non_upgrade_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_policy_fixture();
    fixture.set_account(
        "program_data",
        crate::common::program_data_account(Some(&crate::common::rent_recipient())),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::UnauthorizedInitializer));
}

#[test]
fn create_policy_rejects_trailing_instruction_data() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_policy_fixture();
    fixture.push_data(0);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidInstructionData));
}

#[test]
fn a_policy_config_at_a_foreign_address_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_policy_fixture();
    fixture.substitute(
        "policy_config",
        solana_pubkey::Pubkey::new_from_array([9; 32]),
    );
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidPolicyConfigPda));
}

/// Missing accounts must not reach the table hash.
#[test]
fn a_short_account_list_is_rejected() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_policy_fixture();
    fixture.truncate(3);
    fixture.expect_err(
        &mollusk,
        ProgramError::Custom(u32::from(AccountError::NotEnoughAccountKeys)),
    );
}
