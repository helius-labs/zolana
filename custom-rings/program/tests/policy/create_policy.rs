use custom_ring_interface::{PolicyConfig, POLICY_CONFIG};
use custom_ring_program::CustomRingError;
use mollusk_svm::result::ProgramResult;
use solana_program_error::ProgramError;

use crate::common::{
    self, create_policy_fixture, policy_config_pda, program_id, records_pda, records_tree,
    records_tree_account, setup_mollusk,
};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

/// Pins the green fixture, without it the negatives could pass for the wrong
/// reason.
#[test]
fn create_policy_pins_the_compiled_table() {
    let (mollusk, _) = setup_mollusk();
    let fixture = create_policy_fixture();
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_eq!(result.program_result, ProgramResult::Success);

    let written = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &policy_config_pda().0)
        .map(|(_, account)| account.clone())
        .expect("policy config account");
    assert_eq!(written.owner, program_id());
    let config: &PolicyConfig = bytemuck::from_bytes(&written.data);
    assert_eq!(config.discriminator, POLICY_CONFIG);
    let sources = common::own_source_slots();
    assert_eq!(config.sources, sources);
    assert_eq!(config.policy_hash, common::policy_hash_for(&sources));
    assert_eq!(config.records_tree.to_bytes(), records_tree().to_bytes());
    assert_eq!(config.records_bump, records_pda().1);
}

#[test]
fn a_records_tree_owned_by_another_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_policy_fixture();
    let mut foreign = records_tree_account();
    foreign.owner = program_id();
    fixture.set_account("records_tree", foreign);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidRecordsTree));
}

#[test]
fn a_records_tree_without_the_tree_discriminator_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let mut fixture = create_policy_fixture();
    let mut wrong = records_tree_account();
    wrong.data[0] = 0;
    fixture.set_account("records_tree", wrong);
    fixture.expect_err(&mollusk, custom(CustomRingError::InvalidRecordsTree));
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
    let result = mollusk.process_instruction(fixture.instruction(), fixture.accounts());
    assert_ne!(result.program_result, ProgramResult::Success);
}
