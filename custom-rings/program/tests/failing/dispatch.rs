use custom_ring_interface::tag;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use zolana_account_checks::AccountError;
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::setup_mollusk;

#[test]
fn missing_instruction_tag_is_rejected_exactly() {
    let (mollusk, program_id) = setup_mollusk();
    let instruction = Instruction {
        program_id,
        accounts: Vec::new(),
        data: Vec::new(),
    };
    expect_err_exact(
        &mollusk,
        &instruction,
        &[],
        ProgramError::InvalidInstructionData,
    );
}

#[test]
fn unknown_instruction_tag_is_rejected_exactly() {
    let (mollusk, program_id) = setup_mollusk();
    let instruction = Instruction {
        program_id,
        accounts: Vec::new(),
        data: vec![0xff],
    };
    expect_err_exact(
        &mollusk,
        &instruction,
        &[],
        ProgramError::InvalidInstructionData,
    );
}

/// The account error proves the tag reached the processor.
#[test]
fn set_paused_tag_reaches_the_processor() {
    let (mollusk, program_id) = setup_mollusk();
    let instruction = Instruction {
        program_id,
        accounts: Vec::new(),
        data: vec![tag::SET_PAUSED, 1],
    };
    expect_err_exact(
        &mollusk,
        &instruction,
        &[],
        ProgramError::Custom(u32::from(AccountError::NotEnoughAccountKeys)),
    );
}
