use custom_ring_program::tag;
use pinocchio::Address;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
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

/// The runtime never routes an instruction to the wrong program, so this branch
/// is unreachable through mollusk; call the dispatcher directly instead of
/// leaving the guard untested.
#[test]
fn foreign_program_id_is_rejected() {
    let foreign = Address::new_from_array([9u8; 32]);
    assert_eq!(
        custom_ring_program::process_instruction(&foreign, &mut [], &[tag::CREATE_CONFIG]),
        Err(pinocchio::error::ProgramError::IncorrectProgramId),
    );
}
