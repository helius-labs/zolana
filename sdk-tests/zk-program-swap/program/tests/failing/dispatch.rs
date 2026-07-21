use mollusk_solana_instruction::Instruction;
use mollusk_solana_program_error::ProgramError;
use zolana_mollusk_harness::expect_err_atomic;

use crate::common::setup_mollusk;

#[test]
fn missing_instruction_tag_is_rejected_exactly_and_atomically() {
    let (mollusk, program_id) = setup_mollusk();
    let instruction = Instruction {
        program_id,
        accounts: Vec::new(),
        data: Vec::new(),
    };
    expect_err_atomic(
        &mollusk,
        &instruction,
        &[],
        ProgramError::InvalidInstructionData,
    );
}

#[test]
fn unknown_instruction_tag_is_rejected_exactly_and_atomically() {
    let (mollusk, program_id) = setup_mollusk();
    let instruction = Instruction {
        program_id,
        accounts: Vec::new(),
        data: vec![0xff],
    };
    expect_err_atomic(
        &mollusk,
        &instruction,
        &[],
        ProgramError::InvalidInstructionData,
    );
}
