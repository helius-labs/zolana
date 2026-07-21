use pinocchio::{error::ProgramError, Address};
use shielded_pool_program::{process_instruction, ID};
use zolana_interface::{error::ShieldedPoolError, instruction::tag};

#[test]
fn rejects_the_wrong_program_before_dispatch() {
    let wrong_program = Address::new_from_array([0u8; 32]);
    assert_eq!(
        process_instruction(&wrong_program, &mut [], &[tag::EMIT_EVENT]),
        Err(ProgramError::IncorrectProgramId)
    );
}

#[test]
fn rejects_empty_unknown_and_malformed_instruction_data_exactly() {
    assert_eq!(
        process_instruction(&ID, &mut [], &[]),
        Err(ProgramError::InvalidInstructionData)
    );
    assert_eq!(
        process_instruction(&ID, &mut [], &[255]),
        Err(ProgramError::InvalidInstructionData)
    );
    assert_eq!(
        process_instruction(&ID, &mut [], &[tag::DEPOSIT, 1, 2, 3]),
        Err(ProgramError::Custom(
            ShieldedPoolError::InvalidInstructionData as u32
        ))
    );
}

#[test]
fn valid_create_tree_payload_reaches_account_validation() {
    let mut data = vec![tag::CREATE_TREE];
    data.extend_from_slice(&[7u8; 32]);
    assert_eq!(
        process_instruction(&ID, &mut [], &data),
        Err(ProgramError::Custom(20_014))
    );
}

#[test]
fn emit_event_is_an_explicit_account_free_noop() {
    assert_eq!(
        process_instruction(&ID, &mut [], &[tag::EMIT_EVENT]),
        Ok(())
    );
}
