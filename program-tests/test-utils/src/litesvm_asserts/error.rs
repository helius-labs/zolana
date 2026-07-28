use solana_instruction_error::InstructionError;
use solana_transaction_error::TransactionError;
use zolana_program_test::ProgramTestError;

#[track_caller]
pub fn assert_custom(err: ProgramTestError, code: u32) {
    assert_instruction_error(err, InstructionError::Custom(code));
}

#[track_caller]
pub fn assert_instruction_error(err: ProgramTestError, expected: InstructionError) {
    assert_instruction_error_at(err, 0, expected);
}

#[track_caller]
pub fn assert_instruction_error_at(
    err: ProgramTestError,
    instruction_index: u8,
    expected: InstructionError,
) {
    let ProgramTestError::TransactionFailure(failure) = err else {
        panic!("expected transaction failure {expected:?}, got {err:?}");
    };
    assert_eq!(
        failure.err,
        TransactionError::InstructionError(instruction_index, expected),
        "unexpected transaction failure; logs:\n{}",
        failure.meta.pretty_logs(),
    );
}
