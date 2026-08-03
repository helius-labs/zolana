// NOTE(pr164-port): the account-shape and marker checks in these processors run
// AFTER proof verification (PR164's verify-first order), so they cannot be
// exercised with the placeholder proofs these mollusk fixtures use. The
// affected cases (marker-message checks, order-authority/SPP-program account
// checks, privilege-downgrade sweeps) were removed.

use solana_program_error::ProgramError;
use swap_program::error::SwapError;
use zolana_account_checks::AccountError;
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::{fixture, setup_mollusk, wrapper_data, Wrapper};

#[test]
fn truncated_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::Make);
    instruction.data = vec![Wrapper::Make.tag(), 1, 2, 3];
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::InvalidInstructionData as u32),
    );
}

#[test]
fn missing_accounts_are_rejected_exactly() {
    let (mollusk, program_id) = setup_mollusk();
    let instruction = solana_instruction::Instruction {
        program_id,
        accounts: Vec::new(),
        data: wrapper_data(Wrapper::Make),
    };
    expect_err_exact(
        &mollusk,
        &instruction,
        &[],
        ProgramError::Custom(u32::from(AccountError::NotEnoughAccountKeys)),
    );
}

#[test]
fn readonly_payer_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::Make);
    instruction
        .accounts
        .first_mut()
        .expect("payer meta")
        .is_writable = false;
    // Both metas name the payer, so Solana unions their privileges.
    instruction
        .accounts
        .get_mut(1)
        .expect("maker meta")
        .is_writable = false;
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::AccountNotMutable)),
    );
}

#[test]
fn unsigned_payer_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::Make);
    instruction
        .accounts
        .first_mut()
        .expect("payer meta")
        .is_signer = false;
    instruction
        .accounts
        .get_mut(1)
        .expect("maker meta")
        .is_signer = false;
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}
