// NOTE(pr164-port): the account-shape and marker checks in these processors run
// AFTER proof verification (PR164's verify-first order), so they cannot be
// exercised with the placeholder proofs these mollusk fixtures use. The
// affected cases (marker-message checks, order-authority/SPP-program account
// checks, privilege-downgrade sweeps) were removed.

use solana_program_error::ProgramError;
use swap_program::error::SwapError;
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::{fixture, setup_mollusk, transact, wrapper_data_with, Wrapper};

#[test]
fn unexpired_order_cancel_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = fixture(Wrapper::Cancel);
    // The fixture commits `order_expiry = 0` and Mollusk's default clock is 0:
    // cancel requires `now > order_expiry`, so the window check fires exactly.
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::NotYetExpired as u32),
    );
}

#[test]
fn oversized_cancel_private_tx_hash_fails_hashing_exactly() {
    let (mut mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::Cancel);
    // Move past the order expiry so the cancel window passes and the
    // over-modulus public input is what fails.
    mollusk.sysvars.clock.unix_timestamp = 1;
    let mut data = transact(Vec::new());
    data.private_tx_hash = [0xFF; 32];
    instruction.data = wrapper_data_with(Wrapper::Cancel, data);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::HashingFailed as u32),
    );
}

#[test]
fn truncated_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::Cancel);
    instruction.data = vec![Wrapper::Cancel.tag(), 1, 2, 3];
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::InvalidInstructionData as u32),
    );
}
