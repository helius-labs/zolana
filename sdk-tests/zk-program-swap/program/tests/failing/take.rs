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
fn expired_take_is_rejected_exactly() {
    let (mut mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::Take);
    // Bind the relayer deadline below the warped clock so the window check is
    // the branch that fires.
    let mut data = transact(Vec::new());
    data.expiry_unix_ts = 5;
    instruction.data = wrapper_data_with(Wrapper::Take, data);
    mollusk.sysvars.clock.unix_timestamp = 6;
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::Expired as u32),
    );
}

#[test]
fn oversized_take_private_tx_hash_fails_hashing_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::Take);
    // 0xFF-filled bytes exceed the BN254 modulus, so the public-input Poseidon
    // hash fails before proof verification.
    let mut data = transact(Vec::new());
    data.private_tx_hash = [0xFF; 32];
    instruction.data = wrapper_data_with(Wrapper::Take, data);
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
    let (mut instruction, accounts) = fixture(Wrapper::Take);
    instruction.data = vec![Wrapper::Take.tag(), 1, 2, 3];
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::InvalidInstructionData as u32),
    );
}
