//! Ring-deposit forwarder negatives.
//!
//! The forwarder's only work is validation plus the CPI into SPP, which mollusk
//! cannot execute (SPP is not loaded here), so both assertable failures are
//! pre-CPI. The successful forward is covered by the localnet end-to-end test.

use custom_ring_program::error::CustomRingError;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::{deposit_fixture, setup_mollusk, substitute_account};

fn custom(error: CustomRingError) -> ProgramError {
    ProgramError::Custom(error as u32)
}

#[test]
fn impostor_shielded_pool_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = deposit_fixture();
    substitute_account(
        &mut instruction,
        &mut accounts,
        3,
        Pubkey::new_from_array([71; 32]),
    );
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::InvalidShieldedPoolProgram),
    );
}

#[test]
fn missing_ring_auth_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = deposit_fixture();
    substitute_account(
        &mut instruction,
        &mut accounts,
        2,
        Pubkey::new_from_array([72; 32]),
    );
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::MissingRingAuth),
    );
}
