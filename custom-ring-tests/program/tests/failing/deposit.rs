//! Ring-deposit forwarder negatives.
//!
//! The forwarder's only work is validation plus the CPI into SPP, which mollusk
//! cannot execute (SPP is not loaded here), so every assertable failure is
//! pre-CPI. The successful forward is covered by the localnet end-to-end test.

use custom_ring_program::error::CustomRingError;
use pinocchio::cpi::MAX_CPI_ACCOUNTS;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use zolana_test_utils::mollusk::expect_err_exact;

use crate::common::{account, deposit_fixture, setup_mollusk, substitute_account};

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

/// The forwarder names the runtime's CPI account limit instead of surfacing the
/// loader's opaque `InvalidArgument`.
#[test]
fn oversized_account_list_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = deposit_fixture();
    // Filler addresses start above every address the fixture already uses.
    let mut filler = 100u8;
    while instruction.accounts.len() <= MAX_CPI_ACCOUNTS {
        filler += 1;
        let key = Pubkey::new_from_array([filler; 32]);
        instruction
            .accounts
            .push(AccountMeta::new_readonly(key, false));
        accounts.push((key, account(1_000_000_000)));
    }
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        custom(CustomRingError::TooManyAccounts),
    );
}
