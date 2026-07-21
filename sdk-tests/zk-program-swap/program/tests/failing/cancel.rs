use mollusk_solana_program_error::ProgramError;
use mollusk_solana_pubkey::Pubkey;
use swap_program::error::SwapError;
use zolana_account_checks::AccountError;
use zolana_mollusk_harness::{expect_err_atomic, sweep_account_matrix, AccountMutation, Expected};

use crate::common::{account, fixture, setup_mollusk, Wrapper};

#[test]
fn truncated_instruction_data_is_rejected_exactly_and_atomically() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::Cancel);
    instruction.data = vec![Wrapper::Cancel.tag(), 1, 2, 3];
    expect_err_atomic(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::InvalidInstructionData as u32),
    );
}

#[test]
fn wrong_shielded_pool_program_is_rejected_exactly_and_atomically() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = fixture(Wrapper::Cancel);
    let wrong_program = Pubkey::new_from_array([31; 32]);
    instruction.accounts.last_mut().expect("SPP meta").pubkey = wrong_program;
    *accounts.last_mut().expect("SPP account") = (wrong_program, account(1));
    expect_err_atomic(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::InvalidShieldedPoolProgram as u32),
    );
}

#[test]
fn non_executable_shielded_pool_program_is_rejected_exactly_and_atomically() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, mut accounts) = fixture(Wrapper::Cancel);
    accounts.last_mut().expect("SPP account").1.executable = false;
    expect_err_atomic(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::ProgramNotExecutable)),
    );
}

#[test]
fn wrong_order_authority_is_rejected_exactly_and_atomically() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = fixture(Wrapper::Cancel);
    let authority_index = instruction.accounts.len() - 2;
    let wrong = Pubkey::new_from_array([32; 32]);
    instruction
        .accounts
        .get_mut(authority_index)
        .expect("order authority meta")
        .pubkey = wrong;
    *accounts
        .get_mut(authority_index)
        .expect("order authority account") = (wrong, account(1_000_000_000));
    expect_err_atomic(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::MissingOrderAuthority as u32),
    );
}

#[test]
fn writable_order_authority_is_rejected_exactly_and_atomically() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::Cancel);
    let authority_index = instruction.accounts.len() - 2;
    instruction
        .accounts
        .get_mut(authority_index)
        .expect("order authority meta")
        .is_writable = true;
    expect_err_atomic(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::AccountMutable)),
    );
}

#[test]
fn cancel_rejects_every_account_privilege_downgrade() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = fixture(Wrapper::Cancel);
    // Metas: [0] payer (signer, writable), [1] maker (signer), [2] payer
    // duplicate (signer, writable), [3] tree (writable), [4] order
    // authority, [5] SPP program. Positions 0 and 2 are duplicate metas of
    // one account, and the runtime takes the union of duplicate-meta
    // privileges, so downgrading either one alone keeps every account check
    // passing and the run fails only at the fixture's unexpired order
    // window. The maker signer, tree mutability, order-authority, and
    // trailing SPP cells have stable named errors; the remaining removals
    // shift the account shape, so only deterministic atomic rejection is
    // pinned.
    sweep_account_matrix(
        &mollusk,
        &instruction,
        &accounts,
        |mutation| match mutation {
            AccountMutation::Unsign { index: 0 | 2 }
            | AccountMutation::Readonly { index: 0 | 2 } => {
                Expected::Err(ProgramError::Custom(SwapError::NotYetExpired as u32))
            }
            AccountMutation::Unsign { index: 1 } => {
                Expected::Err(ProgramError::Custom(u32::from(AccountError::InvalidSigner)))
            }
            AccountMutation::Readonly { index: 3 } => Expected::Err(ProgramError::Custom(
                u32::from(AccountError::AccountNotMutable),
            )),
            AccountMutation::Remove { index: 4 } => Expected::Err(ProgramError::Custom(
                SwapError::MissingOrderAuthority as u32,
            )),
            AccountMutation::Remove { index: 5 } => Expected::Err(ProgramError::Custom(
                SwapError::InvalidShieldedPoolProgram as u32,
            )),
            _ => Expected::Rejected,
        },
    );
}
