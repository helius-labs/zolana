use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use swap_program::error::SwapError;
use zolana_account_checks::AccountError;
use zolana_test_utils::mollusk::{
    expect_err_exact, sweep_account_matrix, AccountMutation, Expected,
};

use crate::common::{account, fixture, setup_mollusk, transact, wrapper_data_with, Wrapper};

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
fn writable_shielded_pool_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::Take);
    instruction
        .accounts
        .last_mut()
        .expect("SPP meta")
        .is_writable = true;
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::AccountMutable)),
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

#[test]
fn wrong_shielded_pool_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = fixture(Wrapper::Take);
    let wrong_program = Pubkey::new_from_array([31; 32]);
    instruction.accounts.last_mut().expect("SPP meta").pubkey = wrong_program;
    *accounts.last_mut().expect("SPP account") = (wrong_program, account(1));
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::InvalidShieldedPoolProgram as u32),
    );
}

#[test]
fn non_executable_shielded_pool_program_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, mut accounts) = fixture(Wrapper::Take);
    accounts.last_mut().expect("SPP account").1.executable = false;
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::ProgramNotExecutable)),
    );
}

#[test]
fn wrong_order_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = fixture(Wrapper::Take);
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
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::MissingOrderAuthority as u32),
    );
}

#[test]
fn writable_order_authority_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::Take);
    let authority_index = instruction.accounts.len() - 2;
    instruction
        .accounts
        .get_mut(authority_index)
        .expect("order authority meta")
        .is_writable = true;
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::AccountMutable)),
    );
}

#[test]
fn take_rejects_every_account_privilege_downgrade() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = fixture(Wrapper::Take);
    // Metas: [0] payer (signer, writable), [1] payer duplicate (signer,
    // writable), [2] tree (writable), [3] order authority, [4] SPP program.
    // Positions 0 and 1 are duplicate metas of one account, and the runtime
    // takes the union of duplicate-meta privileges, so downgrading either
    // one alone keeps every account check passing and the run fails only at
    // the fixture's placeholder proof. Tree mutability, the order-authority
    // meta, and the trailing SPP meta have stable named errors; the
    // remaining removals shift the account shape, so only deterministic
    // deterministic rejection is pinned.
    sweep_account_matrix(
        &mollusk,
        &instruction,
        &accounts,
        |mutation| match mutation {
            AccountMutation::Unsign { index: 0 | 1 }
            | AccountMutation::Readonly { index: 0 | 1 } => Expected::Err(ProgramError::Custom(
                SwapError::ProofVerificationFailed as u32,
            )),
            AccountMutation::Readonly { index: 2 } => Expected::Err(ProgramError::Custom(
                u32::from(AccountError::AccountNotMutable),
            )),
            AccountMutation::Remove { index: 3 } => Expected::Err(ProgramError::Custom(
                SwapError::MissingOrderAuthority as u32,
            )),
            AccountMutation::Remove { index: 4 } => Expected::Err(ProgramError::Custom(
                SwapError::InvalidShieldedPoolProgram as u32,
            )),
            _ => Expected::Rejected,
        },
    );
}

#[test]
fn reordered_payer_and_tree_are_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = fixture(Wrapper::Take);
    let spp_payer_index = 1;
    let tree_index = 2;
    instruction.accounts.swap(spp_payer_index, tree_index);
    accounts.swap(spp_payer_index, tree_index);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}
