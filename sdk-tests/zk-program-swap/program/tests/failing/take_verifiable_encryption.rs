use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use swap_program::error::SwapError;
use zolana_account_checks::AccountError;
use zolana_test_utils::mollusk::{
    expect_err_exact, sweep_account_matrix, AccountMutation, Expected,
};

use crate::common::{account, fixture, setup_mollusk, transact, wrapper_data_with, Wrapper};

#[test]
fn expired_take_verifiable_encryption_is_rejected_exactly() {
    let (mut mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::TakeVerifiableEncryption);
    let mut data = transact(Vec::new());
    data.expiry_unix_ts = 5;
    instruction.data = wrapper_data_with(Wrapper::TakeVerifiableEncryption, data);
    mollusk.sysvars.clock.unix_timestamp = 6;
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::Expired as u32),
    );
}

#[test]
fn garbage_commitment_is_rejected_exactly() {
    use swap_program::instructions::take_verifiable_encryption::{
        TakeVerifiableEncryptionIxData, TakeVerifiableEncryptionProof,
    };
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::TakeVerifiableEncryption);
    // Zeroed a/b/c decompress (to the identity), so the 0xFF commitment is the
    // first point the verifier fails to decompress: this exercises the BSB22
    // commitment path itself, not the plain proof points.
    let body = TakeVerifiableEncryptionIxData {
        proof: TakeVerifiableEncryptionProof {
            proof_a: [0; 32],
            proof_b: [0; 64],
            proof_c: [0; 32],
            commitment: [0xFF; 32],
            commitment_pok: [0xFF; 32],
        },
        transact: transact(Vec::new()),
    };
    let mut data = vec![Wrapper::TakeVerifiableEncryption.tag()];
    data.extend_from_slice(&wincode::serialize(&body).expect("serialize tve body"));
    instruction.data = data;
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::ProofVerificationFailed as u32),
    );
}

#[test]
fn missing_destination_ciphertext_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::TakeVerifiableEncryption);
    // Wire-valid transact whose final output carries no data slot: the TVE
    // rail requires the verifiable destination ciphertext there.
    let mut data = transact(Vec::new());
    data.outputs.last_mut().expect("destination output").data = None;
    instruction.data = wrapper_data_with(Wrapper::TakeVerifiableEncryption, data);
    expect_err_exact(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::InvalidInstructionData as u32),
    );
}

#[test]
fn truncated_instruction_data_is_rejected_exactly() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::TakeVerifiableEncryption);
    instruction.data = vec![Wrapper::TakeVerifiableEncryption.tag(), 1, 2, 3];
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
    let (mut instruction, mut accounts) = fixture(Wrapper::TakeVerifiableEncryption);
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
    let (instruction, mut accounts) = fixture(Wrapper::TakeVerifiableEncryption);
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
    let (mut instruction, mut accounts) = fixture(Wrapper::TakeVerifiableEncryption);
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
    let (mut instruction, accounts) = fixture(Wrapper::TakeVerifiableEncryption);
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
fn take_verifiable_encryption_rejects_every_account_privilege_downgrade() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = fixture(Wrapper::TakeVerifiableEncryption);
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
