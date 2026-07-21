use mollusk_solana_program_error::ProgramError;
use mollusk_solana_pubkey::Pubkey;
use swap_program::{
    error::SwapError,
    instructions::make::{MakeIxData, MakeProof, MARKER_PLACEHOLDER},
    tag,
};
use zolana_account_checks::AccountError;
use zolana_mollusk_harness::{expect_err_atomic, sweep_account_matrix, AccountMutation, Expected};

use crate::common::{account, fixture, marker, setup_mollusk, transact, wrapper_data, Wrapper};

#[test]
fn truncated_instruction_data_is_rejected_exactly_and_atomically() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::Make);
    instruction.data = vec![Wrapper::Make.tag(), 1, 2, 3];
    expect_err_atomic(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(SwapError::InvalidInstructionData as u32),
    );
}

fn assert_marker_messages(
    messages: Vec<zolana_interface::instruction::instruction_data::transact::MessageData>,
    expected: ProgramError,
) {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, accounts) = fixture(Wrapper::Make);
    let body = wincode::serialize(&MakeIxData {
        proof: MakeProof {
            proof_a: [10; 32],
            proof_b: [11; 64],
            proof_c: [12; 32],
        },
        transact: transact(messages),
    })
    .expect("serialize make");
    instruction.data = vec![tag::MAKE];
    instruction.data.extend_from_slice(&body);
    expect_err_atomic(&mollusk, &instruction, &accounts, expected);
}

#[test]
fn missing_marker_message_is_rejected_exactly_and_atomically() {
    assert_marker_messages(
        Vec::new(),
        ProgramError::Custom(SwapError::InvalidMarkerMessage as u32),
    );
}

#[test]
fn duplicate_marker_messages_are_rejected_exactly_and_atomically() {
    assert_marker_messages(
        vec![
            marker(MARKER_PLACEHOLDER.to_vec()),
            marker(MARKER_PLACEHOLDER.to_vec()),
        ],
        ProgramError::Custom(SwapError::InvalidMarkerMessage as u32),
    );
}

#[test]
fn non_placeholder_marker_bytes_are_rejected_exactly_and_atomically() {
    assert_marker_messages(
        vec![marker(vec![1; MARKER_PLACEHOLDER.len()])],
        ProgramError::Custom(SwapError::InvalidMarkerPlaceholder as u32),
    );
}

#[test]
fn wrong_length_marker_placeholder_is_rejected_exactly_and_atomically() {
    assert_marker_messages(
        vec![marker(vec![0; 1])],
        ProgramError::Custom(SwapError::InvalidMarkerPlaceholder as u32),
    );
}

#[test]
fn wrong_shielded_pool_program_is_rejected_exactly_and_atomically() {
    let (mollusk, _) = setup_mollusk();
    let (mut instruction, mut accounts) = fixture(Wrapper::Make);
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
    let (instruction, mut accounts) = fixture(Wrapper::Make);
    accounts.last_mut().expect("SPP account").1.executable = false;
    expect_err_atomic(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::ProgramNotExecutable)),
    );
}

#[test]
fn missing_accounts_are_rejected_exactly_and_atomically() {
    let (mollusk, program_id) = setup_mollusk();
    let instruction = mollusk_solana_instruction::Instruction {
        program_id,
        accounts: Vec::new(),
        data: wrapper_data(Wrapper::Make),
    };
    expect_err_atomic(
        &mollusk,
        &instruction,
        &[],
        ProgramError::Custom(u32::from(AccountError::NotEnoughAccountKeys)),
    );
}

#[test]
fn make_rejects_every_account_privilege_downgrade() {
    let (mollusk, _) = setup_mollusk();
    let (instruction, accounts) = fixture(Wrapper::Make);
    // Metas: [0] payer (signer, writable), [1] payer duplicate (signer,
    // writable), [2] tree (writable), [3] SPP program. Positions 0 and 1 are
    // duplicate metas of one account, and the runtime takes the union of
    // duplicate-meta privileges, so downgrading either one alone keeps every
    // account check passing and the run fails only at the fixture's
    // placeholder proof. Tree mutability and the trailing SPP meta have
    // stable named errors; the remaining removals shift the account shape,
    // so only deterministic atomic rejection is pinned.
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
                SwapError::InvalidShieldedPoolProgram as u32,
            )),
            _ => Expected::Rejected,
        },
    );
}

#[test]
fn readonly_payer_is_rejected_exactly_and_atomically() {
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
    expect_err_atomic(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::AccountNotMutable)),
    );
}

#[test]
fn unsigned_payer_is_rejected_exactly_and_atomically() {
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
    expect_err_atomic(
        &mollusk,
        &instruction,
        &accounts,
        ProgramError::Custom(u32::from(AccountError::InvalidSigner)),
    );
}
