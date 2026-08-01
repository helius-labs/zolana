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
    // The last output must carry the 71-byte destination ciphertext (checked
    // before the proof runs), so the 0xFF commitment is the first point the
    // verifier fails to decompress.
    let mut t = transact(Vec::new());
    if let Some(last) = t.outputs.last_mut() {
        last.data = Some(vec![8; 71]);
    }
    let body = TakeVerifiableEncryptionIxData {
        proof: TakeVerifiableEncryptionProof {
            proof_a: [0; 32],
            proof_b: [0; 64],
            proof_c: [0; 32],
            commitment: [0xFF; 32],
            commitment_pok: [0xFF; 32],
        },
        transact: t,
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
