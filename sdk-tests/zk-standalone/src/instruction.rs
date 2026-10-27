//! The one instruction of the verifier program: verify a withdrawal proof.

use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use spr_zk_dsl::CompressedProof;

use crate::verifier::withdrawal;

/// Compressed proof (a, b, c) followed by the public inputs: the commitment,
/// the amount (little-endian) and the destination.
pub const WITHDRAWAL_DATA_LEN: usize = 32 + 64 + 32 + 32 + 8 + 32;

/// The instruction data verifying `proof` for `public_inputs`.
pub fn withdrawal_data(
    proof: &CompressedProof,
    public_inputs: &withdrawal::PublicInputs,
) -> [u8; WITHDRAWAL_DATA_LEN] {
    let mut data = [0u8; WITHDRAWAL_DATA_LEN];
    let fields: [&[u8]; 6] = [
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs.commitment,
        &public_inputs.amount.to_le_bytes(),
        &public_inputs.destination,
    ];
    let mut rest = data.as_mut_slice();
    for field in fields {
        let (head, tail) = rest.split_at_mut(field.len());
        head.copy_from_slice(field);
        rest = tail;
    }
    data
}

pub fn process_instruction(
    _program_id: &Address,
    _accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (proof, public_inputs) =
        parse(instruction_data).ok_or(ProgramError::InvalidInstructionData)?;
    withdrawal::verify(&proof, &public_inputs).map_err(|_| ProgramError::InvalidArgument)
}

fn parse(data: &[u8]) -> Option<(CompressedProof, withdrawal::PublicInputs)> {
    let (a, data) = data.split_first_chunk::<32>()?;
    let (b, data) = data.split_first_chunk::<64>()?;
    let (c, data) = data.split_first_chunk::<32>()?;
    let (commitment, data) = data.split_first_chunk::<32>()?;
    let (amount, data) = data.split_first_chunk::<8>()?;
    let (destination, data) = data.split_first_chunk::<32>()?;
    data.is_empty().then_some((
        CompressedProof {
            a: *a,
            b: *b,
            c: *c,
        },
        withdrawal::PublicInputs {
            commitment: *commitment,
            amount: u64::from_le_bytes(*amount),
            destination: *destination,
        },
    ))
}
