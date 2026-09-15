use custom_ring_interface::{CustomRingProof, PlainGroth16Proof};
use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use pinocchio::{error::ProgramError, ProgramResult};

use crate::error::CustomRingError;

const PROOF_ERR: CustomRingError = CustomRingError::ProofVerificationFailed;

/// Verify a proof over the single public input `public_input_hash`.
///
/// The proof and the key must agree on whether a BSB22 commitment is present:
/// a commitment-carrying key requires the Pedersen proof-of-knowledge pairing,
/// so accepting a commitment-less proof against it would skip a constraint the
/// circuit relies on. The mismatched combinations are therefore rejected rather
/// than coerced. Audited statements carry a BSB22 commitment over private wires.
#[inline(never)]
pub(crate) fn verify_groth16(
    proof: &CustomRingProof,
    public_input_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
) -> ProgramResult {
    let Groth16Points { a, b, c } = Groth16Points::decompress(&proof.groth16)?;
    let commitment = decompress_g1(&proof.commitment).map_err(|_| PROOF_ERR)?;
    let commitment_pok = decompress_g1(&proof.commitment_pok).map_err(|_| PROOF_ERR)?;
    let public_inputs = [public_input_hash];
    let mut verifier = Groth16Verifier::new_with_commitment(
        &a,
        &b,
        &c,
        &commitment,
        &commitment_pok,
        &public_inputs,
        verifying_key,
    )
    .map_err(|_| PROOF_ERR)?;
    verifier.verify().map_err(|_| PROOF_ERR)?;
    Ok(())
}

#[inline(never)]
pub(crate) fn verify_plain_groth16(
    proof: &PlainGroth16Proof,
    public_input_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
) -> ProgramResult {
    let Groth16Points { a, b, c } = Groth16Points::decompress(proof)?;
    let public_inputs = [public_input_hash];
    let mut verifier =
        Groth16Verifier::new(&a, &b, &c, &public_inputs, verifying_key).map_err(|_| PROOF_ERR)?;
    verifier.verify().map_err(|_| PROOF_ERR)?;
    Ok(())
}

struct Groth16Points {
    a: [u8; 64],
    b: [u8; 128],
    c: [u8; 64],
}

impl Groth16Points {
    fn decompress(proof: &PlainGroth16Proof) -> Result<Self, ProgramError> {
        Ok(Self {
            a: decompress_g1(&proof.proof_a).map_err(|_| PROOF_ERR)?,
            b: decompress_g2(&proof.proof_b).map_err(|_| PROOF_ERR)?,
            c: decompress_g1(&proof.proof_c).map_err(|_| PROOF_ERR)?,
        })
    }
}
