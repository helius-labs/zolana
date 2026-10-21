use custom_ring_interface::{
    key_catalog::RingCircuit, verifying_key, CustomRingError, CustomRingProof,
};
use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use pinocchio::ProgramResult;

pub(crate) fn ring_key(
    circuit: RingCircuit,
) -> Result<&'static Groth16Verifyingkey<'static>, CustomRingError> {
    verifying_key(circuit).ok_or(CustomRingError::UnsupportedCircuit)
}

#[must_use]
pub(crate) struct RingProof<'a> {
    pub proof: &'a CustomRingProof,
    pub statement: [u8; 32],
    pub key: &'a Groth16Verifyingkey<'a>,
}

impl RingProof<'_> {
    /// Every ring key carries a BSB22 commitment, a proof without one never verifies.
    #[inline(never)]
    pub fn verify(self) -> ProgramResult {
        let points = &self.proof.groth16;
        Groth16Verifier::new_with_commitment(
            &decompress_g1(&points.proof_a).map_err(failed)?,
            &decompress_g2(&points.proof_b).map_err(failed)?,
            &decompress_g1(&points.proof_c).map_err(failed)?,
            &decompress_g1(&self.proof.commitment).map_err(failed)?,
            &decompress_g1(&self.proof.commitment_pok).map_err(failed)?,
            &[self.statement],
            self.key,
        )
        .map_err(failed)?
        .verify()
        .map_err(failed)?;
        Ok(())
    }
}

fn failed<E>(_: E) -> CustomRingError {
    CustomRingError::ProofVerificationFailed
}
