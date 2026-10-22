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
            &decompress_g1(&points.proof_a).map_err(undecodable)?,
            &decompress_g2(&points.proof_b).map_err(undecodable)?,
            &decompress_g1(&points.proof_c).map_err(undecodable)?,
            &decompress_g1(&self.proof.commitment).map_err(undecodable)?,
            &decompress_g1(&self.proof.commitment_pok).map_err(undecodable)?,
            &[self.statement],
            self.key,
        )
        .map_err(|_| CustomRingError::UnsupportedCircuit)?
        .verify()
        .map_err(|_| CustomRingError::ProofVerificationFailed)?;
        Ok(())
    }
}

fn undecodable<E>(_: E) -> CustomRingError {
    CustomRingError::InvalidRingProofPoint
}

#[cfg(test)]
mod tests {
    use bytemuck::Zeroable;

    use super::*;

    fn verify(proof: &CustomRingProof, key: &Groth16Verifyingkey<'_>) -> ProgramResult {
        RingProof {
            proof,
            statement: [7; 32],
            key,
        }
        .verify()
    }

    #[test]
    fn each_proof_stage_fails_with_its_own_code() {
        let key = ring_key(RingCircuit::RegisterKey).unwrap();
        let identity = CustomRingProof::zeroed();
        assert_eq!(
            verify(&identity, key),
            Err(CustomRingError::ProofVerificationFailed.into())
        );
        let mut off_curve = identity;
        off_curve.groth16.proof_a = [0x10; 32];
        assert_eq!(
            verify(&off_curve, key),
            Err(CustomRingError::InvalidRingProofPoint.into())
        );
        let without_commitment = Groth16Verifyingkey {
            nr_pubinputs: key.nr_pubinputs,
            vk_alpha_g1: key.vk_alpha_g1,
            vk_beta_g2: key.vk_beta_g2,
            vk_gamma_g2: key.vk_gamma_g2,
            vk_delta_g2: key.vk_delta_g2,
            vk_ic: key.vk_ic,
            vk_commitment: None,
        };
        assert_eq!(
            verify(&identity, &without_commitment),
            Err(CustomRingError::UnsupportedCircuit.into())
        );
    }
}
