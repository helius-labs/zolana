use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use light_program_profiler::profile;
use pinocchio::ProgramResult;
use zolana_interface::error::ShieldedPoolError;

pub struct CompressedGroth16Proof<'a> {
    pub a: &'a [u8; 32],
    pub b: &'a [u8; 64],
    pub c: &'a [u8; 32],
    pub commitment: Option<(&'a [u8; 32], &'a [u8; 32])>,
}

/// One Groth16 statement the program is about to settle.
pub struct Groth16Statement<'a> {
    pub proof: CompressedGroth16Proof<'a>,
    pub public_input_hash: [u8; 32],
    pub verifying_key: &'a Groth16Verifyingkey<'a>,
    pub encoding_err: ShieldedPoolError,
    pub verify_err: ShieldedPoolError,
}

impl Groth16Statement<'_> {
    /// A proof and a key must agree on whether a BSB22 commitment exists. A
    /// mismatch would otherwise verify a commitment nothing constrains.
    #[inline(never)]
    #[profile]
    pub fn verify(self) -> ProgramResult {
        let Groth16Statement {
            proof,
            public_input_hash,
            verifying_key,
            encoding_err,
            verify_err,
        } = self;
        let proof_a = decompress_g1(proof.a).map_err(|_| encoding_err)?;
        let proof_b = decompress_g2(proof.b).map_err(|_| encoding_err)?;
        let proof_c = decompress_g1(proof.c).map_err(|_| encoding_err)?;
        let public_inputs = [public_input_hash];

        let commitment = match (proof.commitment, verifying_key.vk_commitment.is_some()) {
            (Some((commitment, commitment_pok)), true) => Some((
                decompress_g1(commitment).map_err(|_| encoding_err)?,
                decompress_g1(commitment_pok).map_err(|_| encoding_err)?,
            )),
            (None, false) => None,
            _ => return Err(verify_err.into()),
        };
        let mut verifier = match &commitment {
            Some((commitment, commitment_pok)) => Groth16Verifier::new_with_commitment(
                &proof_a,
                &proof_b,
                &proof_c,
                commitment,
                commitment_pok,
                &public_inputs,
                verifying_key,
            )
            .map_err(|_| verify_err)?,
            None => {
                Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, verifying_key)
                    .map_err(|_| verify_err)?
            }
        };
        verifier.verify().map_err(|_| verify_err)?;
        Ok(())
    }
}

/// Registered verification against a finalized VK-registry account whose
/// address the caller has already matched to the circuit's spec. Borrows the
/// prepared blobs and the GT target in place; the syscalls validate their
/// encoding, the address commitment is the provenance.
#[cfg(feature = "vk-registry")]
#[inline(never)]
#[profile]
pub fn verify_groth16_registered(
    proof: CompressedGroth16Proof,
    public_input_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
    registry_data: &[u8],
    spec: &zolana_interface::verifying_keys::registry_spec::VkRegistrySpec,
    encoding_err: ShieldedPoolError,
    verify_err: ShieldedPoolError,
) -> ProgramResult {
    let refs = crate::instructions::vk_registry::prepared_vk_refs(registry_data, spec)?;

    let proof_a = decompress_g1(proof.a).map_err(|_| encoding_err)?;
    let proof_b = decompress_g2(proof.b).map_err(|_| encoding_err)?;
    let proof_c = decompress_g1(proof.c).map_err(|_| encoding_err)?;
    let public_inputs = [public_input_hash];

    match (proof.commitment, verifying_key.vk_commitment.is_some()) {
        (Some((commitment, commitment_pok)), true) => {
            let commitment = decompress_g1(commitment).map_err(|_| encoding_err)?;
            let commitment_pok = decompress_g1(commitment_pok).map_err(|_| encoding_err)?;
            let mut verifier = Groth16Verifier::new_with_commitment(
                &proof_a,
                &proof_b,
                &proof_c,
                &commitment,
                &commitment_pok,
                &public_inputs,
                verifying_key,
            )
            .map_err(|_| verify_err)?;
            verifier.verify_prepared(&refs).map_err(|_| verify_err)?;
        }
        (None, false) => {
            let mut verifier =
                Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, verifying_key)
                    .map_err(|_| verify_err)?;
            verifier.verify_prepared(&refs).map_err(|_| verify_err)?;
        }
        _ => return Err(verify_err.into()),
    }
    Ok(())
}
