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
///
/// The verifying key and the registry spec must name the same circuit. Every
/// caller resolves them from one selector, so the two cannot disagree.
pub struct Groth16Statement<'a> {
    pub proof: CompressedGroth16Proof<'a>,
    pub public_input_hash: [u8; 32],
    pub verifying_key: &'a Groth16Verifyingkey<'a>,
    pub encoding_err: ShieldedPoolError,
    pub verify_err: ShieldedPoolError,
}

impl Groth16Statement<'_> {
    /// Settle against the compile-time verifying key.
    #[inline(never)]
    #[profile]
    pub fn verify(self) -> ProgramResult {
        self.settle(None)
    }

    /// Settle against a finalized VK-registry account's prepared operands.
    /// `None` falls back to [`Self::verify`]. The spec's address is the entire
    /// provenance of the prepared blobs, and the syscalls validate their
    /// encoding.
    #[cfg(feature = "vk-registry")]
    #[inline(never)]
    #[profile]
    pub fn verify_registered(
        self,
        registry: Option<&pinocchio::AccountView>,
        spec: &zolana_interface::verifying_keys::registry_spec::VkRegistrySpec,
    ) -> ProgramResult {
        let Some(registry) = registry else {
            return self.verify();
        };
        let data = crate::instructions::vk_registry::load_finalized_vk_registry(registry, spec)?;
        let refs = crate::instructions::vk_registry::prepared_vk_refs(&data, spec)?;
        self.settle(Some(&refs))
    }

    /// A proof and a key must agree on whether a BSB22 commitment exists. A
    /// mismatch would otherwise verify a commitment nothing constrains.
    fn settle(
        self,
        #[cfg(feature = "vk-registry")] prepared: Option<
            &groth16_solana::groth16::PreparedVkRefs<'_>,
        >,
        #[cfg(not(feature = "vk-registry"))] prepared: Option<&core::convert::Infallible>,
    ) -> ProgramResult {
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
        match prepared {
            None => verifier.verify().map_err(|_| verify_err)?,
            #[cfg(feature = "vk-registry")]
            Some(refs) => verifier.verify_prepared(refs).map_err(|_| verify_err)?,
            #[cfg(not(feature = "vk-registry"))]
            Some(never) => match *never {},
        }
        Ok(())
    }
}
