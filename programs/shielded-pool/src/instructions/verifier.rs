//! Shared Groth16 verification: solo path and batch incarnation (agave fold).
//! Standard Groth16 only — no BSB22 / Pedersen.

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use light_program_profiler::profile;
use pinocchio::ProgramResult;
use zolana_groth16_batch::{
    batch_verify_validated, batch_verify_wire, unpack_vk, vk_from_solana, WireProof,
};
use zolana_interface::error::ShieldedPoolError;

/// The compressed Groth16 proof points handed to [`verify_groth16`].
pub struct CompressedGroth16Proof<'a> {
    pub a: &'a [u8; 32],
    pub b: &'a [u8; 64],
    pub c: &'a [u8; 32],
}

/// One wire proof + public input for batch verify.
pub struct BatchProofItem {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
    pub public_input_hash: [u8; 32],
}

/// Decompress and verify one standard Groth16 proof.
#[inline(never)]
#[profile]
pub fn verify_groth16(
    proof: CompressedGroth16Proof,
    public_input_hash: [u8; 32],
    verifying_key: &Groth16Verifyingkey,
    encoding_err: ShieldedPoolError,
    verify_err: ShieldedPoolError,
) -> ProgramResult {
    if verifying_key.vk_commitment.is_some() {
        return Err(verify_err.into());
    }
    let proof_a = decompress_g1(proof.a).map_err(|_| encoding_err)?;
    let proof_b = decompress_g2(proof.b).map_err(|_| encoding_err)?;
    let proof_c = decompress_g1(proof.c).map_err(|_| encoding_err)?;
    let public_inputs = [public_input_hash];

    let mut verifier =
        Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, verifying_key)
            .map_err(|_| verify_err)?;
    verifier.verify().map_err(|_| verify_err)?;
    Ok(())
}

/// Same-vk RLC batch (agave fold).
#[inline(never)]
#[profile]
pub fn batch_verify_groth16(
    verifying_key: &Groth16Verifyingkey,
    items: &[BatchProofItem],
    encoding_err: ShieldedPoolError,
    verify_err: ShieldedPoolError,
) -> ProgramResult {
    if items.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let wire: Vec<_> = items
        .iter()
        .map(|i| {
            (
                WireProof {
                    a: i.a,
                    b: i.b,
                    c: i.c,
                },
                i.public_input_hash,
            )
        })
        .collect();
    match batch_verify_wire(verifying_key, &wire) {
        Ok(true) => Ok(()),
        Ok(false) => Err(verify_err.into()),
        Err(zolana_groth16_batch::WireError::Decompress) => Err(encoding_err.into()),
        Err(zolana_groth16_batch::WireError::CommittedUnsupported) => Err(verify_err.into()),
        Err(_) => Err(verify_err.into()),
    }
}

/// Hetero RLC: packed foreign VK bytes + SPP verifying key.
#[inline(never)]
#[profile]
pub fn batch_verify_compose(
    foreign_vk_bytes: &[u8],
    spp_vk: &Groth16Verifyingkey,
    foreign: &BatchProofItem,
    spp: &BatchProofItem,
    encoding_err: ShieldedPoolError,
    verify_err: ShieldedPoolError,
) -> ProgramResult {
    let foreign_vk = unpack_vk(foreign_vk_bytes).map_err(|_| encoding_err)?;
    let spp_validated = vk_from_solana(spp_vk).map_err(|_| verify_err)?;
    let items = [
        (
            0u16,
            WireProof {
                a: foreign.a,
                b: foreign.b,
                c: foreign.c,
            },
            foreign.public_input_hash,
        ),
        (
            1u16,
            WireProof {
                a: spp.a,
                b: spp.b,
                c: spp.c,
            },
            spp.public_input_hash,
        ),
    ];
    match batch_verify_validated(&[foreign_vk, spp_validated], &items) {
        Ok(true) => Ok(()),
        Ok(false) => Err(verify_err.into()),
        Err(zolana_groth16_batch::WireError::Decompress) => Err(encoding_err.into()),
        Err(zolana_groth16_batch::WireError::CommittedUnsupported) => Err(verify_err.into()),
        Err(_) => Err(verify_err.into()),
    }
}
