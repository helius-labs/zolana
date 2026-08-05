use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

#[cfg(not(feature = "vk-registry"))]
use crate::instructions::verifier::verify_groth16;
use crate::{
    error::TimelockEscrowError,
    instructions::{shared::cpi_spp_transact_signed, verifier::CompressedGroth16Proof},
    verifying_keys::escrow,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct EscrowProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct EscrowIxData {
    pub proof: EscrowProof,
    pub transact: TransactIxData,
}

#[inline(never)]
#[profile]
pub fn process_escrow_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("creator")?;

    let EscrowIxData { proof, transact } = wincode::deserialize_exact(data)
        .map_err(|_| TimelockEscrowError::InvalidInstructionData)?;

    let spp_accounts = iter.remaining()?;
    #[cfg(feature = "vk-registry")]
    let (vk_registry, spp_accounts) = crate::vk_registry::split_vk_registry(
        spp_accounts,
        &crate::vk_registry_specs::ESCROW_REGISTRY,
    );

    let proof = CompressedGroth16Proof {
        a: &proof.proof_a,
        b: &proof.proof_b,
        c: &proof.proof_c,
        commitment: None,
    };
    #[cfg(feature = "vk-registry")]
    crate::instructions::verifier::verify_groth16_registered(
        proof,
        transact.private_tx_hash,
        &escrow::VERIFYINGKEY,
        vk_registry,
        &crate::vk_registry_specs::ESCROW_REGISTRY,
    )?;
    #[cfg(not(feature = "vk-registry"))]
    verify_groth16(proof, transact.private_tx_hash, &escrow::VERIFYINGKEY)?;

    let transact_bytes = transact
        .serialize()
        .map_err(|_| TimelockEscrowError::InvalidInstructionData)?;

    cpi_spp_transact_signed(spp_accounts, &transact_bytes)
}
