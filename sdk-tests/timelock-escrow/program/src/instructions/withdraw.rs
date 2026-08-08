use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_hasher::primitives::hash_bytes;
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

#[cfg(not(feature = "vk-registry"))]
use crate::instructions::verifier::verify_groth16;
use crate::{
    error::TimelockEscrowError,
    instructions::{
        shared::{check_after_window, cpi_spp_transact_signed, u64_right_align},
        verifier::CompressedGroth16Proof,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct WithdrawProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct WithdrawIxData {
    pub proof: WithdrawProof,
    /// The committed escrow `unlock` timestamp the withdraw proof reveals as a
    /// public input. Separate from `transact.expiry_unix_ts` (the SPP relayer
    /// deadline): withdraw requires `now > unlock`, which is necessarily in the
    /// past, whereas SPP rejects a `transact` whose `expiry_unix_ts` is in the
    /// past. The escrow's committed terms hash includes `unlock`; the proof
    /// recomputes it.
    pub unlock_timestamp: u64,
    pub transact: TransactIxData,
}

pub struct WithdrawPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub unlock: u64,
    pub owner_pk_field: &'a [u8; 32],
}

impl WithdrawPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        Poseidon::hashv(&[
            self.private_tx_hash.as_slice(),
            u64_right_align(self.unlock).as_slice(),
            self.owner_pk_field.as_slice(),
        ])
        .map_err(|_| TimelockEscrowError::HashingFailed.into())
    }
}

#[inline(never)]
#[profile]
pub fn process_withdraw_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("caller")?;
    // The creator signs the withdraw; the withdraw proof recomputes the
    // escrow's committed owner_hash from this pubkey (owner_pk_field), so only
    // the creator can withdraw and the creator knows the refund blinding it
    // chose.
    let owner_pk_field = hash_bytes(iter.next_signer("creator")?.address().as_array())
        .map_err(TimelockEscrowError::from)?;

    let WithdrawIxData {
        proof,
        unlock_timestamp,
        transact,
    } = wincode::deserialize_exact(data)
        .map_err(|_| TimelockEscrowError::InvalidInstructionData)?;

    let clock = Clock::get()?;
    check_after_window(clock.unix_timestamp, unlock_timestamp)?;

    let spp_accounts = iter.remaining()?;
    #[cfg(feature = "vk-registry")]
    let (vk_registry, spp_accounts) = crate::vk_registry::split_vk_registry(
        spp_accounts,
        &crate::vk_registry_specs::WITHDRAW_REGISTRY,
    );

    let proof = CompressedGroth16Proof {
        a: &proof.proof_a,
        b: &proof.proof_b,
        c: &proof.proof_c,
        commitment: None,
    };
    let public_input_hash = WithdrawPublicInput {
        private_tx_hash: &transact.private_tx_hash,
        unlock: unlock_timestamp,
        owner_pk_field: &owner_pk_field,
    }
    .hash()?;
    #[cfg(feature = "vk-registry")]
    crate::instructions::verifier::verify_groth16_registered(
        proof,
        public_input_hash,
        &crate::verifying_keys::withdraw::VERIFYINGKEY,
        vk_registry,
        &crate::vk_registry_specs::WITHDRAW_REGISTRY,
    )?;
    #[cfg(not(feature = "vk-registry"))]
    verify_groth16(
        proof,
        public_input_hash,
        &crate::verifying_keys::withdraw::VERIFYINGKEY,
    )?;

    let transact_bytes = transact
        .serialize()
        .map_err(|_| TimelockEscrowError::InvalidInstructionData)?;
    cpi_spp_transact_signed(spp_accounts, &transact_bytes)
}
