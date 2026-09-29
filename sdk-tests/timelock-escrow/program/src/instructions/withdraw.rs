use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_hasher::primitives::solana_owner_identity;
use zolana_hasher::{Hasher, Poseidon};

use crate::{
    error::TimelockEscrowError,
    instructions::{
        shared::{check_after_window, u64_right_align, EscrowAuthority},
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    spp::ProvenTransact,
};

pub mod slot {
    pub const ESCROW: usize = 0;
    pub const SOURCE_OUTPUT: usize = 0;
}

pub const N_INPUTS: usize = 1;
pub const N_OUTPUTS: usize = 1;

pub type WithdrawTransact = ProvenTransact<N_INPUTS, N_OUTPUTS>;

pub fn owner_tags(creator: &Address) -> [[u8; 32]; N_OUTPUTS] {
    let mut owner_tags = [[0u8; 32]; N_OUTPUTS];
    owner_tags[slot::SOURCE_OUTPUT] = creator.to_bytes();
    owner_tags
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct WithdrawProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct WithdrawIxData {
    pub proof: WithdrawProof,
    pub unlock_timestamp: u64,
    pub transact: WithdrawTransact,
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
    let creator = *iter.next_signer("creator")?.address();
    let owner_pk_field =
        solana_owner_identity(creator.as_array()).map_err(TimelockEscrowError::from)?;

    let WithdrawIxData {
        proof,
        unlock_timestamp,
        transact,
    } = wincode::deserialize_exact(data)
        .map_err(|_| TimelockEscrowError::InvalidInstructionData)?;

    let clock = Clock::get()?;
    check_after_window(clock.unix_timestamp, unlock_timestamp)?;

    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        WithdrawPublicInput {
            private_tx_hash: &transact.private_tx_hash,
            unlock: unlock_timestamp,
            owner_pk_field: &owner_pk_field,
        }
        .hash()?,
        &crate::verifying_keys::withdraw::VERIFYINGKEY,
    )?;

    let authority = EscrowAuthority::find();
    let transact = transact.into_ix_data(owner_tags(&creator));
    let spp_accounts = iter.remaining()?;
    authority.invoke_transact(spp_accounts, &transact)
}
