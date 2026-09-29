use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_hasher::{Hasher, Poseidon};

use crate::{
    error::TimelockEscrowError,
    instructions::{
        shared::EscrowAuthority,
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    spp::ProvenTransact,
    verifying_keys::escrow,
    ESCROW_OWNER_HASH,
};

pub mod slot {
    pub const SOURCE: usize = 0;
    pub const CHANGE: usize = 0;
    pub const ESCROW: usize = 1;
}

pub const N_INPUTS: usize = 2;
pub const N_OUTPUTS: usize = 2;

pub type EscrowTransact = ProvenTransact<N_INPUTS, N_OUTPUTS>;

pub fn owner_tags(creator: &Address, escrow_authority: &Address) -> [[u8; 32]; N_OUTPUTS] {
    let mut owner_tags = [[0u8; 32]; N_OUTPUTS];
    owner_tags[slot::CHANGE] = creator.to_bytes();
    owner_tags[slot::ESCROW] = escrow_authority.to_bytes();
    owner_tags
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct EscrowProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct EscrowIxData {
    pub proof: EscrowProof,
    pub transact: EscrowTransact,
}

pub struct EscrowPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub escrow_owner_hash: &'a [u8; 32],
}

impl EscrowPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        Poseidon::hashv(&[
            self.private_tx_hash.as_slice(),
            self.escrow_owner_hash.as_slice(),
        ])
        .map_err(|_| TimelockEscrowError::HashingFailed.into())
    }
}

#[inline(never)]
#[profile]
pub fn process_escrow_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let creator = *iter.next_signer_mut("creator")?.address();

    let EscrowIxData { proof, transact } = wincode::deserialize_exact(data)
        .map_err(|_| TimelockEscrowError::InvalidInstructionData)?;

    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        EscrowPublicInput {
            private_tx_hash: &transact.private_tx_hash,
            escrow_owner_hash: &ESCROW_OWNER_HASH,
        }
        .hash()?,
        &escrow::VERIFYINGKEY,
    )?;

    let authority = EscrowAuthority::find();
    let transact = transact.into_ix_data(owner_tags(&creator, authority.address()));
    let spp_accounts = iter.remaining()?;
    authority.invoke_transact(spp_accounts, &transact)
}
