use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{
    error::SwapError,
    instructions::{
        shared::{check_within_window, cpi_spp_transact_signed, u64_right_align},
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TakeProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TakeIxData {
    pub proof: TakeProof,
    pub transact: TransactIxData,
}

pub struct TakePublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub expiry: u64,
}

impl TakePublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        Poseidon::hashv(&[
            self.private_tx_hash.as_slice(),
            u64_right_align(self.expiry).as_slice(),
        ])
        .map_err(|_| SwapError::HashingFailed.into())
    }
}

#[inline(never)]
#[profile]
pub fn process_take_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("payer")?;

    let TakeIxData { proof, transact } =
        wincode::deserialize_exact(data).map_err(|_| SwapError::InvalidInstructionData)?;

    let clock = Clock::get()?;
    check_within_window(clock.unix_timestamp, transact.expiry_unix_ts)?;

    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        TakePublicInput {
            private_tx_hash: &transact.private_tx_hash,
            expiry: transact.expiry_unix_ts,
        }
        .hash()?,
        &crate::verifying_keys::take::VERIFYINGKEY,
    )?;

    let transact_bytes = transact
        .serialize()
        .map_err(|_| SwapError::InvalidInstructionData)?;
    let spp_accounts = iter.remaining()?;
    cpi_spp_transact_signed(spp_accounts, &transact_bytes)
}
