//! Batch incarnation of escrow: compose hub (no solo verify).

use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::TimelockEscrowError,
    instructions::{
        escrow::EscrowIxData,
        shared::{compose_ix_data, cpi_spp_compose_signed},
    },
};

#[inline(never)]
#[profile]
pub fn process_escrow_batch_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("creator")?;

    let EscrowIxData { proof, transact } = wincode::deserialize_exact(data)
        .map_err(|_| TimelockEscrowError::InvalidInstructionData)?;

    let foreign_pi = transact.private_tx_hash;
    let transact_bytes = transact
        .serialize()
        .map_err(|_| TimelockEscrowError::InvalidInstructionData)?;
    let compose = compose_ix_data(
        &foreign_pi,
        &proof.proof_a,
        &proof.proof_b,
        &proof.proof_c,
        &transact_bytes,
    );
    cpi_spp_compose_signed(iter.remaining()?, &compose)
}
