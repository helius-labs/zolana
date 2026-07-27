//! Batch incarnation of withdraw: compose hub.

use light_program_profiler::profile;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_hasher::primitives::hash_bytes;

use crate::{
    error::TimelockEscrowError,
    instructions::{
        shared::{check_after_window, compose_ix_data, cpi_spp_compose_signed},
        withdraw::{WithdrawIxData, WithdrawPublicInput},
    },
};

#[inline(never)]
#[profile]
pub fn process_withdraw_batch_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("caller")?;
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

    let foreign_pi = WithdrawPublicInput {
        private_tx_hash: &transact.private_tx_hash,
        unlock: unlock_timestamp,
        owner_pk_field: &owner_pk_field,
    }
    .hash()?;

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
