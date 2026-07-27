//! Batch incarnation of cancel: compose hub.

use light_program_profiler::profile;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_hasher::primitives::hash_bytes;

use crate::{
    error::SwapError,
    instructions::{
        cancel::{CancelIxData, CancelPublicInput},
        shared::{check_after_window, compose_ix_data, cpi_spp_compose_signed},
    },
};

#[inline(never)]
#[profile]
pub fn process_cancel_batch_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("payer")?;
    let maker_owner_pk_field =
        hash_bytes(iter.next_signer("maker")?.address().as_array()).map_err(SwapError::from)?;

    let CancelIxData {
        proof,
        order_expiry,
        transact,
    } = wincode::deserialize_exact(data).map_err(|_| SwapError::InvalidInstructionData)?;

    let clock = Clock::get()?;
    check_after_window(clock.unix_timestamp, order_expiry)?;

    let foreign_pi = CancelPublicInput {
        private_tx_hash: &transact.private_tx_hash,
        expiry: order_expiry,
        maker_owner_pk_field: &maker_owner_pk_field,
    }
    .hash()?;

    let transact_bytes = transact
        .serialize()
        .map_err(|_| SwapError::InvalidInstructionData)?;
    let compose = compose_ix_data(
        &foreign_pi,
        &proof.proof_a,
        &proof.proof_b,
        &proof.proof_c,
        &transact_bytes,
    );
    cpi_spp_compose_signed(iter.remaining()?, &compose)
}
