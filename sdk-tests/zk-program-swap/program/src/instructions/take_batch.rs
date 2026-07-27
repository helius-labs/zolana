//! Batch incarnation of take: compose hub (no in-program solo verify).
//! SPP accounts: [foreign_vk, ...transact accounts].

use light_program_profiler::profile;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::{
    error::SwapError,
    instructions::{
        shared::{check_within_window, compose_ix_data, cpi_spp_compose_signed},
        take::{TakeIxData, TakePublicInput},
    },
};

#[inline(never)]
#[profile]
pub fn process_take_batch_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("payer")?;

    let TakeIxData { proof, transact } =
        wincode::deserialize_exact(data).map_err(|_| SwapError::InvalidInstructionData)?;

    let clock = Clock::get()?;
    check_within_window(clock.unix_timestamp, transact.expiry_unix_ts)?;

    let foreign_pi = TakePublicInput {
        private_tx_hash: &transact.private_tx_hash,
        expiry: transact.expiry_unix_ts,
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
