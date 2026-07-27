//! Batch incarnation of settle: same state close, compose hub for proofs.

use light_program_profiler::profile;
use pinocchio::{address::address_eq, error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::DynamicSwapError,
    instructions::{
        settle::{SettleIxData, SettlePublicInput},
        shared::{compose_ix_data, cpi_spp_compose_signed},
    },
    state::{load_escrow_mut, load_pair},
};

#[inline(never)]
#[profile]
pub fn process_settle_batch_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    iter.next_signer_mut("caller")?;
    let pair_account = iter.next_account("pair")?;
    let escrow_account = iter.next_mut("escrow")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;

    let SettleIxData { proof, transact } =
        wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    let pair = *load_pair(pair_account)?;
    let pair_address = *pair_account.address();

    let escrow = *load_escrow_mut(escrow_account)?;
    if !address_eq(&escrow.pair, pair_account.address()) {
        return Err(DynamicSwapError::PairMismatch.into());
    }
    if !address_eq(&escrow.owner, rent_recipient.address()) {
        return Err(DynamicSwapError::RentRecipientMismatch.into());
    }

    let foreign_pi = SettlePublicInput {
        private_tx_hash: &transact.private_tx_hash,
        execution_price: escrow.execution_price,
        order_in_hash: &escrow.escrow_utxo_hash,
        reservation_in_hash: &escrow.reservation_utxo_hash,
        authority_owner_hash: &pair.authority_owner_hash,
    }
    .hash()?;

    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    let compose = compose_ix_data(
        &foreign_pi,
        &proof.proof_a,
        &proof.proof_b,
        &proof.proof_c,
        &transact_bytes,
    );

    let spp_accounts = iter.remaining()?;
    cpi_spp_compose_signed(
        &pair_address,
        crate::ESCROW_AUTHORITY_PDA_SEED,
        spp_accounts,
        &compose,
    )?;

    let rent_lamports = escrow_account.lamports();
    rent_recipient.set_lamports(
        rent_recipient
            .lamports()
            .checked_add(rent_lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?,
    );
    escrow_account.set_lamports(0);
    escrow_account.close()?;

    Ok(())
}
