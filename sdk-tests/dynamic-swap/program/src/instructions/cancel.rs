use light_program_profiler::profile;
use pinocchio::{
    address::address_eq,
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{
    error::DynamicSwapError,
    instructions::{
        shared::{close_escrow_account, cpi_spp_transact_signed},
        verifier::Groth16ProofBytes,
    },
    state::{load_escrow_mut, load_pair_mut},
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CancelIxData {
    /// `escrow_cancel` circuit proof (1-in: order UTXO / 1-out: refund). The
    /// full order amount returns, in the source asset, to the recipient
    /// committed together with the private minimum price as the order UTXO's
    /// DataHash.
    pub proof: Groth16ProofBytes,
    pub transact: TransactIxData,
}

/// Refunds one escrow after expiry. Permissionless: the caller only pays fees;
/// only a holder of the order UTXO data (the taker, or the maker via the
/// handoff) can build a valid proof, and the refund destination is fixed by
/// the proof.
///
/// An order behind the queue head closes. Cancelling the head advances it and
/// closes the account. An order ahead of the head stays as a cancellation
/// marker until `skip_expired` passes it, so the queue can advance past an
/// order that was refunded out of order.
#[inline(never)]
#[profile]
pub fn process_cancel_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    // Permissionless caller: signs and pays fees only (see doc above).
    iter.next_signer_mut("caller")?;
    let pair_account = iter.next_mut("pair")?;
    let escrow_account = iter.next_mut("escrow")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;

    let CancelIxData { proof, transact } =
        wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    let pair = *load_pair_mut(pair_account)?;
    let pair_address = *pair_account.address();

    // Snapshot the escrow's fields and immediately drop the borrow so
    // `escrow_account` is free to be closed later in this same call.
    let escrow = *load_escrow_mut(escrow_account)?;
    // Bind escrow to this pair before changing its reservation counters.
    if !address_eq(&escrow.pair, pair_account.address()) {
        return Err(DynamicSwapError::PairMismatch.into());
    }
    // `rent_recipient` must be the escrow's `owner` (the taker, who paid the
    // escrow account rent).
    if !address_eq(&escrow.owner, rent_recipient.address()) {
        return Err(DynamicSwapError::RentRecipientMismatch.into());
    }
    // A cancellation marker is already refunded.
    if escrow.cancelled != 0 {
        return Err(DynamicSwapError::EscrowCancelled.into());
    }
    // Cancel only past the window; inside it the escrow belongs to `settle`.
    // The strict partition means settle and cancel can never race.
    if Clock::get()?.slot <= escrow.expires_at {
        return Err(DynamicSwapError::NotYetExpired.into());
    }

    crate::verifier::escrow_cancel::Verifier {
        proof: &proof.to_compressed(),
        public_inputs: crate::verifier::escrow_cancel::PublicInputs {
            order_in_hash: escrow.order_utxo_hash,
            first_nullifier: transact
                .inputs
                .first()
                .ok_or(DynamicSwapError::InvalidInstructionData)?
                .nullifier_hash,
        },
        private_tx_hash: &transact.private_tx_hash,
        transfers: &[],
    }
    .verify()
    .map_err(|_| DynamicSwapError::ProofVerificationFailed)?;

    // Release the reservation in full: the order was never filled, so the
    // exact `max_order_size` taken at create_escrow returns to the bound.
    {
        let mut pair_mut = load_pair_mut(pair_account)?;
        pair_mut.available_liquidity = pair_mut
            .available_liquidity
            .checked_add(pair_mut.max_order_size)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        pair_mut.open_reservations = pair_mut
            .open_reservations
            .checked_sub(1)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        if escrow.order_id == pair.head_order_id {
            pair_mut.head_order_id = escrow
                .order_id
                .checked_add(1)
                .ok_or(ProgramError::ArithmeticOverflow)?;
        }
    }

    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    // The spent order input is owned by the escrow_authority PDA, the only
    // account flipped to a signer in the `transact` CPI.
    let spp_accounts = iter.remaining()?;
    cpi_spp_transact_signed(
        &pair_address,
        crate::ESCROW_AUTHORITY_PDA_SEED,
        spp_accounts,
        &transact_bytes,
    )?;

    if escrow.order_id <= pair.head_order_id {
        close_escrow_account(escrow_account, rent_recipient)
    } else {
        load_escrow_mut(escrow_account)?.cancelled = 1;
        Ok(())
    }
}
