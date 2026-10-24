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
        shared::{
            close_escrow_account, cpi_spp_transact_signed_multi, derive_authority_pda,
            pool_authority_owner_hash,
        },
        verifier::Groth16ProofBytes,
    },
    state::{load_escrow_mut, load_pair_mut},
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SettleIxData {
    /// `pool_settle` circuit proof (2-in: order UTXO, pool note / 3-out:
    /// recipient result, pool change, maker receipt). The circuit privately
    /// fills or refunds according to the order's committed minimum price.
    pub proof: Groth16ProofBytes,
    pub transact: TransactIxData,
}

/// Fills the order at the head of the pair's queue before expiry from the
/// pair's committed pool, closes it, and advances the head. Maker-only: the pair authority signs (only the maker holds the pool
/// notes' confidential data anyway), the payout is funded from a
/// pool_authority-owned note, the change re-locks under the pool_authority,
/// and the source-asset receipt goes to the pair's stored receipt owner-hash.
/// `available_liquidity` is untouched: the reservation taken at create_escrow
/// already charged `max_order_size`, and the unspent part stays in the change
/// note as surplus, publishable later through `rebalance_liquidity`.
#[inline(never)]
#[profile]
pub fn process_settle_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer_mut("authority")?;
    let pair_account = iter.next_mut("pair")?;
    let escrow_account = iter.next_mut("escrow")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;

    let SettleIxData { proof, transact } =
        wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    let pair = *load_pair_mut(pair_account)?;
    let pair_address = *pair_account.address();
    // Only the maker fills: the taker's paths are settle-by-maker before
    // expiry or unilateral cancel after.
    if !address_eq(&pair.authority, authority.address()) {
        return Err(DynamicSwapError::Unauthorized.into());
    }

    // Snapshot the escrow's fields and immediately drop the borrow so
    // `escrow_account` is free to be closed later in this same call.
    let escrow = *load_escrow_mut(escrow_account)?;
    // Bind escrow to this pair: the expiry window, the reservation counters,
    // and the destination-asset public input are pair fields, so a mismatched
    // pair account must be rejected.
    if !address_eq(&escrow.pair, pair_account.address()) {
        return Err(DynamicSwapError::PairMismatch.into());
    }
    // `rent_recipient` must be the escrow's `owner` (the taker, who paid the
    // escrow account rent). The confidential payout destination is not stored
    // on-chain at all -- it is re-opened in-circuit from the order UTXO's
    // composite DataHash.
    if !address_eq(&escrow.owner, rent_recipient.address()) {
        return Err(DynamicSwapError::RentRecipientMismatch.into());
    }
    // Orders fill in FIFO order: the maker cannot fill later orders while
    // leaving an unfavourable one to expire, because every later fill waits
    // for the head's settlement or expiry.
    if escrow.order_id != pair.head_order_id {
        return Err(DynamicSwapError::NotQueueHead.into());
    }
    // A cancelled order is already refunded; its account only marks the
    // queue position. Cancel requires expiry, so the window check below
    // rejects it too.
    if escrow.cancelled != 0 {
        return Err(DynamicSwapError::EscrowCancelled.into());
    }
    // Settle only inside the window; past it the escrow belongs to `cancel`.
    // The strict partition means settle and cancel can never race.
    let expires_at = escrow
        .created_at
        .checked_add(pair.expiry_slots)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if Clock::get()?.slot > expires_at {
        return Err(DynamicSwapError::Expired.into());
    }

    let pool_owner_hash = pool_authority_owner_hash(&pair_address)?;
    crate::verifier::pool_settle::Verifier {
        proof: &proof.to_compressed(),
        public_inputs: crate::verifier::pool_settle::PublicInputs {
            execution_price: escrow.execution_price,
            order_in_hash: escrow.order_utxo_hash,
            destination_asset: pair.destination_asset,
            pool_authority_owner_hash: pool_owner_hash,
            max_order_size: pair.max_order_size,
            receipt_owner_hash: pair.maker_receipt_owner_hash,
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

    // Release the reservation and advance the queue. `available_liquidity`
    // stays untouched: the pool dropped by owed while the bound already
    // dropped by max_order_size at creation, so the invariant holds with the
    // slack accumulating in the change note.
    {
        let mut pair_mut = load_pair_mut(pair_account)?;
        pair_mut.open_reservations = pair_mut
            .open_reservations
            .checked_sub(1)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        pair_mut.head_order_id = escrow
            .order_id
            .checked_add(1)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    // Both PDAs must sign the CPI: the escrow_authority owns the spent order
    // input, the pool_authority owns the spent pool input and authorizes the
    // data-bearing pool change output.
    let (escrow_pda, escrow_bump) =
        derive_authority_pda(crate::ESCROW_AUTHORITY_PDA_SEED, &pair_address);
    let (pool_pda, pool_bump) = derive_authority_pda(crate::POOL_AUTHORITY_PDA_SEED, &pair_address);
    let spp_accounts = iter.remaining()?;
    cpi_spp_transact_signed_multi(
        spp_accounts,
        &transact_bytes,
        &[
            (
                crate::ESCROW_AUTHORITY_PDA_SEED,
                pair_address,
                escrow_pda,
                escrow_bump,
            ),
            (
                crate::POOL_AUTHORITY_PDA_SEED,
                pair_address,
                pool_pda,
                pool_bump,
            ),
        ],
    )?;

    close_escrow_account(escrow_account, rent_recipient)
}
