use light_program_profiler::profile;
use pinocchio::{
    address::address_eq,
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{
    error::DynamicSwapError,
    instructions::{
        shared::{
            close_escrow_account, cpi_spp_transact_signed_multi, derive_authority_pda,
            pool_authority_owner_hash, u64_right_align,
        },
        verifier::{verify_groth16, CompressedGroth16Proof, Groth16ProofBytes},
    },
    state::{load_escrow_mut, load_pair_mut},
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SettleIxData {
    /// `pool_settle` circuit proof (2-in: order UTXO, pool note / 3-out:
    /// recipient payout, pool change, maker receipt). There is no refund
    /// branch: an escrow can only exist at an acceptable price (create_escrow
    /// checks max_price), so settle always settles; the alternative outcome is
    /// `cancel` after expiry.
    pub proof: Groth16ProofBytes,
    pub transact: TransactIxData,
}

/// `pool_settle`'s public-input hash: `Poseidon(PrivateTxHash, ExecutionPrice,
/// OrderInHash, DestinationAsset, PoolAuthorityOwnerHash, MaxOrderSize,
/// ReceiptOwnerHash)`. The recipient owner-hash is deliberately absent -- it is
/// re-opened in-circuit from the order UTXO's DataHash (pinned by
/// `OrderInHash`), which keeps the payout destination confidential.
/// `ExecutionPrice` is the escrow's stored price (always nonzero);
/// `PoolAuthorityOwnerHash` binds the pool input and change to program-locked
/// liquidity; `MaxOrderSize` enters the change note's booked clamp;
/// `ReceiptOwnerHash` fixes the maker receipt destination. Field order and
/// encoding must match the circuit's `PublicInputs.Check`.
pub struct SettlePublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub execution_price: u64,
    pub order_in_hash: &'a [u8; 32],
    pub destination_asset: &'a [u8; 32],
    pub pool_authority_owner_hash: &'a [u8; 32],
    pub max_order_size: u64,
    pub receipt_owner_hash: &'a [u8; 32],
}

impl SettlePublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        Poseidon::hashv(&[
            self.private_tx_hash.as_slice(),
            u64_right_align(self.execution_price).as_slice(),
            self.order_in_hash.as_slice(),
            self.destination_asset.as_slice(),
            self.pool_authority_owner_hash.as_slice(),
            u64_right_align(self.max_order_size).as_slice(),
            self.receipt_owner_hash.as_slice(),
        ])
        .map_err(|_| DynamicSwapError::HashingFailed.into())
    }
}

/// Fills one escrow before expiry from the pair's committed pool and closes
/// it. Maker-only: the pair authority signs (only the maker holds the pool
/// notes' confidential data anyway), the payout is funded from a
/// pool_authority-owned note, the change re-locks under the pool_authority,
/// and the source-asset receipt goes to the pair's stored receipt owner-hash.
/// `liquidity_bound` is untouched: the reservation taken at create_escrow
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
    // DataHash.
    if !address_eq(&escrow.owner, rent_recipient.address()) {
        return Err(DynamicSwapError::RentRecipientMismatch.into());
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
    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        SettlePublicInput {
            private_tx_hash: &transact.private_tx_hash,
            execution_price: escrow.execution_price,
            order_in_hash: &escrow.order_utxo_hash,
            destination_asset: &pair.destination_asset,
            pool_authority_owner_hash: &pool_owner_hash,
            max_order_size: pair.max_order_size,
            receipt_owner_hash: &pair.maker_receipt_owner_hash,
        }
        .hash()?,
        &crate::verifying_keys::pool_settle::VERIFYINGKEY,
    )?;

    // Release the reservation. `liquidity_bound` stays untouched: the pool
    // dropped by owed while the bound already dropped by max_order_size at
    // creation, so the invariant holds with the slack accumulating in the
    // change note.
    {
        let mut pair_mut = load_pair_mut(pair_account)?;
        pair_mut.open_reservations = pair_mut
            .open_reservations
            .checked_sub(1)
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
