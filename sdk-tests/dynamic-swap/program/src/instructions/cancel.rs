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
        shared::{close_escrow_account, cpi_spp_transact_signed},
        verifier::{verify_groth16, CompressedGroth16Proof, Groth16ProofBytes},
    },
    state::{load_escrow_mut, load_pair_mut},
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CancelIxData {
    /// `escrow_cancel` circuit proof (1-in: order UTXO / 1-out: refund). The
    /// full order amount returns, in the source asset, to the recipient
    /// committed as the order UTXO's DataHash.
    pub proof: Groth16ProofBytes,
    pub transact: TransactIxData,
}

/// `escrow_cancel`'s public-input hash: `Poseidon(PrivateTxHash, OrderInHash)`.
/// The recipient owner-hash is re-opened in-circuit from the order UTXO's
/// DataHash (pinned by `OrderInHash`), so the refund destination stays
/// confidential. Field order and encoding must match the circuit's
/// `PublicInputs.Check`.
pub struct CancelPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub order_in_hash: &'a [u8; 32],
}

impl CancelPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        Poseidon::hashv(&[
            self.private_tx_hash.as_slice(),
            self.order_in_hash.as_slice(),
        ])
        .map_err(|_| DynamicSwapError::HashingFailed.into())
    }
}

/// Refunds one escrow after expiry and closes it. Permissionless: the caller
/// only pays fees; only a holder of the order UTXO data (the taker, or the
/// maker via the handoff) can build a valid proof, and the refund destination
/// is fixed by the proof.
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
    // Bind escrow to this pair: the expiry window is a pair field, so a
    // mismatched pair account must be rejected.
    if !address_eq(&escrow.pair, pair_account.address()) {
        return Err(DynamicSwapError::PairMismatch.into());
    }
    // `rent_recipient` must be the escrow's `owner` (the taker, who paid the
    // escrow account rent).
    if !address_eq(&escrow.owner, rent_recipient.address()) {
        return Err(DynamicSwapError::RentRecipientMismatch.into());
    }
    // Cancel only past the window; inside it the escrow belongs to `settle`.
    // The strict partition means settle and cancel can never race.
    let expires_at = escrow
        .created_at
        .checked_add(pair.expiry_slots)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if Clock::get()?.slot <= expires_at {
        return Err(DynamicSwapError::NotYetExpired.into());
    }

    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        CancelPublicInput {
            private_tx_hash: &transact.private_tx_hash,
            order_in_hash: &escrow.order_utxo_hash,
        }
        .hash()?,
        &crate::verifying_keys::escrow_cancel::VERIFYINGKEY,
    )?;

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

    close_escrow_account(escrow_account, rent_recipient)
}
