use light_program_profiler::profile;
use pinocchio::{address::address_eq, error::ProgramError, AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{
    error::DynamicSwapError,
    instructions::{
        shared::{cpi_spp_transact_signed, u64_right_align},
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    state::{load_escrow_mut, load_pair},
};

/// `escrow_settle` circuit proof (2-in: order UTXO, reservation UTXO / 3-out:
/// recipient, maker counter-asset UTXO, maker source-asset UTXO). ONE circuit and
/// VK covers both resolution outcomes -- settle and price-refund -- so the
/// transaction never reveals which occurred. The outcome is derived inside the
/// circuit from the public `execution_price` and the PRIVATE `max_price`
/// (committed in the order UTXO's data hash), so it is not observable on-chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SettleProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SettleIxData {
    pub proof: SettleProof,
    pub transact: TransactIxData,
}

/// `escrow_settle`'s public-input hash: `Poseidon(PrivateTxHash, ExecutionPrice,
/// OrderInHash, ReservationInHash, AuthorityOwnerHash)`. `MaxPrice` and the
/// recipient owner-hash are deliberately absent -- both are private circuit
/// witnesses bound to the order UTXO's data hash (pinned by `OrderInHash`), which
/// is what keeps the settle-vs-refund outcome and the payout destination hidden.
/// `ExecutionPrice` is the escrow's plaintext value (the public pair price, always
/// nonzero). Field order and encoding must match the circuit's `PublicInputs.Check`.
pub struct SettlePublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub execution_price: u64,
    pub order_in_hash: &'a [u8; 32],
    pub reservation_in_hash: &'a [u8; 32],
    pub authority_owner_hash: &'a [u8; 32],
}

impl SettlePublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        Poseidon::hashv(&[
            self.private_tx_hash.as_slice(),
            u64_right_align(self.execution_price).as_slice(),
            self.order_in_hash.as_slice(),
            self.reservation_in_hash.as_slice(),
            self.authority_owner_hash.as_slice(),
        ])
        .map_err(|_| DynamicSwapError::HashingFailed.into())
    }
}

/// Settles one escrow -- settle or price-refund -- and closes it. Permissionless:
/// the caller only pays fees and authorizes the call; the outcome and all
/// destinations are fixed by the proof and on-chain state, and only whoever holds
/// the order/reservation witnesses off-chain (the maker/operator) can build a
/// valid proof.
///
/// Every escrow is priced at creation (commit is folded into create_escrow), so
/// the outcome (settle vs refund) is fixed at creation and settle is deterministic
/// deferred execution. Each escrow is self-contained (its own locked order +
/// reservation UTXOs), so there is no shared pool and no ordering between escrows.
/// A single instruction, account list, VK, and 3-out shape covers both settle and
/// refund, so an observer cannot tell them apart.
#[inline(never)]
#[profile]
pub fn process_settle_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    // Permissionless executor: signs and pays fees only (see doc above).
    iter.next_signer_mut("caller")?;
    let pair_account = iter.next_account("pair")?;
    let escrow_account = iter.next_mut("escrow")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;

    let SettleIxData { proof, transact } =
        wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    let pair = *load_pair(pair_account)?;
    let pair_address = *pair_account.address();

    // Snapshot the escrow's fields and immediately drop the borrow so
    // `escrow_account` is free to be closed later in this same call.
    let escrow = *load_escrow_mut(escrow_account)?;
    // Bind escrow to this pair: both the maker-payout owner (`authority_owner_hash`)
    // and the escrow_authority PDA that signs the spend are derived from the pair,
    // so a mismatched pair account must be rejected. (SPP would also reject the
    // spend on the escrow_authority owner mismatch, but fail early and clearly.)
    if !address_eq(&escrow.pair, pair_account.address()) {
        return Err(DynamicSwapError::PairMismatch.into());
    }
    // `rent_recipient` must be the escrow's raw-pubkey `owner` (who funded the
    // escrow account). The confidential payout destination is not stored on-chain
    // at all -- it is a private circuit witness bound to the order UTXO's DataHash.
    if !address_eq(&escrow.owner, rent_recipient.address()) {
        return Err(DynamicSwapError::RentRecipientMismatch.into());
    }

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
            order_in_hash: &escrow.escrow_utxo_hash,
            reservation_in_hash: &escrow.reservation_utxo_hash,
            authority_owner_hash: &pair.authority_owner_hash,
        }
        .hash()?,
        &crate::verifying_keys::escrow_settle::VERIFYINGKEY,
    )?;

    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    // Both spent inputs (order, reservation) are owned by the escrow_authority PDA,
    // so only that one PDA must be flipped to a signer in the `transact` CPI.
    let spp_accounts = iter.remaining()?;
    cpi_spp_transact_signed(
        &pair_address,
        crate::ESCROW_AUTHORITY_PDA_SEED,
        spp_accounts,
        &transact_bytes,
    )?;

    // Rent must move to `rent_recipient` before the account is closed, or the
    // instruction is unbalanced.
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
