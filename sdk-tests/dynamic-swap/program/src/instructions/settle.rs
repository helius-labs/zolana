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
        shared::{close_escrow_account, cpi_spp_transact_signed, u64_right_align},
        verifier::{verify_groth16, CompressedGroth16Proof, Groth16ProofBytes},
    },
    state::{load_escrow_mut, load_pair},
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SettleIxData {
    /// `escrow_settle` circuit proof (2-in: order UTXO, funder's funding UTXO /
    /// 3-out: recipient payout, funder change, funder source-asset receipt).
    /// There is no refund branch: an escrow can only exist at an acceptable
    /// price (create_escrow checks max_price), so settle always settles; the
    /// alternative outcome is `cancel` after expiry.
    pub proof: Groth16ProofBytes,
    pub transact: TransactIxData,
}

/// `escrow_settle`'s public-input hash: `Poseidon(PrivateTxHash,
/// ExecutionPrice, OrderInHash, DestinationAsset)`. The recipient owner-hash is
/// deliberately absent -- it is re-opened in-circuit from the order UTXO's
/// DataHash (pinned by `OrderInHash`), which keeps the payout destination
/// confidential. `ExecutionPrice` is the escrow's stored price (always
/// nonzero); `DestinationAsset` binds the funding UTXO's asset to the pair.
/// Field order and encoding must match the circuit's `PublicInputs.Check`.
pub struct SettlePublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub execution_price: u64,
    pub order_in_hash: &'a [u8; 32],
    pub destination_asset: &'a [u8; 32],
}

impl SettlePublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        Poseidon::hashv(&[
            self.private_tx_hash.as_slice(),
            u64_right_align(self.execution_price).as_slice(),
            self.order_in_hash.as_slice(),
            self.destination_asset.as_slice(),
        ])
        .map_err(|_| DynamicSwapError::HashingFailed.into())
    }
}

/// Fills one escrow before expiry and closes it. The funder brings the
/// destination-asset liquidity at fill time (its own shielded note -- no shared
/// pool, no per-order reservation) and signs the transaction to authorize
/// spending it (SPP's per-input signer access control). The circuit binds the
/// funder outputs (change + source-asset receipt) to the funding UTXO's owner,
/// so whoever holds the order UTXO data and funds the payout fills the order:
/// the maker in practice (it holds the encrypted order UTXO data), though the
/// taker can self-fill to exit early.
#[inline(never)]
#[profile]
pub fn process_settle_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    // The funder: pays fees and authorizes its own funding input via the outer
    // signature. The program never checks who it is -- the proof fixes every
    // destination.
    iter.next_signer_mut("funder")?;
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
    // Bind escrow to this pair: the expiry window and the destination-asset
    // public input are pair fields, so a mismatched pair account must be
    // rejected.
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
        }
        .hash()?,
        &crate::verifying_keys::escrow_settle::VERIFYINGKEY,
    )?;

    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    // The order input is owned by the escrow_authority PDA, the only account
    // flipped to a signer in the `transact` CPI; the funding input rides on the
    // funder's outer signature.
    let spp_accounts = iter.remaining()?;
    cpi_spp_transact_signed(
        &pair_address,
        crate::ESCROW_AUTHORITY_PDA_SEED,
        spp_accounts,
        &transact_bytes,
    )?;

    close_escrow_account(escrow_account, rent_recipient)
}
