use light_program_profiler::profile;
use pinocchio::{
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
        shared::{check_after_window, cpi_spp_transact_signed, u64_right_align},
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    state::{load_escrow_mut, load_liquidity_mut},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct RefundProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct RefundExpiredIxData {
    pub proof: RefundProof,
    pub transact: TransactIxData,
}

pub struct RefundPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub execution_price: u64,
    pub quote_version: u64,
    pub order_in_hash: &'a [u8; 32],
}

impl RefundPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        Poseidon::hashv(&[
            self.private_tx_hash,
            &u64_right_align(self.execution_price),
            &u64_right_align(self.quote_version),
            self.order_in_hash,
        ])
        .map_err(|_| DynamicSwapError::HashingFailed.into())
    }
}

#[inline(never)]
#[profile]
pub fn process_refund_expired_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let caller = iter.next_signer_mut("caller")?;
    let pair_account = iter.next_account("pair")?;
    let liquidity_account = iter.next_mut("liquidity")?;
    let escrow_account = iter.next_mut("escrow")?;
    let RefundExpiredIxData { proof, transact } =
        wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    let escrow = *load_escrow_mut(escrow_account)?;
    if escrow.pair != *pair_account.address() {
        return Err(DynamicSwapError::PairMismatch.into());
    }
    check_after_window(Clock::get()?.unix_timestamp, escrow.expires_at_unix_ts)?;
    let mut liquidity = load_liquidity_mut(liquidity_account)?;
    if liquidity.pair != *pair_account.address() {
        return Err(DynamicSwapError::PairMismatch.into());
    }

    let public_input_hash = RefundPublicInput {
        private_tx_hash: &transact.private_tx_hash,
        execution_price: escrow.execution_price,
        quote_version: escrow.quote_version,
        order_in_hash: &escrow.escrow_utxo_hash,
    }
    .hash()?;
    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        public_input_hash,
        &crate::verifying_keys::escrow_refund::VERIFYINGKEY,
    )?;

    liquidity.reserved_liability = liquidity
        .reserved_liability
        .checked_sub(escrow.reserved_liability)
        .ok_or(DynamicSwapError::InvalidCapacity)?;
    drop(liquidity);

    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    cpi_spp_transact_signed(
        pair_account.address(),
        crate::ESCROW_AUTHORITY_PDA_SEED,
        iter.remaining()?,
        &transact_bytes,
    )?;

    let rent = escrow_account.lamports();
    caller.set_lamports(
        caller
            .lamports()
            .checked_add(rent)
            .ok_or(ProgramError::ArithmeticOverflow)?,
    );
    escrow_account.set_lamports(0);
    escrow_account.close()
}
