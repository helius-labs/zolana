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
        shared::{
            check_within_window, cpi_spp_transact_signed_multi, derive_authority_pda,
            u64_right_align,
        },
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    state::{load_escrow_mut, load_liquidity_mut, load_pair},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SettleProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SettleIxData {
    pub proof: SettleProof,
    pub available_slots: u64,
    pub transact: TransactIxData,
}

pub struct SettlePublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub execution_price: u64,
    pub quote_version: u64,
    pub order_in_hash: &'a [u8; 32],
    pub pool_in_hash: &'a [u8; 32],
    pub authority_owner_hash: &'a [u8; 32],
    pub destination_asset: &'a [u8; 32],
    pub remaining_reserved_liability: u64,
    pub slot_value: u64,
    pub available_slots: u64,
    pub refresh_capacity: bool,
}

impl SettlePublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        Poseidon::hashv(&[
            self.private_tx_hash,
            &u64_right_align(self.execution_price),
            &u64_right_align(self.quote_version),
            self.order_in_hash,
            self.pool_in_hash,
            self.authority_owner_hash,
            self.destination_asset,
            &u64_right_align(self.remaining_reserved_liability),
            &u64_right_align(self.slot_value),
            &u64_right_align(self.available_slots),
            &u64_right_align(u64::from(self.refresh_capacity)),
        ])
        .map_err(|_| DynamicSwapError::HashingFailed.into())
    }
}

#[inline(never)]
#[profile]
pub fn process_settle_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let caller = iter.next_signer_mut("caller")?;
    let pair_account = iter.next_account("pair")?;
    let liquidity_account = iter.next_mut("liquidity")?;
    let escrow_account = iter.next_mut("escrow")?;
    let SettleIxData {
        proof,
        available_slots,
        transact,
    } = wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    let pair = *load_pair(pair_account)?;
    let escrow = *load_escrow_mut(escrow_account)?;
    if escrow.pair != *pair_account.address() {
        return Err(DynamicSwapError::PairMismatch.into());
    }
    check_within_window(Clock::get()?.unix_timestamp, escrow.expires_at_unix_ts)?;
    let mut liquidity = load_liquidity_mut(liquidity_account)?;
    if liquidity.pair != *pair_account.address() {
        return Err(DynamicSwapError::PairMismatch.into());
    }
    let remaining_reserved_liability = liquidity
        .reserved_liability
        .checked_sub(escrow.reserved_liability)
        .ok_or(DynamicSwapError::InvalidCapacity)?;
    let slot_value = pair
        .max_order_size
        .checked_mul(pair.price)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let advertised_liquidity = liquidity
        .available_slots
        .checked_mul(slot_value)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let refresh_capacity = advertised_liquidity < pair.capacity_refresh_threshold;
    if !refresh_capacity && available_slots != liquidity.available_slots {
        return Err(DynamicSwapError::InvalidCapacity.into());
    }

    let public_input_hash = SettlePublicInput {
        private_tx_hash: &transact.private_tx_hash,
        execution_price: escrow.execution_price,
        quote_version: escrow.quote_version,
        order_in_hash: &escrow.escrow_utxo_hash,
        pool_in_hash: &liquidity.available_hash,
        authority_owner_hash: &pair.authority_owner_hash,
        destination_asset: &pair.destination_asset,
        remaining_reserved_liability,
        slot_value,
        available_slots,
        refresh_capacity,
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
        &crate::verifying_keys::escrow_settle::VERIFYINGKEY,
    )?;

    liquidity.available_hash = transact
        .outputs
        .get(1)
        .ok_or(DynamicSwapError::InvalidInstructionData)?
        .utxo_hash;
    liquidity.reserved_liability = remaining_reserved_liability;
    liquidity.available_slots = available_slots;
    drop(liquidity);

    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    let (escrow_authority, escrow_bump) =
        derive_authority_pda(crate::ESCROW_AUTHORITY_PDA_SEED, pair_account.address());
    let (pool_authority, pool_bump) =
        derive_authority_pda(crate::POOL_AUTHORITY_PDA_SEED, pair_account.address());
    cpi_spp_transact_signed_multi(
        iter.remaining()?,
        &transact_bytes,
        &[
            (
                crate::ESCROW_AUTHORITY_PDA_SEED,
                *pair_account.address(),
                escrow_authority,
                escrow_bump,
            ),
            (
                crate::POOL_AUTHORITY_PDA_SEED,
                *pair_account.address(),
                pool_authority,
                pool_bump,
            ),
        ],
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
