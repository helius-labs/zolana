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
            cpi_spp_transact, escrow_authority_owner_hash, u64_right_align, verify_pda,
            CreatePdaAccount,
        },
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    state::{discriminator::ESCROW, load_liquidity_mut, load_pair, Escrow},
};

pub const ORDER_EXPIRY_SECONDS: i64 = 600;
pub const CREATED_AT_UNIX_TS_TOLERANCE: i64 = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct EscrowOpenProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateEscrowIxData {
    pub proof: EscrowOpenProof,
    pub order_commitment: [u8; 32],
    pub created_at_unix_ts: i64,
    pub transact: TransactIxData,
}

pub struct EscrowOpenPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub created_at_unix_ts: i64,
    pub expires_at_unix_ts: i64,
    pub execution_price: u64,
    pub quote_version: u64,
    pub max_order_size: u64,
    pub escrow_authority_owner_hash: &'a [u8; 32],
    pub source_asset: &'a [u8; 32],
}

impl EscrowOpenPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        let created_at = u64::try_from(self.created_at_unix_ts)
            .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
        let expires_at = u64::try_from(self.expires_at_unix_ts)
            .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
        Poseidon::hashv(&[
            self.private_tx_hash,
            &u64_right_align(created_at),
            &u64_right_align(expires_at),
            &u64_right_align(self.execution_price),
            &u64_right_align(self.quote_version),
            &u64_right_align(self.max_order_size),
            self.escrow_authority_owner_hash,
            self.source_asset,
        ])
        .map_err(|_| DynamicSwapError::HashingFailed.into())
    }
}

#[inline(never)]
#[profile]
pub fn process_create_escrow_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let owner = iter.next_signer_mut("owner")?;
    let pair_account = iter.next_account("pair")?;
    let liquidity_account = iter.next_mut("liquidity")?;
    let escrow_account = iter.next_mut("escrow")?;
    let system_program = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let CreateEscrowIxData {
        proof,
        order_commitment,
        created_at_unix_ts,
        transact,
    } = wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    let pair = *load_pair(pair_account)?;
    let now = Clock::get()?.unix_timestamp;
    if now.abs_diff(created_at_unix_ts) > CREATED_AT_UNIX_TS_TOLERANCE as u64 {
        return Err(DynamicSwapError::CreatedAtOutOfTolerance.into());
    }
    let expires_at_unix_ts = created_at_unix_ts
        .checked_add(ORDER_EXPIRY_SECONDS)
        .ok_or(DynamicSwapError::InvalidInstructionData)?;
    let reserved_liability = pair
        .max_order_size
        .checked_mul(pair.price)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    let mut liquidity = load_liquidity_mut(liquidity_account)?;
    if liquidity.pair != *pair_account.address() {
        return Err(DynamicSwapError::PairMismatch.into());
    }
    if liquidity.available_slots == 0 {
        return Err(DynamicSwapError::InsufficientCapacity.into());
    }

    let escrow_authority_owner_hash = escrow_authority_owner_hash(pair_account.address())?;
    let public_input_hash = EscrowOpenPublicInput {
        private_tx_hash: &transact.private_tx_hash,
        created_at_unix_ts,
        expires_at_unix_ts,
        execution_price: pair.price,
        quote_version: pair.quote_version,
        max_order_size: pair.max_order_size,
        escrow_authority_owner_hash: &escrow_authority_owner_hash,
        source_asset: &pair.source_asset,
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
        &crate::verifying_keys::escrow_open::VERIFYINGKEY,
    )?;

    let order_out_hash = transact
        .outputs
        .first()
        .ok_or(DynamicSwapError::InvalidInstructionData)?
        .utxo_hash;
    let pair_key = *pair_account.address().as_array();
    let escrow_bump = verify_pda(
        escrow_account.address(),
        &[Escrow::SEED_PREFIX, &pair_key, &order_commitment],
        &crate::ID,
    )?;
    CreatePdaAccount::<3> {
        fee_payer: owner,
        new_account: escrow_account,
        space: Escrow::SIZE,
        owner: &crate::ID,
        signer_seeds: [Escrow::SEED_PREFIX, &pair_key, &order_commitment],
        bump: escrow_bump,
    }
    .execute()?;

    {
        let mut bytes = escrow_account
            .try_borrow_mut()
            .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
        let state: &mut Escrow = bytemuck::from_bytes_mut(&mut bytes);
        state.discriminator = ESCROW;
        state.bump = escrow_bump;
        state.pair = *pair_account.address();
        state.escrow_utxo_hash = order_out_hash;
        state.order_commitment = order_commitment;
        state.execution_price = pair.price;
        state.quote_version = pair.quote_version;
        state.reserved_liability = reserved_liability;
        state.created_at_unix_ts = created_at_unix_ts;
        state.expires_at_unix_ts = expires_at_unix_ts;
    }

    liquidity.available_slots -= 1;
    liquidity.reserved_liability = liquidity
        .reserved_liability
        .checked_add(reserved_liability)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    drop(liquidity);

    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    cpi_spp_transact(iter.remaining()?, &transact_bytes)
}
