use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{
    error::DynamicSwapError,
    instructions::{
        deposit_liquidity::PoolUpdatePublicInput,
        shared::cpi_spp_transact_signed,
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    state::{load_liquidity_mut, load_pair},
};

/// `pool_update` circuit proof (2-in/2-out, shared with `deposit_liquidity`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct PoolUpdateProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct WithdrawLiquidityIxData {
    pub proof: PoolUpdateProof,
    pub available_slots: u64,
    pub refresh_capacity: bool,
    /// No amount field, and no public settlement leg on `transact`: the
    /// withdrawal is fully shielded. The `pool_update` circuit debits the pool
    /// into an authority-owned note of the same asset inside the shielded set
    /// (`pool_in + auth_in == pool_out + auth_out`), so the withdrawn amount
    /// lives only inside the UTXO commitments and ciphertexts of
    /// `transact.outputs` -- never in cleartext instruction data. The circuit
    /// also proves that the smaller pool still covers aggregate liabilities and
    /// every advertised capacity slot.
    pub transact: TransactIxData,
}

const OUTPUT_INDEX: usize = 0;

#[inline(never)]
#[profile]
pub fn process_withdraw_liquidity_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer_mut("authority")?;
    let pair_account = iter.next_account("pair")?;
    let liquidity_account = iter.next_mut("liquidity")?;

    let WithdrawLiquidityIxData {
        proof,
        available_slots,
        refresh_capacity,
        transact,
    } = wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    let pair = load_pair(pair_account)?;
    if pair.authority != *authority.address() {
        return Err(DynamicSwapError::Unauthorized.into());
    }

    let mut liquidity = load_liquidity_mut(liquidity_account)?;
    if liquidity.pair != *pair_account.address() {
        return Err(DynamicSwapError::PairMismatch.into());
    }
    if !refresh_capacity && available_slots != liquidity.available_slots {
        return Err(DynamicSwapError::InvalidCapacity.into());
    }
    let slot_value = pair
        .max_order_size
        .checked_mul(pair.price)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // The pool_update circuit folds PrivateTxHash and PoolInHash (the
    // witnessed old pool UTXO's own reconstructed hash) into PublicInputHash,
    // and asserts PoolInHash equals that witness. Passing the account's own
    // current `available_hash` here means the proof only verifies if the
    // prover's witnessed pool input really is this account's live UTXO --
    // without it, any unspent UTXO owned by `pool_authority` could stand in
    // for the real one. The withdrawn amount itself never enters this hash;
    // it stays a private circuit witness balanced by the authority note
    // (see `WithdrawLiquidityIxData`).
    let public_input_hash = PoolUpdatePublicInput {
        private_tx_hash: &transact.private_tx_hash,
        pool_in_hash: &liquidity.available_hash,
        destination_asset: &pair.destination_asset,
        reserved_liability: liquidity.reserved_liability,
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
        &crate::verifying_keys::pool_update::VERIFYINGKEY,
    )?;

    liquidity.available_hash = transact
        .outputs
        .get(OUTPUT_INDEX)
        .ok_or(DynamicSwapError::InvalidInstructionData)?
        .utxo_hash;
    liquidity.available_slots = available_slots;

    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    let spp_accounts = iter.remaining()?;
    cpi_spp_transact_signed(
        pair_account.address(),
        crate::POOL_AUTHORITY_PDA_SEED,
        spp_accounts,
        &transact_bytes,
    )
}
