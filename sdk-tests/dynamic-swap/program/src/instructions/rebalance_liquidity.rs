use light_program_profiler::profile;
use pinocchio::{address::address_eq, error::ProgramError, AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{
    error::DynamicSwapError,
    instructions::{
        shared::{cpi_spp_transact_signed, pool_authority_owner_hash},
        verifier::Groth16ProofBytes,
    },
    state::load_pair_mut,
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct RebalanceLiquidityIxData {
    /// `pool_rebalance` circuit proof (up to 5 pool notes in, up to 4 out,
    /// dummy-padded to the fixed IN5_OUT4 shape).
    pub proof: Groth16ProofBytes,
    /// The published surplus: the proof checks `sum(booked_out) =
    /// sum(booked_in) + credit`, capped by the spent notes' surplus, so the
    /// bound can never be raised past value provably present and not yet
    /// counted. `0` is a pure merge/split/re-blind.
    pub credit: u64,
    pub transact: TransactIxData,
}

/// Restructures the pool (merge, split, re-blind, redistribute booked) and
/// optionally publishes accumulated settle surplus into `available_liquidity` via
/// the public `credit`. This is the only instruction that raises the bound
/// from confidential value; deposits raise it by their public SPL amount.
#[inline(never)]
#[profile]
pub fn process_rebalance_liquidity_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer_mut("authority")?;
    let pair_account = iter.next_mut("pair")?;
    let pair_address = *pair_account.address();

    let RebalanceLiquidityIxData {
        proof,
        credit,
        transact,
    } = wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    let pair = *load_pair_mut(pair_account)?;
    if !address_eq(&pair.authority, authority.address()) {
        return Err(DynamicSwapError::Unauthorized.into());
    }
    // A rebalance moves no public value: every input and output is a pool
    // note, so any interface transfer is a mismatch.
    if !transact.interface_transfers.is_empty() {
        return Err(DynamicSwapError::InterfaceTransferMismatch.into());
    }

    let pool_owner_hash = pool_authority_owner_hash(&pair_address)?;
    crate::verifier::pool_rebalance::Verifier {
        proof: &proof.to_compressed(),
        public_inputs: crate::verifier::pool_rebalance::PublicInputs {
            pool_authority_owner_hash: pool_owner_hash,
            destination_asset: pair.destination_asset,
            credit,
        },
        private_tx_hash: &transact.private_tx_hash,
        transfers: &[],
    }
    .verify()
    .map_err(|_| DynamicSwapError::ProofVerificationFailed)?;

    {
        let mut pair = load_pair_mut(pair_account)?;
        pair.available_liquidity = pair
            .available_liquidity
            .checked_add(credit)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    // Every real input and every data-bearing output is owned by the
    // pool_authority PDA, the only account flipped to a signer in the
    // `transact` CPI.
    let spp_accounts = iter.remaining()?;
    cpi_spp_transact_signed(
        &pair_address,
        crate::POOL_AUTHORITY_PDA_SEED,
        spp_accounts,
        &transact_bytes,
    )
}
