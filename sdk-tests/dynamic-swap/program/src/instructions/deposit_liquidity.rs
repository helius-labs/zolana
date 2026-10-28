use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
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
pub struct DepositLiquidityIxData {
    pub proof: Groth16ProofBytes,
    pub amount: u64,
    pub transact: TransactIxData,
}

// Moves a public amount of the depositor's shielded destination asset into the
// pair's liquidity pool as one new pool note booking the full amount, and adds
// the amount to available liquidity. Permissionless: the depositor owns the
// spent note and signs.
//
// A proofless SPP deposit cannot carry the booked data hash, because SPP
// cannot check the owner's signature on data without a proof. The deposit is
// therefore a proven transact with no public transfer: the `pool_deposit`
// proof binds its only input to a non-pool note holding exactly `amount` of
// the destination asset and its only output to a pool note that holds and
// books `amount`. The CPI signs for the pool authority that owns that note; the
// proof's exclusion of a pool-owned source is what stops a deposit from
// re-booking liquidity the pool already holds.
//
// Steps:
// 1. Check that the pair account is present and writable.
// 2. Parse the proof, amount, and shielded-pool transaction.
// 3. Load the pair, verifying program ownership, exact `Pair::SIZE`, the pair
//    discriminator, and writable access.
// 4. Check that the amount is nonzero.
// 5. Check that the transaction carries no interface transfer, so the pool
//    note's value comes from the spent note alone.
// 6. Derive the `pool_authority` PDA's owner hash.
// 7. Build the proof's public-input hash from `transact.private_tx_hash`, the
//    pool owner, destination asset, and amount.
// 8. Verify the `pool_deposit` Groth16 proof.
// 9. Add the amount to `pair.available_liquidity` with overflow checking.
// 10. Check that the forwarded shielded-pool account list is present.
// 11. Serialize the shielded-pool transaction.
// 12. Invoke the shielded-pool program with the `pool_authority` PDA as signer.
#[inline(never)]
#[profile]
pub fn process_deposit_liquidity_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    // Step 1: Check that the pair account is present and writable.
    let pair_account = iter.next_mut("pair")?;
    let pair_address = *pair_account.address();

    // Step 2: Parse the proof, amount, and shielded-pool transaction.
    let DepositLiquidityIxData {
        proof,
        amount,
        transact,
    } = wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    {
        // Step 3: Load and validate the pair account.
        let mut pair = load_pair_mut(pair_account)?;
        // Step 4: Check that the amount is nonzero.
        if amount == 0 {
            return Err(DynamicSwapError::InvalidDepositAmount.into());
        }

        // Step 5: Check that the transaction carries no interface transfer.
        if !transact.interface_transfers.is_empty() {
            return Err(DynamicSwapError::InterfaceTransferMismatch.into());
        }

        // Step 6: Derive the pool authority's owner hash.
        let pool_owner_hash = pool_authority_owner_hash(&pair_address)?;
        // Step 7: Build the proof's public-input hash.
        // Step 8: Verify the pool-deposit proof.
        crate::verifier::pool_deposit::Verifier {
            proof: &proof.to_compressed(),
            public_inputs: crate::verifier::pool_deposit::PublicInputs {
                pool_authority_owner_hash: pool_owner_hash,
                destination_asset: pair.destination_asset,
                amount,
            },
            private_tx_hash: &transact.private_tx_hash,
            transfers: &[],
        }
        .verify()
        .map_err(|_| DynamicSwapError::ProofVerificationFailed)?;

        // Step 9: Add the amount to available liquidity without overflow.
        pair.available_liquidity = pair
            .available_liquidity
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    // Step 10: Check that the forwarded shielded-pool accounts are present.
    let spp_accounts = iter.remaining()?;
    // Step 11: Serialize the shielded-pool transaction.
    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    // Step 12: Invoke the shielded pool with the pool authority as signer.
    cpi_spp_transact_signed(
        &pair_address,
        crate::POOL_AUTHORITY_PDA_SEED,
        spp_accounts,
        &transact_bytes,
    )
}
