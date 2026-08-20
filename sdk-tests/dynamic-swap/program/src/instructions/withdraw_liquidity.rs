use light_program_profiler::profile;
use pinocchio::{address::address_eq, error::ProgramError, AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::instruction::instruction_data::transact::{
    InterfaceTransfer, TransactIxData,
};

use crate::{
    error::DynamicSwapError,
    instructions::{
        shared::{cpi_spp_transact_signed, pool_authority_owner_hash, u64_right_align},
        verifier::{verify_groth16, CompressedGroth16Proof, Groth16ProofBytes},
    },
    state::load_pair_mut,
};

const WITHDRAWAL_GROUP_LEN: usize = 5;
const USER_TOKEN_FROM_END: usize = 2;

const TOKEN_ACCOUNT_OWNER_RANGE: core::ops::Range<usize> = 32..64;

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct WithdrawLiquidityIxData {
    pub proof: Groth16ProofBytes,
    pub amount: u64,
    pub transact: TransactIxData,
}

pub struct PoolWithdrawPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub pool_authority_owner_hash: &'a [u8; 32],
    pub destination_asset: &'a [u8; 32],
    pub amount: u64,
}

impl PoolWithdrawPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        Poseidon::hashv(&[
            self.private_tx_hash.as_slice(),
            self.pool_authority_owner_hash.as_slice(),
            self.destination_asset.as_slice(),
            u64_right_align(self.amount).as_slice(),
        ])
        .map_err(|_| DynamicSwapError::HashingFailed.into())
    }
}

// Withdraws destination-asset SPL tokens from the pair's liquidity pool into
// the authority's token account and subtracts the amount from available
// liquidity.
//
// Steps:
// 1. Check that the authority account is present, writable, and a signer.
// 2. Check that the pair account is present and writable.
// 3. Parse the proof, amount, and shielded-pool transaction.
// 4. Load the pair, verifying program ownership, exact `Pair::SIZE`, the pair
//    discriminator, and writable access.
// 5. Check that the signer is the pair authority.
// 6. Check that the amount is nonzero.
// 7. Check that the amount does not exceed `pair.available_liquidity`.
// 8. Check for exactly one SPL withdrawal matching the amount.
// 9. Derive the `pool_authority` PDA's owner hash.
// 10. Build the proof's public-input hash from `transact.private_tx_hash`, the
//     pool owner, destination asset, and amount.
// 11. Verify the `pool_withdraw` Groth16 proof.
// 12. Check that the forwarded shielded-pool account list is present.
// 13. Check that the account list is long enough for the five-account SPL
//     withdrawal group.
// 14. Locate the destination token account in that group.
// 15. Read the destination token account's owner field.
// 16. Check that the destination token account belongs to the pair authority.
// 17. Subtract the amount from `pair.available_liquidity` with underflow
//     checking.
// 18. Serialize the shielded-pool transaction.
// 19. Invoke the shielded-pool program with the `pool_authority` PDA as signer.
#[inline(never)]
#[profile]
pub fn process_withdraw_liquidity_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    // Step 1: Check that the authority is present, writable, and a signer.
    let authority = iter.next_signer_mut("authority")?;
    // Step 2: Check that the pair account is present and writable.
    let pair_account = iter.next_mut("pair")?;
    let pair_address = *pair_account.address();

    // Step 3: Parse the proof, amount, and shielded-pool transaction.
    let WithdrawLiquidityIxData {
        proof,
        amount,
        transact,
    } = wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    // Step 4: Load and validate the pair account.
    let pair = *load_pair_mut(pair_account)?;
    // Step 5: Check that the signer is the pair authority.
    if !address_eq(&pair.authority, authority.address()) {
        return Err(DynamicSwapError::Unauthorized.into());
    }
    // Step 6: Check that the amount is nonzero.
    if amount == 0 {
        return Err(DynamicSwapError::InvalidWithdrawalAmount.into());
    }
    // Step 7: Check that the amount does not exceed available liquidity.
    if amount > pair.available_liquidity {
        return Err(DynamicSwapError::InsufficientLiquidity.into());
    }

    // Step 8: Check that the public transfer shape matches the amount.
    match transact.interface_transfers.as_slice() {
        [InterfaceTransfer::SplWithdrawal {
            amount: transfer_amount,
            ..
        }] if *transfer_amount == amount => {}
        _ => return Err(DynamicSwapError::InterfaceTransferMismatch.into()),
    }

    // Step 9: Derive the pool authority's owner hash.
    let pool_owner_hash = pool_authority_owner_hash(&pair_address)?;
    // Step 10: Build the proof's public-input hash.
    // Step 11: Verify the pool-withdraw proof.
    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        PoolWithdrawPublicInput {
            private_tx_hash: &transact.private_tx_hash,
            pool_authority_owner_hash: &pool_owner_hash,
            destination_asset: &pair.destination_asset,
            amount,
        }
        .hash()?,
        &crate::verifying_keys::pool_withdraw::VERIFYINGKEY,
    )?;

    // Step 12: Check that the forwarded shielded-pool accounts are present.
    let spp_accounts = iter.remaining()?;
    // Step 13: Check that the SPL withdrawal group has enough accounts.
    if spp_accounts.len() < WITHDRAWAL_GROUP_LEN {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    // Step 14: Locate the destination token account.
    let user_token = spp_accounts
        .get(spp_accounts.len() - USER_TOKEN_FROM_END)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    // Step 15: Read the destination token account's owner field.
    let token_data = user_token
        .try_borrow()
        .map_err(|_| DynamicSwapError::InterfaceTransferMismatch)?;
    let token_owner = token_data
        .get(TOKEN_ACCOUNT_OWNER_RANGE)
        .ok_or(DynamicSwapError::InterfaceTransferMismatch)?;
    // Step 16: Check that the token account belongs to the pair authority.
    if token_owner != pair.authority.as_array() {
        return Err(DynamicSwapError::InterfaceTransferMismatch.into());
    }

    {
        // Step 17: Subtract the amount from available liquidity.
        let mut pair = load_pair_mut(pair_account)?;
        pair.available_liquidity = pair
            .available_liquidity
            .checked_sub(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    // Step 18: Serialize the shielded-pool transaction.
    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    // Step 19: Invoke the shielded pool with the pool authority as signer.
    cpi_spp_transact_signed(
        &pair_address,
        crate::POOL_AUTHORITY_PDA_SEED,
        spp_accounts,
        &transact_bytes,
    )
}
