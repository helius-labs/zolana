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

/// The SplWithdrawal settlement group appended to the transact tail:
/// `cpi_authority, mint, spl_interface, user_token_account, token_program`.
/// With exactly one transfer (enforced below) SPP rejects leftover accounts,
/// so the group is the tail's final five accounts and the destination token
/// account sits second-to-last.
const WITHDRAWAL_GROUP_LEN: usize = 5;
const USER_TOKEN_FROM_END: usize = 2;

/// SPL token account layout: the owner pubkey occupies bytes 32..64.
const TOKEN_ACCOUNT_OWNER_RANGE: core::ops::Range<usize> = 32..64;

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct WithdrawLiquidityIxData {
    /// `pool_withdraw` circuit proof (1-in: pool note / 1-out: pool change).
    pub proof: Groth16ProofBytes,
    /// The public withdrawn amount. `0` is allowed: it re-blinds a public
    /// deposit note into a confidential one, with no SPL leg.
    pub amount: u64,
    pub transact: TransactIxData,
}

/// `pool_withdraw`'s public-input hash: `Poseidon(PrivateTxHash,
/// PoolAuthorityOwnerHash, DestinationAsset, Amount)`. Field order and encoding
/// must match the circuit's `PublicInputs.Check`.
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

/// Unshields a public `amount` of the destination asset from one pool note to
/// the authority's SPL token account through the transact's SplWithdrawal leg.
/// Rejects `amount > liquidity_bound`, so guaranteed funds for open orders can
/// never leave; the circuit additionally consumes `amount` from the note's
/// booked value, keeping the bound a lower bound.
#[inline(never)]
#[profile]
pub fn process_withdraw_liquidity_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer_mut("authority")?;
    let pair_account = iter.next_mut("pair")?;
    let pair_address = *pair_account.address();

    let WithdrawLiquidityIxData {
        proof,
        amount,
        transact,
    } = wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    let pair = *load_pair_mut(pair_account)?;
    if !address_eq(&pair.authority, authority.address()) {
        return Err(DynamicSwapError::Unauthorized.into());
    }
    if amount > pair.liquidity_bound {
        return Err(DynamicSwapError::InsufficientLiquidity.into());
    }

    // The transact's public SPL leg must be exactly the withdrawn amount: one
    // SplWithdrawal matching `amount`, or none at all for the `amount = 0`
    // re-blind (SPP rejects zero-amount transfers).
    match (amount, transact.interface_transfers.as_slice()) {
        (0, []) => {}
        (
            _,
            [InterfaceTransfer::SplWithdrawal {
                amount: transfer_amount,
                ..
            }],
        ) if *transfer_amount == amount => {}
        _ => return Err(DynamicSwapError::InterfaceTransferMismatch.into()),
    }

    let pool_owner_hash = pool_authority_owner_hash(&pair_address)?;
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

    let spp_accounts = iter.remaining()?;
    // Defense in depth: the withdrawal destination must be a token account
    // owned by the pair authority (the authority signed and picked the
    // accounts, but this keeps a mistaken destination from settling). With
    // exactly one transfer the group is the tail's final five accounts.
    if amount > 0 {
        if spp_accounts.len() < WITHDRAWAL_GROUP_LEN {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        let user_token = spp_accounts
            .get(spp_accounts.len() - USER_TOKEN_FROM_END)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        let token_data = user_token
            .try_borrow()
            .map_err(|_| DynamicSwapError::InterfaceTransferMismatch)?;
        let token_owner = token_data
            .get(TOKEN_ACCOUNT_OWNER_RANGE)
            .ok_or(DynamicSwapError::InterfaceTransferMismatch)?;
        if token_owner != pair.authority.as_array() {
            return Err(DynamicSwapError::InterfaceTransferMismatch.into());
        }
    }

    {
        let mut pair = load_pair_mut(pair_account)?;
        pair.liquidity_bound = pair
            .liquidity_bound
            .checked_sub(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    // The spent pool note is owned by the pool_authority PDA, the only account
    // flipped to a signer in the `transact` CPI (it also authorizes the
    // data-bearing pool change output).
    cpi_spp_transact_signed(
        &pair_address,
        crate::POOL_AUTHORITY_PDA_SEED,
        spp_accounts,
        &transact_bytes,
    )
}
