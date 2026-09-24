pub mod discovery;
pub mod instructions;
pub mod prover;
pub mod shared;
pub mod state;

use solana_pubkey::Pubkey;

pub use dynamic_swap_program::{
    instructions::{
        cancel::{CancelIxData, CancelPublicInput},
        create_escrow::{CreateEscrowIxData, EscrowOpenPublicInput},
        create_pair::CreatePairData,
        rebalance_liquidity::{PoolRebalancePublicInput, RebalanceLiquidityIxData},
        settle::{SettleIxData, SettlePublicInput},
        update_price::UpdatePriceData,
        verifier::Groth16ProofBytes,
        withdraw_liquidity::{PoolWithdrawPublicInput, WithdrawLiquidityIxData},
    },
    state::{Escrow, Pair},
    tag, ESCROW_AUTHORITY_PDA_SEED, ESCROW_NULLIFIER_PUBKEY, ID, POOL_AUTHORITY_PDA_SEED,
};

pub(crate) fn err(e: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}

pub fn pair_pda(authority: &Pubkey, source_asset_id: u64, destination_asset_id: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[
            Pair::SEED_PREFIX,
            authority.as_ref(),
            &source_asset_id.to_le_bytes(),
            &destination_asset_id.to_le_bytes(),
        ],
        &ID,
    )
    .0
}

/// The escrow account is keyed by the order UTXO's hash: a taker can hold
/// concurrent orders, and either party can derive the address from the order
/// alone.
pub fn escrow_pda(order_utxo_hash: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[Escrow::SEED_PREFIX, order_utxo_hash], &ID).0
}

pub fn escrow_authority_pda(pair: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ESCROW_AUTHORITY_PDA_SEED, pair.as_ref()], &ID).0
}

/// Owns every pool (liquidity) UTXO for the pair.
pub fn pool_authority_pda(pair: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[POOL_AUTHORITY_PDA_SEED, pair.as_ref()], &ID).0
}
