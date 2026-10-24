pub mod discovery;
pub mod instructions;
pub mod prover;
pub mod shared;
pub mod state;

use solana_pubkey::Pubkey;

pub use dynamic_swap_program::{
    instructions::{
        cancel::CancelIxData, create_escrow::CreateEscrowIxData, create_pair::CreatePairData,
        deposit_liquidity::DepositLiquidityIxData, rebalance_liquidity::RebalanceLiquidityIxData,
        settle::SettleIxData, update_price::UpdatePriceData, verifier::Groth16ProofBytes,
        withdraw_liquidity::WithdrawLiquidityIxData,
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

/// The escrow account is keyed by the pair and the order's position in the
/// pair's FIFO queue: `create_escrow` takes `Pair::next_order_id`, and the
/// order `settle` or `skip_expired` accepts is at `Pair::head_order_id`.
pub fn escrow_pda(pair: &Pubkey, order_id: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[Escrow::SEED_PREFIX, pair.as_ref(), &order_id.to_le_bytes()],
        &ID,
    )
    .0
}

pub fn escrow_authority_pda(pair: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ESCROW_AUTHORITY_PDA_SEED, pair.as_ref()], &ID).0
}

/// Owns every pool (liquidity) UTXO for the pair.
pub fn pool_authority_pda(pair: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[POOL_AUTHORITY_PDA_SEED, pair.as_ref()], &ID).0
}
