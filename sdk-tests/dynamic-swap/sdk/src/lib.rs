pub mod discovery;
pub mod instructions;
pub mod prover;
pub mod shared;
pub mod state;

use solana_pubkey::Pubkey;

pub use dynamic_swap_program::{
    instructions::{
        create_escrow::{CreateEscrowIxData, EscrowOpenProof, EscrowOpenPublicInput},
        create_pair::CreatePairData,
        deposit_liquidity::{DepositLiquidityIxData, PoolUpdateProof, PoolUpdatePublicInput},
        refund_expired::{RefundExpiredIxData, RefundProof, RefundPublicInput},
        settle::{SettleIxData, SettleProof, SettlePublicInput},
        update_price::UpdatePriceData,
        withdraw_liquidity::WithdrawLiquidityIxData,
    },
    state::{Escrow, Liquidity, Pair},
    tag, ESCROW_AUTHORITY_PDA_SEED, ID, POOL_AUTHORITY_PDA_SEED,
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

pub fn liquidity_pda(pair: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[Liquidity::SEED_PREFIX, pair.as_ref()], &ID).0
}

pub fn escrow_pda(pair: &Pubkey, order_commitment: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[Escrow::SEED_PREFIX, pair.as_ref(), order_commitment], &ID).0
}

pub fn pool_authority_pda(pair: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[POOL_AUTHORITY_PDA_SEED, pair.as_ref()], &ID).0
}

pub fn escrow_authority_pda(pair: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ESCROW_AUTHORITY_PDA_SEED, pair.as_ref()], &ID).0
}
