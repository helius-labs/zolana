pub mod discovery;
pub mod instructions;
pub mod prover;
pub mod shared;
pub mod state;

use solana_instruction::AccountMeta;
use solana_pubkey::Pubkey;
use zolana_interface::{instruction::TransactIxData, pda};

pub use dynamic_swap_program::{
    instructions::{
        create_escrow::{CreateEscrowIxData, EscrowOpenProof, EscrowOpenPublicInput},
        create_pair::CreatePairData,
        settle::{SettleIxData, SettleProof, SettlePublicInput},
        update_price::UpdatePriceData,
    },
    state::{Escrow, Pair},
    tag, ESCROW_AUTHORITY_PDA_SEED, ID,
};

pub(crate) fn err(e: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}

pub(crate) fn nullifier_marker_accounts(
    tree: &Pubkey,
    transact: &TransactIxData,
) -> Vec<AccountMeta> {
    transact
        .inputs
        .iter()
        .map(|input| AccountMeta::new(pda::nullifier_marker(tree, &input.nullifier_hash).0, false))
        .collect()
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

/// The escrow account is keyed by its owner (the taker): either party can
/// derive its address from the taker's pubkey alone -- one open escrow per taker.
pub fn escrow_pda(owner: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[Escrow::SEED_PREFIX, owner.as_ref()], &ID).0
}

pub fn escrow_authority_pda(pair: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[ESCROW_AUTHORITY_PDA_SEED, pair.as_ref()], &ID).0
}
