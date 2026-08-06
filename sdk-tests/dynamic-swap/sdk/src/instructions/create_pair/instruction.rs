use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{err, tag, CreatePairData};

/// Creates a unidirectional trading pair plus its liquidity account.
/// `initial_pool_utxo_hash` must be
/// the hash of a zero-amount UTXO already owned by `pool_authority`, created
/// out-of-band via an ordinary SPP `Deposit` (SPP can't spend a nonexistent
/// leaf, so `deposit_liquidity` can't be 1-in on the very first call).
pub struct CreatePair {
    pub payer: Pubkey,
    pub pair: Pubkey,
    pub liquidity: Pubkey,
    pub price: u64,
    pub max_order_size: u64,
    pub capacity_refresh_threshold: u64,
    pub source_asset_id: u64,
    pub destination_asset_id: u64,
    pub initial_pool_utxo_hash: [u8; 32],
    pub authority_owner_hash: [u8; 32],
    /// The source asset's UTXO commitment (`asset_field(source_mint)`); see
    /// `Pair::source_asset`.
    pub source_asset: [u8; 32],
    pub destination_asset: [u8; 32],
    pub settlement_viewing_pubkey: [u8; 33],
}

impl CreatePair {
    pub fn instruction(self) -> Result<Instruction> {
        let data = CreatePairData {
            price: self.price,
            max_order_size: self.max_order_size,
            capacity_refresh_threshold: self.capacity_refresh_threshold,
            source_asset_id: self.source_asset_id,
            destination_asset_id: self.destination_asset_id,
            initial_pool_utxo_hash: self.initial_pool_utxo_hash,
            authority_owner_hash: self.authority_owner_hash,
            source_asset: self.source_asset,
            destination_asset: self.destination_asset,
            settlement_viewing_pubkey: self.settlement_viewing_pubkey,
        };

        let mut instruction_data = vec![tag::CREATE_PAIR];
        instruction_data.extend_from_slice(&borsh::to_vec(&data).map_err(err)?);

        let accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new(self.pair, false),
            AccountMeta::new(self.liquidity, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];
        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
