use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{err, tag, CreatePairData};

/// Creates a unidirectional trading pair. There is no shared pool: the maker
/// funds each escrow directly, so no pool bootstrap or auxiliary accounts are
/// needed.
pub struct CreatePair {
    pub payer: Pubkey,
    pub pair: Pubkey,
    pub price: u64,
    pub source_asset_id: u64,
    pub destination_asset_id: u64,
    pub authority_owner_hash: [u8; 32],
    /// The source asset's UTXO commitment (`asset_field(source_mint)`); see
    /// `Pair::source_asset`.
    pub source_asset: [u8; 32],
    /// The destination asset's UTXO commitment; see `Pair::destination_asset`.
    pub destination_asset: [u8; 32],
}

impl CreatePair {
    pub fn instruction(self) -> Result<Instruction> {
        let data = CreatePairData {
            price: self.price,
            source_asset_id: self.source_asset_id,
            destination_asset_id: self.destination_asset_id,
            authority_owner_hash: self.authority_owner_hash,
            source_asset: self.source_asset,
            destination_asset: self.destination_asset,
        };

        let mut instruction_data = vec![tag::CREATE_PAIR];
        instruction_data.extend_from_slice(&borsh::to_vec(&data).map_err(err)?);

        let accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new(self.pair, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ];
        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
