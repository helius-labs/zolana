use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{err, tag, CreatePairData};

/// Creates a unidirectional trading pair. The pool starts empty
/// (`available_liquidity = 0`); the maker commits liquidity afterwards with
/// `deposit_liquidity`.
pub struct CreatePair {
    pub payer: Pubkey,
    pub pair: Pubkey,
    pub price: u64,
    pub source_asset_id: u64,
    pub destination_asset_id: u64,
    /// The maker's settle window in slots; see `Pair::expiry_slots`.
    pub expiry_slots: u64,
    /// The worst-case owed per escrow; see `Pair::max_order_size`.
    pub max_order_size: u64,
    /// The source asset's UTXO commitment (`asset_field(source_mint)`); see
    /// `Pair::source_asset`.
    pub source_asset: [u8; 32],
    /// The destination asset's UTXO commitment; see `Pair::destination_asset`.
    pub destination_asset: [u8; 32],
    /// The maker receipt destination; see `Pair::maker_receipt_owner_hash`.
    pub maker_receipt_owner_hash: [u8; 32],
    /// The maker's encryption pubkey; see `Pair::maker_encryption_pubkey`.
    pub maker_encryption_pubkey: [u8; 33],
}

impl CreatePair {
    pub fn instruction(self) -> Result<Instruction> {
        let data = CreatePairData {
            price: self.price,
            source_asset_id: self.source_asset_id,
            destination_asset_id: self.destination_asset_id,
            expiry_slots: self.expiry_slots,
            max_order_size: self.max_order_size,
            source_asset: self.source_asset,
            destination_asset: self.destination_asset,
            maker_receipt_owner_hash: self.maker_receipt_owner_hash,
            maker_encryption_pubkey: self.maker_encryption_pubkey,
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
