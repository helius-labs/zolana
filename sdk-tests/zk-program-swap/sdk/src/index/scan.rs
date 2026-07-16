use anyhow::{anyhow, Result};
use solana_address::Address;
use zolana_interface::event::OutputDataEncoding;
use zolana_transaction::{
    instructions::transact::OutputSlot, AssetRegistry, DataRecord, EncryptedScheme,
    ShieldedTransaction, SOL_ASSET_ID, SOL_MINT,
};

use crate::{err, state::PlainTextData};

pub(crate) fn resolve_mint(registry: &AssetRegistry, asset_id: u64) -> Result<Address> {
    if asset_id == SOL_ASSET_ID {
        return Ok(SOL_MINT);
    }
    registry.resolve(asset_id).map_err(err)
}

/// Unified confidential ciphertext slots with their decryption slot index:
/// ciphertext slots are indexed over data-bearing slots only.
pub(crate) fn unified_slots(
    tx: &ShieldedTransaction,
) -> impl Iterator<Item = (u32, &OutputSlot, Vec<u8>)> {
    let mut next_index = 0u32;
    tx.output_slots.iter().filter_map(move |slot| {
        let output_data = slot.output_data()?;
        let slot_index = next_index;
        next_index += 1;
        let OutputDataEncoding::Encrypted(mut blob) = output_data else {
            return None;
        };
        let scheme = EncryptedScheme::from_byte(*blob.first()?).ok()?;
        (scheme == EncryptedScheme::Confidential).then(|| {
            blob.drain(..1);
            (slot_index, slot, blob)
        })
    })
}

pub(crate) fn parse_order_data(records: &[DataRecord]) -> Result<PlainTextData> {
    let order_bytes = records
        .iter()
        .find_map(|record| match record {
            DataRecord::UtxoData(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("order plaintext carries no utxo data record"))?;
    PlainTextData::deserialize(order_bytes)
}
