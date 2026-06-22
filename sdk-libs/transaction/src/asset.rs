use std::collections::HashMap;

use solana_address::Address;
use zolana_keypair::hash::hash_field;

use crate::error::TransactionError;

pub const SOL_ASSET_ID: u64 = 1;
pub const SOL_MINT: Address = Address::new_from_array([0u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetRegistry(HashMap<u64, Address>);

impl AssetRegistry {
    pub fn new(
        entries: impl IntoIterator<Item = (u64, Address)>,
    ) -> Result<Self, TransactionError> {
        let mut registry = Self::default();
        for (asset_id, mint) in entries {
            registry.insert(asset_id, mint)?;
        }
        Ok(registry)
    }

    pub fn insert(&mut self, asset_id: u64, mint: Address) -> Result<(), TransactionError> {
        if asset_id == SOL_ASSET_ID {
            return Err(TransactionError::ReservedAssetId(asset_id));
        }
        if self.0.contains_key(&asset_id) {
            return Err(TransactionError::DuplicateAssetId(asset_id));
        }
        if self.0.values().any(|m| m == &mint) {
            return Err(TransactionError::DuplicateMint(mint));
        }
        self.0.insert(asset_id, mint);
        Ok(())
    }

    pub fn resolve(&self, asset_id: u64) -> Result<Address, TransactionError> {
        self.0
            .get(&asset_id)
            .copied()
            .ok_or(TransactionError::UnknownAsset(asset_id))
    }

    pub fn asset_id(&self, mint: &Address) -> Result<u64, TransactionError> {
        self.0
            .iter()
            .find_map(|(id, m)| (m == mint).then_some(*id))
            .ok_or(TransactionError::UnknownMint(*mint))
    }

    pub fn mint_for_asset_field(
        &self,
        asset_field: &[u8; 32],
    ) -> Result<Address, TransactionError> {
        if &hash_field(SOL_MINT.as_array()).map_err(|e| TransactionError::Hash(e.to_string()))?
            == asset_field
        {
            return Ok(SOL_MINT);
        }
        for mint in self.0.values() {
            if &hash_field(mint.as_array()).map_err(|e| TransactionError::Hash(e.to_string()))?
                == asset_field
            {
                return Ok(*mint);
            }
        }
        Err(TransactionError::UnknownAssetField(*asset_field))
    }
}

impl Default for AssetRegistry {
    fn default() -> Self {
        Self(HashMap::from([(SOL_ASSET_ID, SOL_MINT)]))
    }
}
