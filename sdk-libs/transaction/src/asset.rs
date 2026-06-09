use std::collections::HashMap;

use solana_address::Address;

use crate::error::TransactionError;

pub const SOL_ASSET_ID: u64 = 1;
pub const SOL_MINT: Address = Address::new_from_array([0u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetRegistry(HashMap<u64, Address>);

impl AssetRegistry {
    pub fn new(entries: impl IntoIterator<Item = (u64, Address)>) -> Self {
        let mut map: HashMap<u64, Address> = entries.into_iter().collect();
        map.insert(SOL_ASSET_ID, SOL_MINT);
        Self(map)
    }

    pub fn insert(&mut self, asset_id: u64, mint: Address) -> Option<Address> {
        self.0.insert(asset_id, mint)
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
}

impl Default for AssetRegistry {
    fn default() -> Self {
        Self::new([])
    }
}
