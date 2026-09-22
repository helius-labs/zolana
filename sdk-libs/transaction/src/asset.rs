use std::collections::HashMap;

use solana_address::Address;

use crate::{error::TransactionError, utxo::WalletUtxo};

pub const SOL_ASSET_ID: u64 = 1;
pub const SOL_MINT: Address = Address::new_from_array([0u8; 32]);

/// A mint address used in commitments and its compact ID used in payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Mint {
    pub asset: Address,
    pub asset_id: u64,
}

impl Mint {
    pub const SOL: Self = Self::new(SOL_MINT, SOL_ASSET_ID);

    pub const fn new(asset: Address, asset_id: u64) -> Self {
        Self { asset, asset_id }
    }
}

impl Default for Mint {
    fn default() -> Self {
        Self::SOL
    }
}

/// One mint's verified balance and spendable notes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetBalance {
    pub asset_id: u64,
    pub mint: Address,
    pub amount: u64,
    pub utxos: Vec<WalletUtxo>,
}

/// Spendable default-ring balances. Ring-bound notes are never in here; a
/// wallet reports those separately.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Balances {
    pub assets: Vec<AssetBalance>,
}

impl Balances {
    pub fn get_balance(&self, mint: Address) -> Option<&AssetBalance> {
        self.assets.iter().find(|balance| balance.mint == mint)
    }
}

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

    pub fn resolve(&self, asset_id: u64) -> Result<Mint, TransactionError> {
        self.0
            .get(&asset_id)
            .copied()
            .map(|asset| Mint::new(asset, asset_id))
            .ok_or(TransactionError::UnknownAsset(asset_id))
    }

    pub fn mint(&self, asset: &Address) -> Result<Mint, TransactionError> {
        Ok(Mint::new(*asset, self.asset_id(asset)?))
    }

    pub fn asset_id(&self, mint: &Address) -> Result<u64, TransactionError> {
        self.0
            .iter()
            .find_map(|(id, m)| (m == mint).then_some(*id))
            .ok_or(TransactionError::UnknownMint(*mint))
    }

    pub fn address_for_field(&self, field: &[u8; 32]) -> Result<Option<Address>, TransactionError> {
        for mint in self.0.values() {
            let mint_field = zolana_hasher::primitives::hash_bytes(mint.as_array())?;
            if &mint_field == field {
                return Ok(Some(*mint));
            }
        }
        Ok(None)
    }
}

impl Default for AssetRegistry {
    fn default() -> Self {
        Self(HashMap::from([(SOL_ASSET_ID, SOL_MINT)]))
    }
}
