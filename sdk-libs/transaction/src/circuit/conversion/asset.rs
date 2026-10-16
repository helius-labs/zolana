use std::collections::HashMap;

use solana_address::Address;
use zolana_hasher::primitives::hash_bytes;
use zolana_zk_dsl::{
    conversion::{Allocator, Placeholder, ProofInput},
    Bytes, CircuitError,
};

use crate::{circuit, Mint};

/// The mints a native instantiation met, by asset hash.
#[derive(Default)]
pub struct MintRecords(pub(crate) HashMap<[u8; 32], Mint>);

impl MintRecords {
    pub fn get(&self, asset_hash: &[u8; 32]) -> Option<&Mint> {
        self.0.get(asset_hash)
    }
}

impl ProofInput for Mint {
    type Circuit = circuit::Asset;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Asset, CircuitError> {
        let asset_hash = hash_bytes(self.asset.as_array())?;
        allocator.record(|records: &mut MintRecords| {
            records.0.insert(asset_hash, *self);
        });
        asset(allocator, &self.asset)
    }
}

#[doc(hidden)]
pub fn asset(allocator: &Allocator, mint: &Address) -> Result<circuit::Asset, CircuitError> {
    Ok(circuit::Asset::new(
        Bytes(*mint.as_array()).instantiate(allocator)?,
    ))
}

impl Placeholder for Mint {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Mint::SOL)
    }
}
