use solana_address::Address;
use zolana_hasher::primitives::hash_bytes;
use zolana_transaction::Mint;

use super::{Allocator, ProofInput};
use crate::{circuit, client, RelationError};

impl ProofInput for Mint {
    type Circuit = circuit::Asset;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Asset, RelationError> {
        let asset_hash = hash_bytes(self.asset.as_array())?;
        allocator.record(|records| {
            records.mints.insert(asset_hash, *self);
        });
        asset(allocator, &self.asset)
    }
}

pub(super) fn asset(
    allocator: &Allocator,
    mint: &Address,
) -> Result<circuit::Asset, RelationError> {
    Ok(circuit::Asset::new(
        client::Bytes(*mint.as_array()).instantiate(allocator)?,
    ))
}
