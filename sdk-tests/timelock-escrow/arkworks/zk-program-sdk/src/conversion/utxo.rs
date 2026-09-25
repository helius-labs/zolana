use zolana_client::ProofInputUtxo;
use zolana_hasher::primitives::hash_bytes;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{utxo::SppProofInputUtxo, Mint, WalletUtxo};

use super::{var, Allocator, ProofInput};
use crate::{
    circuit::{CircuitVar, Utxo},
    RelationError,
};

impl TryFrom<&ProofInputUtxo> for Utxo {
    type Error = RelationError;

    fn try_from(proof_inputs: &ProofInputUtxo) -> Result<Self, RelationError> {
        Ok(Self {
            domain: var(&proof_inputs.domain, "utxo domain")?,
            owner: var(&proof_inputs.owner_hash, "utxo owner")?,
            asset: var(&proof_inputs.asset, "utxo asset")?,
            amount: var(&proof_inputs.amount, "utxo amount")?,
            blinding: var(&proof_inputs.blinding, "utxo blinding")?,
            data_hash: var(&proof_inputs.data_hash, "utxo data hash")?,
            ring_data_hash: var(&proof_inputs.ring_data_hash, "utxo ring data hash")?,
            ring_program_id: var(&proof_inputs.ring_program_id, "utxo ring program id")?,
            tree_id: var(&proof_inputs.tree_id, "utxo tree id")?,
        })
    }
}

impl ProofInput for Utxo {
    type Circuit = Utxo;

    fn instantiate(&self, allocator: &Allocator) -> Result<Utxo, RelationError> {
        Ok(Self {
            domain: self.domain.instantiate(allocator)?,
            owner: self.owner.instantiate(allocator)?,
            asset: self.asset.instantiate(allocator)?,
            amount: self.amount.instantiate(allocator)?,
            blinding: self.blinding.instantiate(allocator)?,
            data_hash: self.data_hash.instantiate(allocator)?,
            ring_data_hash: self.ring_data_hash.instantiate(allocator)?,
            ring_program_id: self.ring_program_id.instantiate(allocator)?,
            tree_id: self.tree_id.instantiate(allocator)?,
        })
    }
}

impl ProofInput for ShieldedAddress {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, RelationError> {
        let owner_hash = self.owner_hash().map_err(RelationError::input)?;
        allocator.record(|records| {
            records.owners.insert(owner_hash, *self);
        });
        allocator.private_input(&var(&owner_hash, "owner hash")?)
    }
}

impl ProofInput for Mint {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, RelationError> {
        let asset_hash = hash_bytes(self.asset.as_array())?;
        allocator.record(|records| {
            records.mints.insert(asset_hash, *self);
        });
        allocator.private_input(&var(&asset_hash, "asset hash")?)
    }
}

impl ProofInput for WalletUtxo {
    type Circuit = Utxo;

    fn instantiate(&self, allocator: &Allocator) -> Result<Utxo, RelationError> {
        let spp_input = SppProofInputUtxo::from(self);
        let circuit_utxo =
            Utxo::try_from(&ProofInputUtxo::try_from(&spp_input).map_err(RelationError::input)?)?;
        if !spp_input.is_dummy() {
            let asset_hash = hash_bytes(self.utxo.asset.asset.as_array())?;
            allocator.record(|records| {
                records.mints.insert(asset_hash, self.utxo.asset);
                records.utxos.insert(self.utxo_hash, self.clone());
            });
        }
        circuit_utxo.instantiate(allocator)
    }
}
