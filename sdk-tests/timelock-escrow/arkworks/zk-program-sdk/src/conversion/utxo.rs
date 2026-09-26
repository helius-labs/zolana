use ark_r1cs_std::eq::EqGadget;
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::DUMMY_DOMAIN;
use zolana_transaction::{
    utxo::{ProofInputUtxo, SppProofInputUtxo},
    WalletUtxo,
};

use super::{asset::asset, owner::owner, var, Allocator, Placeholder, ProofInput};
use crate::{
    circuit::{self, constant, CircuitVar},
    client, RelationError,
};

impl ProofInput for WalletUtxo {
    type Circuit = circuit::Utxo;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Utxo, RelationError> {
        let spp_input = SppProofInputUtxo::from(self);
        let fields = ProofInputUtxo::try_from(&spp_input).map_err(RelationError::input)?;
        let domain = field(allocator, &fields.domain, "utxo domain")?;
        let dummy = domain.is_eq(&constant(u64::from(DUMMY_DOMAIN)))?;
        let owner_preimage = if spp_input.is_dummy() {
            client::Owner {
                tag: 0,
                key: [0u8; 32],
                nullifier_pk: [0u8; 32],
            }
        } else {
            let asset_hash = hash_bytes(self.utxo.asset.asset.as_array())?;
            allocator.record(|records| {
                records.mints.insert(asset_hash, self.utxo.asset);
                records.utxos.insert(self.utxo_hash, self.clone());
            });
            client::Owner::try_from((&self.utxo.owner, self.nullifier_pubkey))?
        };
        Ok(circuit::Utxo {
            domain,
            owner: owner(allocator, &owner_preimage, &dummy)?,
            asset: asset(allocator, &self.utxo.asset.asset)?,
            amount: field(allocator, &fields.amount, "utxo amount")?,
            blinding: field(allocator, &fields.blinding, "utxo blinding")?,
            data_hash: field(allocator, &fields.data_hash, "utxo data hash")?,
            ring_data_hash: field(allocator, &fields.ring_data_hash, "utxo ring data hash")?,
            ring_program_id: field(allocator, &fields.ring_program_id, "utxo ring program id")?,
            tree_id: field(allocator, &fields.tree_id, "utxo tree id")?,
            nullifier: field(allocator, &self.nullifier, "utxo nullifier")?,
            latest_tree_id: allocator
                .private_input(&constant(u64::from(self.latest_tree_id.unwrap_or(0))))?,
            has_latest_tree_id: self.latest_tree_id.is_some().instantiate(allocator)?,
        })
    }
}

fn field(
    allocator: &Allocator,
    bytes: &[u8; 32],
    name: &'static str,
) -> Result<CircuitVar, RelationError> {
    allocator.private_input(&var(bytes, name)?)
}

impl Placeholder for WalletUtxo {
    fn placeholder() -> Result<Self, RelationError> {
        WalletUtxo::dummy(0).map_err(RelationError::input)
    }
}
