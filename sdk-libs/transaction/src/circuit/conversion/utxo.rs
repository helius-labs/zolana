use std::collections::HashMap;

use ark_bn254::Fr;
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::DUMMY_DOMAIN;
use zolana_keypair::circuit::{client, owner};
use zolana_zk_dsl::{
    circuit::{constant, labels::Scope, Assert, CircuitVar, Uint, VariableRole},
    conversion::{Allocator, Dummy, Placeholder, ProofInput},
    CircuitError,
};

use super::asset::MintRecords;
use crate::{
    circuit::{self, UtxoCircuitErrorKind},
    utxo::{ProofInputUtxo, SppProofInputUtxo},
    WalletUtxo,
};

/// The utxos a native instantiation met, by utxo hash.
#[derive(Default)]
pub struct UtxoRecords(HashMap<[u8; 32], WalletUtxo>);

impl UtxoRecords {
    pub fn get(&self, utxo_hash: &[u8; 32]) -> Option<&WalletUtxo> {
        self.0.get(utxo_hash)
    }
}

impl ProofInput for WalletUtxo {
    type Circuit = circuit::Utxo;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Utxo, CircuitError> {
        let _scope = Scope::open(&allocator.cs(), "a utxo proof input");
        let spp_input = SppProofInputUtxo::from(self);
        let fields =
            ProofInputUtxo::try_from(&spp_input).map_err(UtxoCircuitErrorKind::InvalidUtxo)?;
        let domain = field(
            allocator,
            &fields.domain,
            "utxo domain",
            VariableRole::Constrained,
        )?;
        let dummy = domain.is_equal(&constant(u64::from(DUMMY_DOMAIN)))?;
        let owner_preimage = if spp_input.is_dummy() {
            client::UtxoOwner {
                tag: 0,
                key: [0u8; 32],
                nullifier_pk: [0u8; 32],
            }
        } else {
            let asset_hash = hash_bytes(self.utxo.asset.asset.as_array())?;
            allocator.record(|records: &mut MintRecords| {
                records.0.insert(asset_hash, self.utxo.asset);
            });
            allocator.record(|records: &mut UtxoRecords| {
                records.0.insert(self.utxo_hash, self.clone());
            });
            client::UtxoOwner::try_from((&self.utxo.owner, self.nullifier_pubkey))?
        };
        // A dummy contributes no owner hash and skips the tag check, so its
        // owner tag and nullifier public key are intentionally unused. A real
        // input binds both through its commitment and the tag check, so the
        // free-variable check keeps reporting them if that ever breaks.
        let unused_role = if spp_input.is_dummy() {
            VariableRole::Carried
        } else {
            VariableRole::Constrained
        };
        Ok(circuit::Utxo {
            domain,
            owner: owner(allocator, &owner_preimage, &dummy, unused_role)?,
            asset: self.utxo.asset.asset.instantiate(allocator)?,
            amount: Uint::trusted(field(
                allocator,
                &fields.amount,
                "utxo amount",
                VariableRole::Constrained,
            )?),
            blinding: field(
                allocator,
                &fields.blinding,
                "utxo blinding",
                VariableRole::Constrained,
            )?,
            data_hash: field(
                allocator,
                &fields.data_hash,
                "utxo data hash",
                VariableRole::Constrained,
            )?,
            ring_data_hash: field(
                allocator,
                &fields.ring_data_hash,
                "utxo ring data hash",
                VariableRole::Constrained,
            )?,
            ring_program_id: field(
                allocator,
                &fields.ring_program_id,
                "utxo ring program id",
                VariableRole::Constrained,
            )?,
            tree_id: field(
                allocator,
                &fields.tree_id,
                "utxo tree id",
                VariableRole::Constrained,
            )?,
            meta: circuit::UtxoMeta {
                nullifier: field(
                    allocator,
                    &self.nullifier,
                    "utxo nullifier",
                    VariableRole::Carried,
                )?,
                latest_tree_id: allocator.witness(
                    Fr::from(self.latest_tree_id.unwrap_or(0)),
                    "utxo latest tree id",
                    VariableRole::Carried,
                )?,
                has_latest_tree_id: self.latest_tree_id.is_some().instantiate(allocator)?,
            },
        })
    }
}

#[track_caller]
fn field(
    allocator: &Allocator,
    bytes: &[u8; 32],
    name: &'static str,
    role: VariableRole,
) -> Result<CircuitVar, CircuitError> {
    allocator.witness(
        zolana_zk_dsl::conversion::field(bytes, name)?.into(),
        name,
        role,
    )
}

impl Placeholder for WalletUtxo {
    fn placeholder() -> Result<Self, CircuitError> {
        <Self as Dummy>::dummy(None)
    }
}

const PADDING_BLINDING: [u8; 32] = [0u8; 32];
const PADDING_TREE_ID: u16 = 0;

impl Dummy for WalletUtxo {
    fn dummy(first: Option<&Self>) -> Result<Self, CircuitError> {
        let tree_id = first.map_or(PADDING_TREE_ID, |first| first.tree_id);
        Ok(WalletUtxo::dummy_with_blinding(PADDING_BLINDING, tree_id)
            .map_err(UtxoCircuitErrorKind::InvalidUtxo)?)
    }
}
