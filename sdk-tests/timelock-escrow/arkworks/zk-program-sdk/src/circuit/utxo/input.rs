use zolana_interface::DUMMY_DOMAIN;

use crate::{
    circuit::{constant, poseidon, zero, Assert, Asset, Bool, CircuitVar, Owner, Uint},
    CircuitError,
};

#[derive(Clone, Debug)]
pub struct Utxo {
    pub domain: CircuitVar,
    pub owner: Owner,
    pub asset: Asset,
    pub(crate) amount: Uint<64>,
    pub blinding: CircuitVar,
    pub data_hash: CircuitVar,
    pub ring_data_hash: CircuitVar,
    pub ring_program_id: CircuitVar,
    pub tree_id: CircuitVar,
    pub nullifier: CircuitVar,
    pub latest_tree_id: CircuitVar,
    pub has_latest_tree_id: Bool,
}

#[derive(Clone, Debug)]
pub(crate) struct SpentInput {
    pub(crate) hash: CircuitVar,
    pub(crate) nullifier: CircuitVar,
    pub(crate) latest_tree_id: CircuitVar,
    pub(crate) has_latest_tree_id: Bool,
}

impl Default for Utxo {
    fn default() -> Self {
        Self {
            domain: zero(),
            owner: Owner::default(),
            asset: Asset::default(),
            amount: Uint::zero(),
            blinding: zero(),
            data_hash: zero(),
            ring_data_hash: zero(),
            ring_program_id: zero(),
            tree_id: zero(),
            nullifier: zero(),
            latest_tree_id: zero(),
            has_latest_tree_id: Bool::constant(false),
        }
    }
}

impl Utxo {
    pub fn dummy() -> Self {
        Self {
            domain: constant(u64::from(DUMMY_DOMAIN)),
            ..Self::default()
        }
    }

    #[track_caller]
    pub fn hash(&self) -> Result<CircuitVar, CircuitError> {
        self.hash_with(&self.owner.hash()?, &self.asset.hash()?)
    }

    pub(crate) fn spent(&self, hash: CircuitVar) -> SpentInput {
        SpentInput {
            hash,
            nullifier: self.nullifier.clone(),
            latest_tree_id: self.latest_tree_id.clone(),
            has_latest_tree_id: self.has_latest_tree_id.clone(),
        }
    }

    #[track_caller]
    pub(super) fn hash_with(
        &self,
        owner_hash: &CircuitVar,
        asset_hash: &CircuitVar,
    ) -> Result<CircuitVar, CircuitError> {
        let ring = poseidon(&[self.ring_data_hash.clone(), self.ring_program_id.clone()])?;
        let owner = poseidon(&[owner_hash.clone(), self.blinding.clone()])?;
        poseidon(&[
            self.domain.clone(),
            self.tree_id.clone(),
            asset_hash.clone(),
            self.amount.var(),
            self.data_hash.clone(),
            ring,
            owner,
        ])
    }

    #[track_caller]
    pub(super) fn assert_default_ring(&self) -> Result<(), CircuitError> {
        self.ring_data_hash
            .assert_equal(&zero(), "the utxo is in a ring")?;
        self.ring_program_id
            .assert_equal(&zero(), "the utxo is in a ring")
    }
}
