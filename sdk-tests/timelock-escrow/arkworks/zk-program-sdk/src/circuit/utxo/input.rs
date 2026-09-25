use zolana_interface::DUMMY_DOMAIN;

use crate::{
    circuit::{constant, poseidon, zero, Assert, CircuitVar},
    RelationError,
};

#[derive(Clone, Debug)]
pub struct Utxo {
    pub domain: CircuitVar,
    pub owner: CircuitVar,
    pub asset: CircuitVar,
    pub amount: CircuitVar,
    pub blinding: CircuitVar,
    pub data_hash: CircuitVar,
    pub ring_data_hash: CircuitVar,
    pub ring_program_id: CircuitVar,
    pub tree_id: CircuitVar,
}

impl Default for Utxo {
    fn default() -> Self {
        Self {
            domain: zero(),
            owner: zero(),
            asset: zero(),
            amount: zero(),
            blinding: zero(),
            data_hash: zero(),
            ring_data_hash: zero(),
            ring_program_id: zero(),
            tree_id: zero(),
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

    pub fn hash(&self) -> Result<CircuitVar, RelationError> {
        let ring = poseidon(&[self.ring_data_hash.clone(), self.ring_program_id.clone()])?;
        let owner = poseidon(&[self.owner.clone(), self.blinding.clone()])?;
        poseidon(&[
            self.domain.clone(),
            self.tree_id.clone(),
            self.asset.clone(),
            self.amount.clone(),
            self.data_hash.clone(),
            ring,
            owner,
        ])
    }

    pub(super) fn assert_default_ring(&self) -> Result<(), RelationError> {
        self.ring_data_hash
            .assert_equal(&zero(), "the utxo is in a ring")?;
        self.ring_program_id
            .assert_equal(&zero(), "the utxo is in a ring")
    }
}
