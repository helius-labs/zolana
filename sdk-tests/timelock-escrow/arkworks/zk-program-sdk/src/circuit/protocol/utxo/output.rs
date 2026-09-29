use zolana_interface::DUMMY_DOMAIN;

use super::{utxo_domain, Utxo};
use crate::{
    circuit::{constant, zero, Asset, Bool, CircuitVar, Owner, Uint},
    CircuitError,
};

#[derive(Clone, Debug)]
pub(crate) struct Output {
    pub(crate) owner: Owner,
    pub(crate) asset: Asset,
    pub(crate) amount: Uint<64>,
    pub(crate) data_hash: CircuitVar,
    pub(crate) data: Option<Vec<u8>>,
    pub(crate) empty_if_zero: bool,
}

impl Output {
    #[track_caller]
    pub(crate) fn is_empty(&self) -> Result<Bool, CircuitError> {
        if self.empty_if_zero {
            self.amount.is_zero()
        } else {
            Ok(Bool::constant(false))
        }
    }

    #[track_caller]
    pub(crate) fn hash(
        &self,
        empty: &Bool,
        blinding: CircuitVar,
        tree_id: CircuitVar,
    ) -> Result<CircuitVar, CircuitError> {
        let utxo = Utxo {
            domain: empty.select(&constant(u64::from(DUMMY_DOMAIN)), &utxo_domain()),
            owner: self.owner.clone(),
            asset: self.asset.clone(),
            amount: self.amount.clone(),
            blinding,
            data_hash: self.data_hash.clone(),
            tree_id,
            ..Utxo::default()
        };
        let owner = empty.select(&zero(), &self.owner.hash()?);
        let asset = empty.select(&zero(), &self.asset.hash()?);
        utxo.hash_with(&owner, &asset)
    }
}
