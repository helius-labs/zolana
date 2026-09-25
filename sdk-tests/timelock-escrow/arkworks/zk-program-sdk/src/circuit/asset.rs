use std::{cell::OnceCell, rc::Rc};

use ark_r1cs_std::boolean::Boolean;
use solana_address::Address;
use zolana_transaction::SOL_MINT;

use super::{
    var::{assert_equal_unless, cached},
    Bytes, CircuitVar, Field,
};
use crate::{circuit_lib::packed, RelationError};

#[derive(Clone, Debug)]
pub struct Asset {
    bytes: Bytes<32>,
    hash: Rc<OnceCell<CircuitVar>>,
}

impl Asset {
    pub(crate) fn new(bytes: Bytes<32>) -> Self {
        Self {
            bytes,
            hash: Rc::new(OnceCell::new()),
        }
    }

    pub fn constant(mint: &Address) -> Self {
        Self::new(Bytes::constant(mint.as_array()))
    }

    pub fn sol() -> Self {
        Self::constant(&SOL_MINT)
    }

    pub fn hash(&self) -> Result<CircuitVar, RelationError> {
        cached(&self.hash, || self.bytes.hash_bytes())
    }

    pub(crate) fn is_clone_of(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.hash, &other.hash)
    }

    pub(crate) fn assert_same_unless(
        &self,
        other: &Self,
        skip: &Boolean<Field>,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        for (left, right) in packed(self.bytes.bytes())
            .iter()
            .zip(&packed(other.bytes.bytes()))
        {
            assert_equal_unless(left, right, skip, rule)?;
        }
        Ok(())
    }
}

impl Default for Asset {
    fn default() -> Self {
        Self::sol()
    }
}
