use std::{cell::OnceCell, rc::Rc};

use solana_address::Address;
use zolana_zk_dsl::{
    circuit::{
        builtins::{
            field::var::cached,
            ops::assert::{all_equal, assert_all_equal, assert_all_equal_if},
            types::bytes::packed,
        },
        Assert, Bool, Bytes, CircuitDefault, CircuitType, CircuitVar, Select,
    },
    CircuitError,
};
use zolana_zk_gadgets::HashBytes;

use crate::SOL_MINT;

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

    pub fn hash(&self) -> Result<CircuitVar, CircuitError> {
        cached(&self.hash, || self.bytes.hash_bytes())
    }

    #[doc(hidden)]
    pub fn is_clone_of(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.hash, &other.hash)
    }
}

impl Default for Asset {
    fn default() -> Self {
        Self::sol()
    }
}

impl Assert for Asset {
    fn is_equal(&self, other: &Self) -> Result<Bool, CircuitError> {
        all_equal(&packed(self.bytes.bytes()), &packed(other.bytes.bytes()))
    }

    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), CircuitError> {
        assert_all_equal(
            &packed(self.bytes.bytes()),
            &packed(other.bytes.bytes()),
            rule,
        )
    }

    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), CircuitError> {
        assert_all_equal_if(
            &packed(self.bytes.bytes()),
            &packed(other.bytes.bytes()),
            condition,
            rule,
        )
    }
}

impl Select for Asset {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self {
        Self::new(Bytes::select(condition, &if_true.bytes, &if_false.bytes))
    }
}

impl CircuitType for Asset {}

impl CircuitDefault for Asset {
    fn circuit_default() -> Self {
        Asset::default()
    }
}
