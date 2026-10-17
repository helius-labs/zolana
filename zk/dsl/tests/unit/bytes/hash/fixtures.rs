use zolana_program::{
    circuit::{Assert, Circuit, Field},
    conversion::ProofInput,
    Bytes, CircuitError,
};
use zolana_zk_gadgets::HashBytes as _;

use crate::harness::fixture::{rule_broken, Refusal};

pub const RULE: &str = "the hash is the hash of the bytes";
pub const FILE: &str = file!();

pub const RULE_BROKEN: Refusal = rule_broken(RULE, FILE);

/// `Bytes::hash_bytes` over range-checked bytes.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct HashBytes<const N: usize> {
    pub bytes: Bytes<N>,
    pub hash: Field,
}

impl<const N: usize> Circuit for HashBytesCircuit<N> {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        self.bytes.hash_bytes()?.assert_equal(&self.hash, RULE)
    }
}
