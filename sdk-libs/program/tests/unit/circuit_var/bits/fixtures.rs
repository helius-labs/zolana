use zolana_program::{
    circuit::{constant, from_bits_le, Assert, Bits, Bool, CircuitVar, Constraints, Field},
    conversion::ProofInput,
    CircuitError,
};

use crate::harness::fixture::Refusal;

pub const FILE: &str = file!();

pub const WIDTH_RULE: &str = "a value does not fit in its bit width";
pub const BOOL_RULE: &str = "a value is neither 0 nor 1";
pub const TO_BITS_RULE: &str = "the claimed bits are x's little-endian bits";
pub const FROM_BITS_RULE: &str = "the value is the bits' little-endian sum";

pub const VALUE_TOO_LARGE: Refusal = ("CircuitError.ValueTooLarge", None, FILE);
pub const BIT_WIDTH_TOO_LARGE: Refusal = ("CircuitError.BitWidthTooLarge", None, FILE);
pub const NOT_ZERO_OR_ONE: Refusal = ("CircuitError.NotZeroOrOne", None, FILE);

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct CheckBits<const N: usize> {
    pub x: Field,
}

impl<const N: usize> Constraints for CheckBitsCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.x.check_bits(N)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct CheckIsBool {
    pub x: Field,
}

impl Constraints for CheckIsBoolCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.x.check_is_bool()
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ToBits<const N: usize> {
    pub x: Field,
    pub bits: [Field; N],
}

impl<const N: usize> Constraints for ToBitsCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let bits = self.x.to_bits_le::<N>()?;
        bits.iter().zip(&self.bits).try_for_each(|(bit, claimed)| {
            CircuitVar::from(bit.clone()).assert_equal(claimed, TO_BITS_RULE)
        })
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct FromBits<const N: usize> {
    pub bits: [Field; N],
    pub value: Field,
}

impl<const N: usize> Constraints for FromBitsCircuit<N> {
    #[allow(clippy::redundant_closure)]
    fn constraints(&self) -> Result<(), CircuitError> {
        let bits = self
            .bits
            .iter()
            // A closure, not `Bool::try_from` itself: through a function value
            // `#[track_caller]` locates a refusal in core's `call_once`.
            .map(|bit| Bool::try_from(bit))
            .collect::<Result<Vec<_>, _>>()?;
        from_bits_le(&bits).assert_equal(&self.value, FROM_BITS_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ConstantCheckBits<const VALUE: u64, const N: usize> {
    pub unused: Field,
}

impl<const VALUE: u64, const N: usize> Constraints for ConstantCheckBitsCircuit<VALUE, N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        constant(VALUE).check_bits(N)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ConstantIsBool<const VALUE: u64> {
    pub unused: Field,
}

impl<const VALUE: u64> Constraints for ConstantIsBoolCircuit<VALUE> {
    fn constraints(&self) -> Result<(), CircuitError> {
        constant(VALUE).check_is_bool()
    }
}

/// The low `N` bits of `value`, least significant first, as field elements.
pub fn low_bits<const N: usize>(value: u64) -> [Field; N] {
    std::array::from_fn(|bit| Field::from(bit < 64 && (value >> bit) & 1 == 1))
}
