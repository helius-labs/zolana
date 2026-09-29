use zk_program_sdk::{
    circuit::{constant, Assert, CircuitVar, Constraints, Field, Uint},
    conversion::ProofInput,
    CircuitError,
};

pub const WIDTH_RULE: &str = "a value does not fit in its bit width";
pub const RULE: &str = "the value is the claimed value";
pub const FILE: &str = file!();

pub const X_WIRE: usize = 1;
pub const FIRST_BIT: usize = 2;

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Borrowed<const BITS: u32> {
    pub x: Field,
}

impl<const BITS: u32> Constraints for BorrowedCircuit<BITS> {
    fn constraints(&self) -> Result<(), CircuitError> {
        Uint::<BITS>::try_from(&self.x).map(drop)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Owned<const BITS: u32> {
    pub x: Field,
}

impl<const BITS: u32> Constraints for OwnedCircuit<BITS> {
    fn constraints(&self) -> Result<(), CircuitError> {
        Uint::<BITS>::try_from(self.x.clone()).map(drop)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct IntoVar<const BITS: u32> {
    pub x: Field,
    pub claimed: Field,
}

impl<const BITS: u32> Constraints for IntoVarCircuit<BITS> {
    fn constraints(&self) -> Result<(), CircuitError> {
        CircuitVar::from(Uint::<BITS>::try_from(&self.x)?).assert_equal(&self.claimed, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct FromBool<const BITS: u32> {
    pub bit: bool,
    pub claimed: Field,
}

impl<const BITS: u32> Constraints for FromBoolCircuit<BITS> {
    fn constraints(&self) -> Result<(), CircuitError> {
        CircuitVar::from(Uint::<BITS>::from(self.bit.clone())).assert_equal(&self.claimed, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Constants {
    pub x: Field,
}

impl Constraints for ConstantsCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let checked = Uint::<4>::try_from(constant(15u64))?;
        let built = Uint::<4>::constant(15)?;
        CircuitVar::from(checked).assert_equal(&self.x, RULE)?;
        CircuitVar::from(built).assert_equal(&self.x, RULE)?;
        CircuitVar::from(Uint::<4>::zero()).assert_equal(&constant(0u64), RULE)
    }
}
