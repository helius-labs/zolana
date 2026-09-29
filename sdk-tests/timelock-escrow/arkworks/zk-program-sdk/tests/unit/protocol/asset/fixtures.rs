use zk_program_sdk::{
    circuit::{Assert, Asset, Constraints, DataHash, Field, Select},
    conversion::ProofInput,
    CircuitError,
};
use zolana_transaction::Mint;

use crate::harness::fixture::{rule_broken, Refusal};

pub const HASH_RULE: &str = "the asset hash is hash_bytes of the mint";
pub const EQUAL_RULE: &str = "the assets are equal";
pub const IS_EQUAL_RULE: &str = "the claim is whether the assets are equal";
pub const FILE: &str = file!();

pub const HASH_BROKEN: Refusal = rule_broken(HASH_RULE, FILE);
pub const EQUAL_BROKEN: Refusal = rule_broken(EQUAL_RULE, FILE);
pub const IS_EQUAL_BROKEN: Refusal = rule_broken(IS_EQUAL_RULE, FILE);

pub const HASH_WIRE: usize = 1;

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssetHash {
    pub hash: Field,
    pub mint: Mint,
}

impl Constraints for AssetHashCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.mint.hash()?.assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct HashedTwice {
    pub hash: Field,
    pub mint: Mint,
}

impl Constraints for HashedTwiceCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let clone = self.mint.clone();
        self.mint.hash()?.assert_equal(&self.hash, HASH_RULE)?;
        clone.hash()?.assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssetDataHash {
    pub hash: Field,
    pub mint: Mint,
}

impl Constraints for AssetDataHashCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        DataHash::hash(&self.mint)?.assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct SolHash {
    pub hash: Field,
}

impl Constraints for SolHashCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        Asset::sol().hash()?.assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Single {
    pub mint: Mint,
}

impl Constraints for SingleCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Pair {
    pub left: Mint,
    pub right: Mint,
}

impl Constraints for PairCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Equal {
    pub left: Mint,
    pub right: Mint,
}

impl Constraints for EqualCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left.assert_equal(&self.right, EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct EqualIf {
    pub left: Mint,
    pub right: Mint,
    pub condition: bool,
}

impl Constraints for EqualIfCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left
            .assert_equal_if(&self.right, &self.condition, EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct IsEqual {
    pub left: Mint,
    pub right: Mint,
    pub claimed: bool,
}

impl Constraints for IsEqualCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left
            .is_equal(&self.right)?
            .assert_equal(&self.claimed, IS_EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct NotEqual {
    pub left: Mint,
    pub right: Mint,
}

impl Constraints for NotEqualCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left.assert_not_equal(&self.right, EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct EqualsConstant {
    pub mint: Mint,
}

pub const CONSTANT_MINT: Mint = super::vectors::USDC;

impl Constraints for EqualsConstantCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.mint
            .assert_equal(&Asset::constant(&CONSTANT_MINT.asset), EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Selected {
    pub hash: Field,
    pub condition: bool,
    pub if_true: Mint,
    pub if_false: Mint,
}

impl Constraints for SelectedCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        Asset::select(&self.condition, &self.if_true, &self.if_false)
            .hash()?
            .assert_equal(&self.hash, HASH_RULE)
    }
}
