use spr_program::{
    circuit::{Assert, Circuit, DataHash, Field, HashBytes, Select, SolanaAddress},
    conversion::ProofInput,
    CircuitError,
};
use spr_transaction::Mint;

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

impl Circuit for AssetHashCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        self.mint.hash_bytes()?.assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct HashedTwice {
    pub hash: Field,
    pub mint: Mint,
}

impl Circuit for HashedTwiceCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let clone = self.mint.clone();
        self.mint
            .hash_bytes()?
            .assert_equal(&self.hash, HASH_RULE)?;
        clone.hash_bytes()?.assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssetDataHash {
    pub hash: Field,
    pub mint: Mint,
}

impl Circuit for AssetDataHashCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        DataHash::hash(&self.mint)?.assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct SolHash {
    pub hash: Field,
}

impl Circuit for SolHashCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        SolanaAddress::constant(&spr_transaction::SOL_MINT)
            .hash_bytes()?
            .assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Single {
    pub mint: Mint,
}

impl Circuit for SingleCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Pair {
    pub left: Mint,
    pub right: Mint,
}

impl Circuit for PairCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Equal {
    pub left: Mint,
    pub right: Mint,
}

impl Circuit for EqualCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        self.left.assert_equal(&self.right, EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct EqualIf {
    pub left: Mint,
    pub right: Mint,
    pub condition: bool,
}

impl Circuit for EqualIfCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
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

impl Circuit for IsEqualCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
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

impl Circuit for NotEqualCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        self.left.assert_not_equal(&self.right, EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct EqualsConstant {
    pub mint: Mint,
}

pub const CONSTANT_MINT: Mint = super::vectors::USDC;

impl Circuit for EqualsConstantCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        self.mint
            .assert_equal(&SolanaAddress::constant(&CONSTANT_MINT.asset), EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Selected {
    pub hash: Field,
    pub condition: bool,
    pub if_true: Mint,
    pub if_false: Mint,
}

impl Circuit for SelectedCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        SolanaAddress::select(&self.condition, &self.if_true, &self.if_false)
            .hash_bytes()?
            .assert_equal(&self.hash, HASH_RULE)
    }
}
