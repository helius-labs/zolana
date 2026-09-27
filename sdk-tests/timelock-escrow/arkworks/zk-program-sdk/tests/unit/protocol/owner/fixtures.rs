use zk_program_sdk::{
    circuit::{Assert, Constraints, DataHash, Field, Owner, OwnerKey, Select},
    conversion::ProofInput,
    CircuitError, Owner as ClientOwner,
};
use zolana_keypair::ShieldedAddress;

use crate::harness::fixture::{rule_broken, Refusal};

pub const HASH_RULE: &str = "the owner hash is Poseidon(identity, nullifier_pk)";
pub const IDENTITY_RULE: &str = "the identity is hash_bytes(tag || key)";
pub const EQUAL_RULE: &str = "the owners are equal";
pub const IS_EQUAL_RULE: &str = "the claim is whether the owners are equal";
pub const FILE: &str = file!();

pub const HASH_BROKEN: Refusal = rule_broken(HASH_RULE, FILE);
pub const IDENTITY_BROKEN: Refusal = rule_broken(IDENTITY_RULE, FILE);
pub const EQUAL_BROKEN: Refusal = rule_broken(EQUAL_RULE, FILE);
pub const IS_EQUAL_BROKEN: Refusal = rule_broken(IS_EQUAL_RULE, FILE);

pub const CLAIM_WIRE: usize = 1;

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct OwnerHash {
    pub hash: Field,
    pub owner: ShieldedAddress,
}

impl Constraints for OwnerHashCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.owner.hash()?.assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Identity {
    pub identity: Field,
    pub owner: ShieldedAddress,
}

impl Constraints for IdentityCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.owner
            .key()
            .identity()?
            .assert_equal(&self.identity, IDENTITY_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct PreimageHash {
    pub hash: Field,
    pub owner: ClientOwner,
}

impl Constraints for PreimageHashCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.owner.hash()?.assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct HashedTwice {
    pub hash: Field,
    pub identity: Field,
    pub owner: ClientOwner,
}

impl Constraints for HashedTwiceCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let clone = self.owner.clone();
        self.owner.hash()?.assert_equal(&self.hash, HASH_RULE)?;
        clone.hash()?.assert_equal(&self.hash, HASH_RULE)?;
        clone
            .key()
            .identity()?
            .assert_equal(&self.identity, IDENTITY_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct OwnerDataHash {
    pub hash: Field,
    pub owner: ClientOwner,
}

impl Constraints for OwnerDataHashCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        DataHash::hash(&self.owner)?.assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Instantiated {
    pub owner: ClientOwner,
}

impl Constraints for InstantiatedCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Pair {
    pub left: ClientOwner,
    pub right: ClientOwner,
}

impl Constraints for PairCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct KeyEqual {
    pub left: ClientOwner,
    pub right: ClientOwner,
}

impl Constraints for KeyEqualCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left.key().assert_equal(self.right.key(), EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct OwnerEqual {
    pub left: ClientOwner,
    pub right: ClientOwner,
}

impl Constraints for OwnerEqualCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left.assert_equal(&self.right, EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct KeyEqualIf {
    pub left: ClientOwner,
    pub right: ClientOwner,
    pub condition: bool,
}

impl Constraints for KeyEqualIfCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left
            .key()
            .assert_equal_if(self.right.key(), &self.condition, EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct OwnerEqualIf {
    pub left: ClientOwner,
    pub right: ClientOwner,
    pub condition: bool,
}

impl Constraints for OwnerEqualIfCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left
            .assert_equal_if(&self.right, &self.condition, EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct KeyIsEqual {
    pub left: ClientOwner,
    pub right: ClientOwner,
    pub claimed: bool,
}

impl Constraints for KeyIsEqualCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left
            .key()
            .is_equal(self.right.key())?
            .assert_equal(&self.claimed, IS_EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct OwnerIsEqual {
    pub left: ClientOwner,
    pub right: ClientOwner,
    pub claimed: bool,
}

impl Constraints for OwnerIsEqualCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left
            .is_equal(&self.right)?
            .assert_equal(&self.claimed, IS_EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct KeySelected {
    pub identity: Field,
    pub condition: bool,
    pub if_true: ClientOwner,
    pub if_false: ClientOwner,
}

impl Constraints for KeySelectedCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        OwnerKey::select(&self.condition, self.if_true.key(), self.if_false.key())
            .identity()?
            .assert_equal(&self.identity, IDENTITY_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct OwnerSelected {
    pub hash: Field,
    pub condition: bool,
    pub if_true: ClientOwner,
    pub if_false: ClientOwner,
}

impl Constraints for OwnerSelectedCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        Owner::select(&self.condition, &self.if_true, &self.if_false)
            .hash()?
            .assert_equal(&self.hash, HASH_RULE)
    }
}
