use spr_keypair::ShieldedAddress;
use spr_program::{
    circuit::{Assert, Circuit, DataHash, Field, Select, SigningPubkey, UtxoOwner},
    conversion::ProofInput,
    CircuitError, UtxoOwner as ClientOwner,
};

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

impl Circuit for OwnerHashCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        self.owner
            .owner()
            .hash()?
            .assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Identity {
    pub identity: Field,
    pub owner: ShieldedAddress,
}

impl Circuit for IdentityCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
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

impl Circuit for PreimageHashCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        self.owner.hash()?.assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct HashedTwice {
    pub hash: Field,
    pub identity: Field,
    pub owner: ClientOwner,
}

impl Circuit for HashedTwiceCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
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

impl Circuit for OwnerDataHashCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        DataHash::hash(&self.owner)?.assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Instantiated {
    pub owner: ClientOwner,
}

impl Circuit for InstantiatedCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Pair {
    pub left: ClientOwner,
    pub right: ClientOwner,
}

impl Circuit for PairCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct KeyEqual {
    pub left: ClientOwner,
    pub right: ClientOwner,
}

impl Circuit for KeyEqualCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        self.left.key().assert_equal(self.right.key(), EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct OwnerEqual {
    pub left: ClientOwner,
    pub right: ClientOwner,
}

impl Circuit for OwnerEqualCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        self.left.assert_equal(&self.right, EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct KeyEqualIf {
    pub left: ClientOwner,
    pub right: ClientOwner,
    pub condition: bool,
}

impl Circuit for KeyEqualIfCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
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

impl Circuit for OwnerEqualIfCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
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

impl Circuit for KeyIsEqualCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
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

impl Circuit for OwnerIsEqualCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
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

impl Circuit for KeySelectedCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        SigningPubkey::select(&self.condition, self.if_true.key(), self.if_false.key())
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

impl Circuit for OwnerSelectedCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        UtxoOwner::select(&self.condition, &self.if_true, &self.if_false)
            .hash()?
            .assert_equal(&self.hash, HASH_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct OwnerTag {
    pub owner: ClientOwner,
}

impl Circuit for OwnerTagCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        Ok(())
    }
}

pub fn owner_tag(tag: u8) -> OwnerTag {
    OwnerTag {
        owner: ClientOwner {
            tag,
            key: [7u8; 32],
            nullifier_pk: [9u8; 32],
        },
    }
}
