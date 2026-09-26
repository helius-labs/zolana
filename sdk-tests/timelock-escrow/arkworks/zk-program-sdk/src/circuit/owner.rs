use std::{cell::OnceCell, rc::Rc};

use ark_r1cs_std::boolean::Boolean;
use zolana_hasher::primitives::{P256_OWNER_TAG, SOLANA_OWNER_TAG};

use super::{
    constant, hash_bytes, poseidon,
    var::{all_equal, assert_all_equal, assert_all_equal_if, assert_equal_unless, cached},
    zero, Assert, Bool, Bytes, CircuitVar, DataHash, Field, Select,
};
use crate::{circuit_lib::packed, RelationError};

#[derive(Clone, Debug)]
pub struct OwnerKey {
    tag: CircuitVar,
    bytes: Bytes<32>,
    identity: Rc<OnceCell<CircuitVar>>,
}

impl OwnerKey {
    pub(crate) fn new(
        tag: CircuitVar,
        bytes: Bytes<32>,
        skip_tag_check: &Boolean<Field>,
    ) -> Result<Self, RelationError> {
        let solana = tag.clone() - constant(u64::from(SOLANA_OWNER_TAG));
        let p256 = tag.clone() - constant(u64::from(P256_OWNER_TAG));
        assert_equal_unless(
            &(solana * p256),
            &zero(),
            skip_tag_check,
            "the owner tag is neither S nor P",
        )?;
        Ok(Self {
            tag,
            bytes,
            identity: Rc::new(OnceCell::new()),
        })
    }

    pub fn tag(&self) -> &CircuitVar {
        &self.tag
    }

    pub(crate) fn bytes(&self) -> &Bytes<32> {
        &self.bytes
    }

    pub fn identity(&self) -> Result<CircuitVar, RelationError> {
        cached(&self.identity, || hash_bytes(&self.tagged()))
    }

    pub(crate) fn assert_same_unless(
        &self,
        other: &Self,
        skip: &Boolean<Field>,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        for (left, right) in packed(&self.tagged()).iter().zip(&packed(&other.tagged())) {
            assert_equal_unless(left, right, skip, rule)?;
        }
        Ok(())
    }

    fn tagged(&self) -> Vec<CircuitVar> {
        core::iter::once(self.tag.clone())
            .chain(self.bytes.bytes().iter().cloned())
            .collect()
    }
}

impl Default for OwnerKey {
    fn default() -> Self {
        Self {
            tag: zero(),
            bytes: Bytes::default(),
            identity: Rc::new(OnceCell::new()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Owner {
    key: OwnerKey,
    nullifier_pk: CircuitVar,
    hash: Rc<OnceCell<CircuitVar>>,
}

impl Owner {
    pub(crate) fn new(key: OwnerKey, nullifier_pk: CircuitVar) -> Self {
        Self {
            key,
            nullifier_pk,
            hash: Rc::new(OnceCell::new()),
        }
    }

    pub fn key(&self) -> &OwnerKey {
        &self.key
    }

    pub fn nullifier_pk(&self) -> &CircuitVar {
        &self.nullifier_pk
    }

    pub fn hash(&self) -> Result<CircuitVar, RelationError> {
        cached(&self.hash, || {
            poseidon(&[self.key.identity()?, self.nullifier_pk.clone()])
        })
    }

    pub(crate) fn assert_same_unless(
        &self,
        other: &Self,
        skip: &Boolean<Field>,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        self.key.assert_same_unless(&other.key, skip, rule)?;
        assert_equal_unless(&self.nullifier_pk, &other.nullifier_pk, skip, rule)
    }
}

impl Default for Owner {
    fn default() -> Self {
        Self::new(OwnerKey::default(), zero())
    }
}

impl DataHash for Owner {
    fn hash(&self) -> Result<CircuitVar, RelationError> {
        Owner::hash(self)
    }
}

impl Assert for OwnerKey {
    fn is_equal(&self, other: &Self) -> Result<Bool, RelationError> {
        all_equal(&packed(&self.tagged()), &packed(&other.tagged()))
    }

    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        assert_all_equal(&packed(&self.tagged()), &packed(&other.tagged()), rule)
    }

    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        assert_all_equal_if(
            &packed(&self.tagged()),
            &packed(&other.tagged()),
            condition,
            rule,
        )
    }
}

impl Select for OwnerKey {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self {
        Self {
            tag: CircuitVar::select(condition, &if_true.tag, &if_false.tag),
            bytes: Bytes::select(condition, &if_true.bytes, &if_false.bytes),
            identity: Rc::new(OnceCell::new()),
        }
    }
}

impl Assert for Owner {
    fn is_equal(&self, other: &Self) -> Result<Bool, RelationError> {
        Ok(self
            .key
            .is_equal(&other.key)?
            .and(&self.nullifier_pk.is_equal(&other.nullifier_pk)?))
    }

    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        self.key.assert_equal(&other.key, rule)?;
        self.nullifier_pk.assert_equal(&other.nullifier_pk, rule)
    }

    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        self.key.assert_equal_if(&other.key, condition, rule)?;
        self.nullifier_pk
            .assert_equal_if(&other.nullifier_pk, condition, rule)
    }
}

impl Select for Owner {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self {
        Self::new(
            OwnerKey::select(condition, &if_true.key, &if_false.key),
            CircuitVar::select(condition, &if_true.nullifier_pk, &if_false.nullifier_pk),
        )
    }
}
