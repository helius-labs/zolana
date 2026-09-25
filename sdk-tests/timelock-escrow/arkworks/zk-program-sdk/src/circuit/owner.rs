use std::cell::OnceCell;

use ark_r1cs_std::boolean::Boolean;
use zolana_hasher::primitives::{P256_OWNER_TAG, SOLANA_OWNER_TAG};

use super::{
    constant, hash_bytes, poseidon,
    var::{assert_equal_unless, cached},
    zero, Bytes, CircuitVar, DataHash, Field,
};
use crate::{circuit_lib::packed, RelationError};

#[derive(Clone, Debug)]
pub struct OwnerKey {
    tag: CircuitVar,
    bytes: Bytes<32>,
    identity: OnceCell<CircuitVar>,
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
            identity: OnceCell::new(),
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
            identity: OnceCell::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Owner {
    key: OwnerKey,
    nullifier_pk: CircuitVar,
    hash: OnceCell<CircuitVar>,
}

impl Owner {
    pub(crate) fn new(key: OwnerKey, nullifier_pk: CircuitVar) -> Self {
        Self {
            key,
            nullifier_pk,
            hash: OnceCell::new(),
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
