use std::{cell::OnceCell, rc::Rc};

use ark_bn254::Fr;
use zolana_hasher::primitives::{P256_OWNER_TAG, SOLANA_OWNER_TAG};

use crate::{
    circuit::{
        builtins::{
            field::var::cached,
            gadgets::hash_bytes::{hash_bytes, packed},
            ops::assert::{all_equal, assert_all_equal, assert_all_equal_if},
        },
        constant, poseidon, zero, Assert, Bool, Bytes, CircuitVar, DataHash, Select,
    },
    CircuitError,
};

/// A tagged signing key. Equality excludes the nullifier public key; use
/// `Owner` equality when that key must also match.
#[derive(Clone, Debug)]
pub struct OwnerKey {
    tag: CircuitVar,
    bytes: Bytes<32>,
    identity: Rc<OnceCell<CircuitVar>>,
}

impl OwnerKey {
    #[track_caller]
    pub(crate) fn new(
        tag: CircuitVar,
        bytes: Bytes<32>,
        skip_tag_check: &Bool,
    ) -> Result<Self, CircuitError> {
        let solana = tag.offset(-Fr::from(SOLANA_OWNER_TAG));
        let p256 = tag.offset(-Fr::from(P256_OWNER_TAG));
        solana.times(&p256).assert_equal_if(
            &zero(),
            &skip_tag_check.not(),
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

    pub fn identity(&self) -> Result<CircuitVar, CircuitError> {
        cached(&self.identity, || hash_bytes(&self.tagged()))
    }

    fn tagged(&self) -> [CircuitVar; 33] {
        let mut tagged: [CircuitVar; 33] = core::array::from_fn(|_| zero());
        let [tag, key @ ..] = &mut tagged;
        *tag = self.tag.clone();
        key.clone_from(self.bytes.bytes());
        tagged
    }
}

impl Default for OwnerKey {
    fn default() -> Self {
        Self {
            tag: constant(u64::from(SOLANA_OWNER_TAG)),
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
    pub(crate) fn dummy() -> Self {
        Self::new(
            OwnerKey {
                tag: zero(),
                bytes: Bytes::default(),
                identity: Rc::new(OnceCell::new()),
            },
            zero(),
        )
    }

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

    pub fn hash(&self) -> Result<CircuitVar, CircuitError> {
        cached(&self.hash, || {
            poseidon(&[self.key.identity()?, self.nullifier_pk.clone()])
        })
    }
}

impl Default for Owner {
    fn default() -> Self {
        Self::new(OwnerKey::default(), zero())
    }
}

impl DataHash for Owner {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        Owner::hash(self)
    }
}

impl Assert for OwnerKey {
    fn is_equal(&self, other: &Self) -> Result<Bool, CircuitError> {
        all_equal(&packed(&self.tagged()), &packed(&other.tagged()))
    }

    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), CircuitError> {
        assert_all_equal(&packed(&self.tagged()), &packed(&other.tagged()), rule)
    }

    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), CircuitError> {
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
    fn is_equal(&self, other: &Self) -> Result<Bool, CircuitError> {
        Ok(self
            .key
            .is_equal(&other.key)?
            .and(&self.nullifier_pk.is_equal(&other.nullifier_pk)?))
    }

    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), CircuitError> {
        self.key.assert_equal(&other.key, rule)?;
        self.nullifier_pk.assert_equal(&other.nullifier_pk, rule)
    }

    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), CircuitError> {
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
