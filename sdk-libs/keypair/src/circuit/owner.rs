use std::{cell::OnceCell, rc::Rc};

use zolana_hasher::primitives::SOLANA_OWNER_TAG;

use zolana_zk_dsl::{
    circuit::{
        builtins::{
            field::var::{cached, system_of},
            ops::assert::{all_equal, assert_all_equal, assert_all_equal_if},
            types::bytes::packed,
        },
        constant, zero, Assert, Bool, Bytes, CircuitDefault, CircuitType, CircuitVar, Select,
    },
    conversion::FromCircuit,
    CircuitError,
};
use zolana_zk_gadgets::{hash_bytes::hash_bytes, poseidon};

/// A tagged signing public key. Equality excludes the nullifier public key; use
/// `UtxoOwner` equality when that key must also match.
#[derive(Clone, Debug)]
pub struct SigningPubkey {
    tag: CircuitVar,
    bytes: Bytes<32>,
    identity: Rc<OnceCell<CircuitVar>>,
}

impl SigningPubkey {
    #[doc(hidden)]
    #[track_caller]
    pub fn new(
        tag: CircuitVar,
        bytes: Bytes<32>,
        skip_tag_check: &Bool,
    ) -> Result<Self, CircuitError> {
        tag.assert_equal_if(
            &constant(u64::from(SOLANA_OWNER_TAG)),
            &skip_tag_check.not(),
            "the owner tag is not S",
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

impl Default for SigningPubkey {
    fn default() -> Self {
        Self {
            tag: constant(u64::from(SOLANA_OWNER_TAG)),
            bytes: Bytes::default(),
            identity: Rc::new(OnceCell::new()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct UtxoOwner {
    key: SigningPubkey,
    nullifier_pk: CircuitVar,
    hash: Rc<OnceCell<CircuitVar>>,
}

impl UtxoOwner {
    #[doc(hidden)]
    pub fn dummy() -> Self {
        Self::new(
            SigningPubkey {
                tag: zero(),
                bytes: Bytes::default(),
                identity: Rc::new(OnceCell::new()),
            },
            zero(),
        )
    }

    #[doc(hidden)]
    pub fn new(key: SigningPubkey, nullifier_pk: CircuitVar) -> Self {
        Self {
            key,
            nullifier_pk,
            hash: Rc::new(OnceCell::new()),
        }
    }

    #[doc(hidden)]
    pub fn is_clone_of(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.hash, &other.hash)
    }

    pub fn key(&self) -> &SigningPubkey {
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

impl Default for UtxoOwner {
    fn default() -> Self {
        Self::new(SigningPubkey::default(), zero())
    }
}

impl Assert for SigningPubkey {
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

impl Select for SigningPubkey {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self {
        Self {
            tag: CircuitVar::select(condition, &if_true.tag, &if_false.tag),
            bytes: Bytes::select(condition, &if_true.bytes, &if_false.bytes),
            identity: Rc::new(OnceCell::new()),
        }
    }
}

impl Assert for UtxoOwner {
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

impl Select for UtxoOwner {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self {
        // Native selection retains the selected address's client metadata.
        let flag = condition.var();
        let left = if_true.key.tagged();
        let right = if_false.key.tagged();
        let cs = system_of(
            core::iter::once(&flag)
                .chain(left.iter())
                .chain(right.iter())
                .chain([&if_true.nullifier_pk, &if_false.nullifier_pk]),
        );
        if cs.is_none() {
            if let Ok(selected) = bool::from_circuit(condition) {
                return if selected {
                    if_true.clone()
                } else {
                    if_false.clone()
                };
            }
        }
        Self::new(
            SigningPubkey::select(condition, &if_true.key, &if_false.key),
            CircuitVar::select(condition, &if_true.nullifier_pk, &if_false.nullifier_pk),
        )
    }
}

impl CircuitType for UtxoOwner {}

impl CircuitType for SigningPubkey {}

impl CircuitDefault for UtxoOwner {
    fn circuit_default() -> Self {
        UtxoOwner::default()
    }
}
