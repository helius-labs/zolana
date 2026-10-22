use core::ops::Deref;
use std::rc::Rc;

use zolana_zk_dsl::{
    circuit::{
        builtins::field::var::system_of, Assert, Bool, Bytes, CircuitType, CircuitVar, Select,
    },
    conversion::{Allocator, ProofInput},
    Bytes as ClientBytes, CircuitError,
};
use zolana_zk_gadgets::{poseidon, HashBytes};

use super::UtxoOwner;

/// An address always includes a viewing key. Its hash is distinct from the
/// owner hash used by SPP UTXO commitments.
#[derive(Clone, Debug)]
pub struct ShieldedAddressCircuit {
    owner: UtxoOwner,
    viewer: Viewer,
}

#[derive(Clone, Debug)]
enum Viewer {
    Key([u8; 33]),
    Selected {
        condition: Bool,
        if_true: Rc<Viewer>,
        if_false: Rc<Viewer>,
    },
}

impl Viewer {
    fn cs(&self) -> zolana_zk_dsl::circuit::CircuitSystem {
        match self {
            Self::Key(_) => zolana_zk_dsl::circuit::CircuitSystem::None,
            Self::Selected {
                condition,
                if_true,
                if_false,
            } => condition.var().cs().or(if_true.cs()).or(if_false.cs()),
        }
    }

    fn instantiate(
        &self,
        cs: &zolana_zk_dsl::circuit::CircuitSystem,
    ) -> Result<Bytes<33>, CircuitError> {
        match self {
            Self::Key(bytes) => {
                let allocator = if cs.is_none() {
                    Allocator::native()
                } else {
                    Allocator::R1cs(cs.clone())
                };
                ClientBytes(*bytes).instantiate(&allocator)
            }
            Self::Selected {
                condition,
                if_true,
                if_false,
            } => Ok(Bytes::select(
                condition,
                &if_true.instantiate(cs)?,
                &if_false.instantiate(cs)?,
            )),
        }
    }
}

impl ShieldedAddressCircuit {
    pub(super) fn new(owner: UtxoOwner, viewing_pubkey: [u8; 33]) -> Self {
        Self {
            owner,
            viewer: Viewer::Key(viewing_pubkey),
        }
    }

    pub fn owner(&self) -> &UtxoOwner {
        &self.owner
    }

    fn cs(&self) -> zolana_zk_dsl::circuit::CircuitSystem {
        let key = self.owner.key();
        system_of(
            core::iter::once(key.tag())
                .chain(key.bytes().bytes())
                .chain([self.owner.nullifier_pk()]),
        )
        .or(self.viewer.cs())
    }

    pub fn hash(&self) -> Result<CircuitVar, CircuitError> {
        let viewer = self.viewer.instantiate(&self.cs())?;
        poseidon(&[self.owner.hash()?, viewer.hash_bytes()?])
    }
}

impl Deref for ShieldedAddressCircuit {
    type Target = UtxoOwner;

    fn deref(&self) -> &UtxoOwner {
        &self.owner
    }
}

impl Assert for ShieldedAddressCircuit {
    fn is_equal(&self, other: &Self) -> Result<Bool, CircuitError> {
        let cs = self.cs().or(other.cs());
        let viewer = self.viewer.instantiate(&cs)?;
        let other_viewer = other.viewer.instantiate(&cs)?;
        Ok(self
            .owner
            .is_equal(&other.owner)?
            .and(&viewer.is_equal(&other_viewer)?))
    }

    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), CircuitError> {
        self.owner.assert_equal(&other.owner, rule)?;
        let cs = self.cs().or(other.cs());
        self.viewer
            .instantiate(&cs)?
            .assert_equal(&other.viewer.instantiate(&cs)?, rule)
    }

    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), CircuitError> {
        self.owner.assert_equal_if(&other.owner, condition, rule)?;
        let cs = condition.var().cs().or(self.cs()).or(other.cs());
        self.viewer.instantiate(&cs)?.assert_equal_if(
            &other.viewer.instantiate(&cs)?,
            condition,
            rule,
        )
    }
}

impl Select for ShieldedAddressCircuit {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self {
        let owner = UtxoOwner::select(condition, &if_true.owner, &if_false.owner);
        let viewer = match condition.var().constant_value() {
            Some(value) if value == ark_bn254::Fr::from(1u64) => if_true.viewer.clone(),
            Some(value) if value == ark_bn254::Fr::from(0u64) => if_false.viewer.clone(),
            _ => Viewer::Selected {
                condition: condition.clone(),
                if_true: Rc::new(if_true.viewer.clone()),
                if_false: Rc::new(if_false.viewer.clone()),
            },
        };
        Self { owner, viewer }
    }
}

impl CircuitType for ShieldedAddressCircuit {}
