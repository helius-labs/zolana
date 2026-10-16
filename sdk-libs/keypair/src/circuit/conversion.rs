use std::collections::HashMap;

use ark_bn254::Fr;
use zolana_hasher::primitives::SOLANA_OWNER_TAG;
use zolana_zk_dsl::{
    circuit::{Bool, VariableRole},
    conversion::{byte_value, field, Allocator, FromCircuit, Placeholder, ProofInput},
    Bytes, CircuitError, PublicField, PublicFieldKind, PublicHashField,
};

use super::OwnerCircuitErrorKind;
use crate::{
    circuit::{self, client},
    ShieldedAddress, ShieldedKeypair, SigningKey,
};

/// The shielded addresses a native instantiation met, by owner hash.
#[derive(Default)]
pub struct OwnerRecords(HashMap<[u8; 32], ShieldedAddress>);

impl OwnerRecords {
    pub fn get(&self, owner_hash: &[u8; 32]) -> Option<&ShieldedAddress> {
        self.0.get(owner_hash)
    }
}

impl ProofInput for ShieldedAddress {
    type Circuit = circuit::Owner;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Owner, CircuitError> {
        let owner_hash = self
            .owner_hash()
            .map_err(OwnerCircuitErrorKind::InvalidOwner)?;
        allocator.record(|records: &mut OwnerRecords| {
            records.0.insert(owner_hash, *self);
        });
        client::Owner::try_from(self)?.instantiate(allocator)
    }
}

impl ProofInput for client::Owner {
    type Circuit = circuit::Owner;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Owner, CircuitError> {
        owner(
            allocator,
            self,
            &Bool::constant(false),
            VariableRole::Constrained,
        )
    }
}

impl FromCircuit for client::Owner {
    fn from_circuit(circuit: &circuit::Owner) -> Result<Self, CircuitError> {
        Ok(Self {
            tag: byte_value(circuit.key().tag())?,
            key: Bytes::<32>::from_circuit(circuit.key().bytes())?.0,
            nullifier_pk: <[u8; 32]>::from_circuit(circuit.nullifier_pk())?,
        })
    }
}

#[doc(hidden)]
pub fn owner(
    allocator: &Allocator,
    owner: &client::Owner,
    skip_tag_check: &Bool,
    nullifier_role: VariableRole,
) -> Result<circuit::Owner, CircuitError> {
    let tag = allocator.witness(
        Fr::from(owner.tag),
        "an owner tag",
        VariableRole::Constrained,
    )?;
    let key = circuit::OwnerKey::new(
        tag,
        Bytes(owner.key).instantiate(allocator)?,
        skip_tag_check,
    )?;
    Ok(circuit::Owner::new(
        key,
        allocator.witness(
            field(&owner.nullifier_pk, "32-byte input")?.into(),
            "a 32-byte proof input",
            nullifier_role,
        )?,
    ))
}

impl Placeholder for ShieldedAddress {
    fn placeholder() -> Result<Self, CircuitError> {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[1u8; 32]))
            .and_then(|keypair| keypair.shielded_address())
            .map_err(|error| OwnerCircuitErrorKind::InvalidOwner(error).into())
    }
}

impl Placeholder for client::Owner {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self {
            tag: SOLANA_OWNER_TAG,
            key: [0u8; 32],
            nullifier_pk: [0u8; 32],
        })
    }
}

/// A ZK program binds an owner through its 32-byte hash.
impl PublicField for ShieldedAddress {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Hash
    }
}

impl PublicHashField for ShieldedAddress {}

impl PublicField for client::Owner {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Hash
    }
}

impl PublicHashField for client::Owner {}
