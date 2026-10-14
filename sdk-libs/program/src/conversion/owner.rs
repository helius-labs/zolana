use ark_bn254::Fr;
use zolana_hasher::primitives::SOLANA_OWNER_TAG;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey};

use super::{bytes::byte_value, Allocator, FromCircuit, Placeholder, ProofInput};
use crate::{
    circuit::{self, Bool, VariableRole},
    client, CircuitError, CircuitErrorKind,
};

impl ProofInput for ShieldedAddress {
    type Circuit = circuit::Owner;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Owner, CircuitError> {
        let owner_hash = self.owner_hash().map_err(CircuitErrorKind::InvalidOwner)?;
        allocator.record(|records| {
            records.owners.insert(owner_hash, *self);
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
            key: client::Bytes::<32>::from_circuit(circuit.key().bytes())?.0,
            nullifier_pk: <[u8; 32]>::from_circuit(circuit.nullifier_pk())?,
        })
    }
}

pub(super) fn owner(
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
        client::Bytes(owner.key).instantiate(allocator)?,
        skip_tag_check,
    )?;
    Ok(circuit::Owner::new(
        key,
        allocator.witness(
            super::field(&owner.nullifier_pk, "32-byte input")?.into(),
            "a 32-byte proof input",
            nullifier_role,
        )?,
    ))
}

impl Placeholder for ShieldedAddress {
    fn placeholder() -> Result<Self, CircuitError> {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[1u8; 32]))
            .and_then(|keypair| keypair.shielded_address())
            .map_err(|error| CircuitErrorKind::InvalidOwner(error).into())
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
