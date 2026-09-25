use ark_r1cs_std::boolean::Boolean;
use zolana_keypair::ShieldedAddress;

use super::{bytes::byte_value, Allocator, FromCircuit, ProofInput};
use crate::{
    circuit::{self, constant, Field},
    client, RelationError,
};

impl ProofInput for ShieldedAddress {
    type Circuit = circuit::Owner;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Owner, RelationError> {
        let owner_hash = self.owner_hash().map_err(RelationError::input)?;
        allocator.record(|records| {
            records.owners.insert(owner_hash, *self);
        });
        client::Owner::try_from(self)?.instantiate(allocator)
    }
}

impl ProofInput for client::Owner {
    type Circuit = circuit::Owner;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Owner, RelationError> {
        owner(allocator, self, &Boolean::FALSE)
    }
}

impl FromCircuit for client::Owner {
    fn from_circuit(circuit: &circuit::Owner) -> Result<Self, RelationError> {
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
    skip_tag_check: &Boolean<Field>,
) -> Result<circuit::Owner, RelationError> {
    let tag = allocator.private_input(&constant(u64::from(owner.tag)))?;
    let key = circuit::OwnerKey::new(
        tag,
        client::Bytes(owner.key).instantiate(allocator)?,
        skip_tag_check,
    )?;
    Ok(circuit::Owner::new(
        key,
        owner.nullifier_pk.instantiate(allocator)?,
    ))
}
