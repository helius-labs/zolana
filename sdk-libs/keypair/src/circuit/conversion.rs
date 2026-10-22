use std::collections::HashMap;

use ark_bn254::Fr;
use zolana_hasher::primitives::SOLANA_OWNER_TAG;
use zolana_zk_dsl::{
    circuit::{Bool, VariableRole},
    conversion::{byte_value, field, to_bytes, Allocator, FromCircuit, Placeholder, ProofInput},
    Bytes, CircuitError, PublicField, PublicFieldKind, PublicHashField,
};

use super::{OwnerCircuitErrorKind, ShieldedAddressCircuit};
use crate::{
    circuit::{self, client},
    ShieldedAddress, ShieldedKeypair, SigningKey,
};

/// Native viewing addresses bound to their instantiated owner values.
#[derive(Default)]
pub struct OwnerRecords {
    bindings: Vec<(circuit::UtxoOwner, ShieldedAddress)>,
    unique: HashMap<[u8; 32], Option<ShieldedAddress>>,
}

impl OwnerRecords {
    /// Resolve the selected address, refusing an ambiguous owner-hash match.
    pub fn get_for(
        &self,
        owner: &circuit::UtxoOwner,
    ) -> Result<Option<&ShieldedAddress>, CircuitError> {
        if let Some((_, address)) = self
            .bindings
            .iter()
            .find(|(value, _)| value.is_clone_of(owner))
        {
            return Ok(Some(address));
        }
        let owner_hash = to_bytes(&owner.hash()?)?;
        match self.unique.get(&owner_hash) {
            Some(Some(address)) => Ok(Some(address)),
            Some(None) => Err(OwnerCircuitErrorKind::AmbiguousOwnerAddress.into()),
            None => Ok(None),
        }
    }

    fn insert(&mut self, hash: [u8; 32], owner: circuit::UtxoOwner, address: ShieldedAddress) {
        self.bindings.push((owner, address));
        self.unique
            .entry(hash)
            .and_modify(|known| {
                if known.as_ref() != Some(&address) {
                    *known = None;
                }
            })
            .or_insert(Some(address));
    }
}

impl ProofInput for ShieldedAddress {
    type Circuit = ShieldedAddressCircuit;

    fn instantiate(&self, allocator: &Allocator) -> Result<ShieldedAddressCircuit, CircuitError> {
        let owner_hash = self
            .owner_hash()
            .map_err(OwnerCircuitErrorKind::InvalidOwner)?;
        let owner = client::UtxoOwner::try_from(self)?.instantiate(allocator)?;
        allocator.record(|records: &mut OwnerRecords| {
            records.insert(owner_hash, owner.clone(), *self);
        });
        Ok(ShieldedAddressCircuit::new(
            owner,
            *self.viewing_pubkey.as_bytes(),
        ))
    }
}

impl ProofInput for client::UtxoOwner {
    type Circuit = circuit::UtxoOwner;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::UtxoOwner, CircuitError> {
        owner(
            allocator,
            self,
            &Bool::constant(false),
            VariableRole::Constrained,
        )
    }
}

impl FromCircuit for client::UtxoOwner {
    fn from_circuit(circuit: &circuit::UtxoOwner) -> Result<Self, CircuitError> {
        Ok(Self {
            tag: byte_value(circuit.key().tag())?,
            key: Bytes::<32>::from_circuit(circuit.key().bytes())?.0,
            nullifier_pk: <[u8; 32]>::from_circuit(circuit.nullifier_pk())?,
        })
    }
}

/// `unused_role` is the role of the tag and the nullifier public key: the
/// tag check skipped by `skip_tag_check` is their only constraint when the
/// owner contributes no hash.
#[doc(hidden)]
pub fn owner(
    allocator: &Allocator,
    owner: &client::UtxoOwner,
    skip_tag_check: &Bool,
    unused_role: VariableRole,
) -> Result<circuit::UtxoOwner, CircuitError> {
    let tag = allocator.witness(Fr::from(owner.tag), "an owner tag", unused_role)?;
    let key = circuit::SigningPubkey::new(
        tag,
        Bytes(owner.key).instantiate(allocator)?,
        skip_tag_check,
    )?;
    Ok(circuit::UtxoOwner::new(
        key,
        allocator.witness(
            field(&owner.nullifier_pk, "32-byte input")?.into(),
            "a 32-byte proof input",
            unused_role,
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

impl Placeholder for client::UtxoOwner {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self {
            tag: SOLANA_OWNER_TAG,
            key: [0u8; 32],
            nullifier_pk: [0u8; 32],
        })
    }
}

/// A ZK program binds both ownership and the viewing key through one hash.
impl PublicField for ShieldedAddress {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Hash
    }
}

impl PublicHashField for ShieldedAddress {}

impl PublicField for client::UtxoOwner {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Hash
    }
}

impl PublicHashField for client::UtxoOwner {}
