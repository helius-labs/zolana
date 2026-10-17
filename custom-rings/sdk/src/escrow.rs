use custom_ring_interface::{RingMode, KEY_REGISTRY_HEIGHT};
use futures::future::try_join_all;
use serde::Serialize;
use zolana_client::{AsyncRpc, ClientError};
use zolana_ring_policy::Member;

use crate::{
    prover::fe, CurrentKeyRegistryRoot, CustomRing, CustomRingConfig, ReadSealedKey, RingError,
};

/// Opens the registry leaf `Poseidon(owner, next, Poseidon(nullifier_pk, ct_hash))`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryKeyOpening {
    #[serde(with = "fe")]
    pub next: [u8; 32],
    #[serde(with = "fe")]
    pub ct_hash: [u8; 32],
    pub index: u64,
    #[serde(serialize_with = "fe::seq")]
    pub path: [[u8; 32]; KEY_REGISTRY_HEIGHT],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutputKey {
    pub owner_pk_hash: [u8; 32],
    pub nullifier_pk: [u8; 32],
}

/// Present only with escrow on.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KeyRegistry {
    pub ring: CustomRing,
}

/// Every opening is included under `root`.
#[derive(Debug)]
pub(crate) struct EscrowedKeys {
    pub root: CurrentKeyRegistryRoot,
    /// Per output, `None` for an unowned slot.
    pub keys: Vec<Option<RegistryKeyOpening>>,
}

impl KeyRegistry {
    pub fn of(ring: CustomRing, config: &CustomRingConfig) -> Option<Self> {
        (config.mode == RingMode::Registry).then_some(Self { ring })
    }

    async fn root(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<CurrentKeyRegistryRoot, RingError> {
        self.ring
            .key_registry_root(rpc)
            .await?
            .ok_or(RingError::MissingKeyRegistry)
    }

    /// The root alone, the prover resolves the openings.
    pub async fn pending(self, rpc: &(impl AsyncRpc + ?Sized)) -> Result<EscrowedKeys, RingError> {
        Ok(EscrowedKeys {
            root: self.root(rpc).await?,
            keys: Vec::new(),
        })
    }

    /// One registry read per distinct owner, an unenrolled key fails before proving.
    pub async fn openings(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
        keys: &[Option<OutputKey>],
    ) -> Result<EscrowedKeys, RingError> {
        let root = self.root(rpc).await?;
        let keys = keys
            .iter()
            .map(|key| {
                key.map(|key| Ok::<_, RingError>((Member::from_bytes(key.owner_pk_hash)?, key)))
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut owners: Vec<Member> = Vec::new();
        for (owner, _) in keys.iter().flatten() {
            if !owners.contains(owner) {
                owners.push(*owner);
            }
        }
        let entries = try_join_all(owners.iter().map(|&member| async move {
            match (ReadSealedKey {
                ring: self.ring,
                member,
                root,
            })
            .read(rpc)
            .await
            {
                Err(RingError::Client(ClientError::RingKeyRegistryMemberUnregistered)) => Ok(None),
                entry => entry.map(Some),
            }
        }))
        .await?;
        let keys = keys
            .into_iter()
            .map(|key| {
                key.map(|(owner, key)| {
                    owners
                        .iter()
                        .zip(&entries)
                        .find_map(|(known, entry)| (*known == owner).then_some(entry.as_ref()))
                        .flatten()
                        .ok_or(RingError::UnregisteredOutputKey { owner })?
                        .opening(&key.nullifier_pk)
                })
                .transpose()
            })
            .collect::<Result<_, _>>()?;
        Ok(EscrowedKeys { root, keys })
    }
}
