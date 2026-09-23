use custom_ring_interface::{KeyEscrow, KEY_REGISTRY_HEIGHT};
use futures::future::try_join_all;
use zolana_client::{AsyncRpc, ClientError, Rpc};
use zolana_ring_policy::Member;

use crate::{
    instructions::spend::ReadEnvironment,
    projection::{retry_projection_lag, retry_projection_lag_async},
    CurrentKeyRegistryRoot, CustomRing, CustomRingConfig, KeyRegistrationError, ReadSealedKey,
    SealedKeyEntry,
};

/// Opens the registry leaf `Poseidon(owner, next, Poseidon(nullifier_pk, ct_hash))`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryKeyOpening {
    pub next: [u8; 32],
    pub ct_hash: [u8; 32],
    pub index: u64,
    pub path: [[u8; 32]; KEY_REGISTRY_HEIGHT],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutputKey {
    pub owner_pk_hash: [u8; 32],
    pub nullifier_pk: [u8; 32],
}

impl OutputKey {
    fn escrowed(self) -> Result<EscrowedKey, KeyRegistrationError> {
        Ok(EscrowedKey {
            owner: Member::owner_identity(&self.owner_pk_hash)
                .map_err(|_| KeyRegistrationError::Hashing)?,
            nullifier_pk: self.nullifier_pk,
        })
    }
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
    /// Per output, `None` for an unowned slot or a namespace-owned record.
    pub keys: Vec<Option<RegistryKeyOpening>>,
}

impl KeyRegistry {
    pub fn of(ring: CustomRing, config: &CustomRingConfig) -> Option<Self> {
        match config.key_escrow {
            KeyEscrow::Off => None,
            KeyEscrow::Registry => Some(Self { ring }),
        }
    }

    pub fn openings<I: Rpc, R: Rpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
        keys: &[Option<OutputKey>],
    ) -> Result<EscrowedKeys, KeyRegistrationError> {
        let outputs = EscrowedOutputs::new(keys)?;
        retry_projection_lag(|| {
            let root = self.root(self.ring.read_key_registry_root(env.rpc)?)?;
            let entries = outputs
                .owners
                .iter()
                .map(|owner| enrolled(self.sealed_key(*owner, root).read(env.indexer)))
                .collect::<Result<Vec<_>, _>>()?;
            outputs.open(root, &entries)
        })
    }

    pub async fn openings_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
        keys: &[Option<OutputKey>],
    ) -> Result<EscrowedKeys, KeyRegistrationError> {
        let outputs = EscrowedOutputs::new(keys)?;
        let outputs = &outputs;
        retry_projection_lag_async(|| async move {
            let root = self.root(self.ring.read_key_registry_root_async(env.rpc).await?)?;
            let entries = try_join_all(outputs.owners.iter().map(|owner| async move {
                enrolled(self.sealed_key(*owner, root).read_async(env.indexer).await)
            }))
            .await?;
            outputs.open(root, &entries)
        })
        .await
    }

    fn root(
        self,
        root: Option<CurrentKeyRegistryRoot>,
    ) -> Result<CurrentKeyRegistryRoot, KeyRegistrationError> {
        root.ok_or(KeyRegistrationError::MissingKeyRegistry)
    }

    fn sealed_key(self, member: Member, root: CurrentKeyRegistryRoot) -> ReadSealedKey {
        ReadSealedKey {
            ring: self.ring,
            member,
            root,
        }
    }
}

#[derive(Clone, Copy)]
struct EscrowedKey {
    owner: Member,
    nullifier_pk: [u8; 32],
}

struct EscrowedOutputs {
    keys: Vec<Option<EscrowedKey>>,
    /// Distinct, one registry read each.
    owners: Vec<Member>,
}

impl EscrowedOutputs {
    fn new(keys: &[Option<OutputKey>]) -> Result<Self, KeyRegistrationError> {
        let keys = keys
            .iter()
            .map(|key| key.map(OutputKey::escrowed).transpose())
            .collect::<Result<Vec<_>, KeyRegistrationError>>()?;
        let mut owners = Vec::new();
        for key in keys.iter().flatten() {
            if !owners.contains(&key.owner) {
                owners.push(key.owner);
            }
        }
        Ok(Self { keys, owners })
    }

    /// `entries` follow `owners`, `None` for an owner the registry does not hold.
    fn open(
        &self,
        root: CurrentKeyRegistryRoot,
        entries: &[Option<SealedKeyEntry>],
    ) -> Result<EscrowedKeys, KeyRegistrationError> {
        let keys = self
            .keys
            .iter()
            .map(|key| {
                key.map(|key| {
                    self.owners
                        .iter()
                        .zip(entries)
                        .find_map(|(owner, entry)| (*owner == key.owner).then_some(entry))
                        .and_then(Option::as_ref)
                        .ok_or(KeyRegistrationError::UnregisteredOutputKey { owner: key.owner })?
                        .opening(&key.nullifier_pk)
                })
                .transpose()
            })
            .collect::<Result<_, _>>()?;
        Ok(EscrowedKeys { root, keys })
    }
}

fn enrolled(
    read: Result<SealedKeyEntry, KeyRegistrationError>,
) -> Result<Option<SealedKeyEntry>, KeyRegistrationError> {
    match read {
        Ok(entry) => Ok(Some(entry)),
        Err(KeyRegistrationError::Client(error))
            if matches!(*error, ClientError::RingKeyRegistryMemberUnregistered) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
