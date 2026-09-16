use anyhow::{bail, Context, Result};
use custom_ring_interface::{
    instruction::{accounts, tag},
    pda, HeadMapLeaf, KeyRegistryRoot, RegisterKeyIxData, RegisteredKey, AUDIT_CIPHERTEXT_LEN,
    COMPRESSED_P256_KEY_LEN, KEY_REGISTRY_ROOT,
};
use sea_orm::{DatabaseConnection, DatabaseTransaction};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use zolana_hasher::HasherError;
use zolana_indexer_api::{
    Base64String, GetRingKeyRegistryEntryResponse, GetRingKeyRegistryRegisterProofResponse, Hash,
    RingMemberProofRequest,
};
use zolana_ring_head_map::FIELD_MAX;
use zolana_ring_policy::Member;

use super::{
    api::{self, Insertion, MemberPath},
    append, fault,
    storage::{RingStore, Undo},
    Append, BlockEnv, Invocation, Leaf, OnChainRoot, ProjectError, Projection, ProjectionKind,
    Step,
};
use crate::{
    api::error::PhotonApiError, ingester::typedefs::block_info::Instruction, rpc::RpcClient,
};

pub(crate) struct KeyRegistry;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct MemberKey {
    pub member: [u8; 32],
    pub index: u64,
    pub next: [u8; 32],
    pub ct_commitment: [u8; 32],
    #[serde(with = "compressed_key")]
    pub eph_pk: [u8; COMPRESSED_P256_KEY_LEN],
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
}

impl Leaf for MemberKey {
    fn sentinel() -> Self {
        Self {
            member: [0; 32],
            index: 0,
            next: FIELD_MAX,
            ct_commitment: [0; 32],
            eph_pk: [0; COMPRESSED_P256_KEY_LEN],
            ciphertext: [0; AUDIT_CIPHERTEXT_LEN],
        }
    }

    fn member(&self) -> [u8; 32] {
        self.member
    }

    fn index(&self) -> u64 {
        self.index
    }

    fn next(&self) -> [u8; 32] {
        self.next
    }

    fn set_next(&mut self, next: [u8; 32]) {
        self.next = next;
    }

    fn hash(&self) -> Result<[u8; 32], HasherError> {
        HeadMapLeaf {
            member: &self.member,
            next: &self.next,
            nullifier: &self.ct_commitment,
        }
        .hash()
    }
}

/// serde derives arrays only up to 32 bytes.
mod compressed_key {
    use custom_ring_interface::COMPRESSED_P256_KEY_LEN;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        value: &[u8; COMPRESSED_P256_KEY_LEN],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; COMPRESSED_P256_KEY_LEN], D::Error> {
        Vec::<u8>::deserialize(deserializer)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("eph_pk must be 33 bytes"))
    }
}

impl OnChainRoot for KeyRegistryRoot {
    fn discriminator(&self) -> u8 {
        self.discriminator
    }

    fn root(&self) -> [u8; 32] {
        self.root
    }

    fn next_index(&self) -> u64 {
        KeyRegistryRoot::next_index(self)
    }

    fn bump(&self) -> u8 {
        self.bump
    }
}

#[derive(Debug)]
pub(crate) struct Registration {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub next_index: u64,
    pub member: [u8; 32],
    pub ct_commitment: [u8; 32],
    pub eph_pk: [u8; COMPRESSED_P256_KEY_LEN],
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
}

impl Projection for KeyRegistry {
    const KIND: ProjectionKind = ProjectionKind::KeyRegistry;
    const INIT_TAG: u8 = tag::CREATE_KEY_REGISTRY_ROOT;
    const INIT_ROOT_SLOT: usize = accounts::CREATE_KEY_REGISTRY_ROOT_ROOT;
    const TRANSITION_TAGS: &'static [u8] = &[tag::REGISTER_KEY];
    const ROOT_DISCRIMINATOR: u8 = KEY_REGISTRY_ROOT;
    type Root = KeyRegistryRoot;
    type Leaf = MemberKey;
    type Transition = Registration;

    fn undos(block: &mut super::storage::BlockUndo) -> &mut Vec<Undo<MemberKey>> {
        &mut block.key_registry
    }

    fn root_address(program: &Pubkey) -> (Pubkey, u8) {
        pda::key_registry_root(program)
    }

    async fn transition(
        invocation: &Invocation<'_>,
        _env: &mut BlockEnv<'_>,
    ) -> Result<Option<Registration>, ProjectError> {
        registration(invocation.instruction).map_err(|error| fault(format!("{error:#}")))
    }

    async fn apply(
        store: &RingStore<'_, DatabaseTransaction, Self>,
        step: Step<'_, Registration>,
    ) -> Result<Undo<MemberKey>, ProjectError> {
        let Step {
            root,
            transition,
            revision,
        } = step;
        let Registration {
            old_root,
            new_root,
            next_index,
            member,
            ct_commitment,
            eph_pk,
            ciphertext,
        } = transition;
        append::<Self>(
            store,
            Step {
                root,
                transition: Append {
                    old_root,
                    new_root,
                    next_index,
                    leaf: MemberKey {
                        member,
                        index: next_index,
                        next: [0; 32],
                        ct_commitment,
                        eph_pk,
                        ciphertext,
                    },
                },
                revision,
            },
        )
        .await
    }
}

fn registration(instruction: &Instruction) -> Result<Option<Registration>> {
    if instruction.data.first() != Some(&tag::REGISTER_KEY) {
        return Ok(None);
    }
    let ix: RegisterKeyIxData = wincode::deserialize_exact(&instruction.data[1..])
        .context("invalid key registration wire")?;
    let root = KeyRegistry::root_address(&instruction.program_id).0;
    if instruction.accounts.get(accounts::REGISTER_KEY_ROOT) != Some(&root) {
        bail!("key registration does not name its canonical root");
    }
    let signer = instruction
        .accounts
        .get(accounts::REGISTER_KEY_MEMBER)
        .context("key registration has no member signer")?;
    let member = *Member::owner_tag(&signer.to_bytes())
        .map_err(|error| anyhow::anyhow!("registration member derivation failed ({error:?})"))?
        .as_bytes();
    Ok(Some(Registration {
        old_root: ix.registry_old_root,
        new_root: ix.registry_new_root,
        next_index: ix.registry_next_index,
        member,
        ct_commitment: RegisteredKey {
            nullifier_pk: &ix.nullifier_pk,
            ciphertext: &ix.ciphertext,
        }
        .commitment()?,
        eph_pk: ix.eph_pk,
        ciphertext: ix.ciphertext,
    }))
}

pub(crate) async fn register(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: RingMemberProofRequest,
) -> Result<GetRingKeyRegistryRegisterProofResponse, PhotonApiError> {
    let Insertion {
        context,
        root,
        low,
        low_proof,
        new_proof,
    } = api::insertion::<KeyRegistry>(db, rpc, &request).await?;
    Ok(GetRingKeyRegistryRegisterProofResponse {
        context,
        root: Hash(root.root),
        next_index: root.next_index,
        member: request.member,
        low_member: Hash(low.member),
        low_next: Hash(low.next),
        low_ct_commitment: Hash(low.ct_commitment),
        low_index: low.index,
        low_proof: low_proof.into_iter().map(Hash).collect(),
        new_proof: new_proof.into_iter().map(Hash).collect(),
    })
}

pub(crate) async fn lookup(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: RingMemberProofRequest,
) -> Result<GetRingKeyRegistryEntryResponse, PhotonApiError> {
    let MemberPath {
        context,
        root,
        leaf,
        proof,
    } = api::member_path::<KeyRegistry>(db, rpc, &request).await?;
    Ok(GetRingKeyRegistryEntryResponse {
        context,
        root: Hash(root.root),
        next_index: root.next_index,
        member: request.member,
        next: Hash(leaf.next),
        index: leaf.index,
        eph_pk: Base64String(leaf.eph_pk.to_vec()),
        ciphertext: Base64String(leaf.ciphertext.to_vec()),
        proof: proof.into_iter().map(Hash).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::error::RingProjectionError,
        ingester::typedefs::block_info::BlockMetadata,
        ring_projection::{
            proof,
            storage::{self, BlockJournal, BlockUndo},
            tests::{field, fixture, member},
        },
    };
    use sea_orm::TransactionTrait;
    use zolana_ring_head_map::HeadMap;

    fn commitment(seed: u8) -> [u8; 32] {
        RegisteredKey {
            nullifier_pk: &field(seed),
            ciphertext: &[seed; 32],
        }
        .commitment()
        .unwrap()
    }

    fn registration(root: &storage::RingRoot, seed: u8, new_root: [u8; 32]) -> Registration {
        Registration {
            old_root: root.root,
            new_root,
            next_index: root.next_index,
            member: member(seed),
            ct_commitment: commitment(seed),
            eph_pk: [seed; 33],
            ciphertext: [seed; 32],
        }
    }

    #[tokio::test]
    async fn key_insert_path_matches_reference_without_mutating_reads() {
        let (db, mut root, mut cursor) = fixture::<KeyRegistry>().await;
        let mut reference = HeadMap::new().unwrap();
        for seed in [5u8, 9, 2, 8] {
            let subject = member(seed);
            let tx = db.begin().await.unwrap();
            let store = RingStore::<_, KeyRegistry>::new(&tx, root.program);
            let low = store.predecessor(&subject).await.unwrap();
            let low_path = proof::path::<KeyRegistry>(&tx, &root, low.index)
                .await
                .unwrap();
            let slot = proof::path::<KeyRegistry>(&tx, &root, root.next_index)
                .await
                .unwrap();
            assert_eq!(slot.leaf, [0; 32]);
            let inputs = reference
                .register(zolana_ring_head_map::Registration {
                    member: subject,
                    genesis: commitment(seed),
                })
                .unwrap();
            assert_eq!(low_path.siblings, inputs.low_proof);
            assert_eq!(store.root().await.unwrap().unwrap().root, root.root);
            KeyRegistry::apply(
                &store,
                Step {
                    root: &root,
                    transition: registration(&root, seed, inputs.new_root),
                    revision: cursor.advance_revision().unwrap(),
                },
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            root = RingStore::<_, KeyRegistry>::new(&db, root.program)
                .root()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(root.root, reference.root());
        }
    }

    #[tokio::test]
    async fn failed_key_registration_rolls_back_and_committed_block_rewinds_and_replays() {
        let (db, root, mut cursor) = fixture::<KeyRegistry>().await;
        let subject = member(8);
        let mut reference = HeadMap::new().unwrap();
        let registered = reference
            .register(zolana_ring_head_map::Registration {
                member: subject,
                genesis: commitment(8),
            })
            .unwrap();
        let tx = db.begin().await.unwrap();
        assert!(KeyRegistry::apply(
            &RingStore::new(&tx, root.program),
            Step {
                root: &root,
                transition: registration(&root, 8, field(99)),
                revision: 2,
            },
        )
        .await
        .is_err());
        tx.rollback().await.unwrap();
        let store = RingStore::<_, KeyRegistry>::new(&db, root.program);
        assert!(store.member(&subject).await.unwrap().is_none());
        assert_eq!(store.root().await.unwrap().unwrap().root, root.root);

        let tx = db.begin().await.unwrap();
        let undo = KeyRegistry::apply(
            &RingStore::new(&tx, root.program),
            Step {
                root: &root,
                transition: registration(&root, 8, registered.new_root),
                revision: cursor.advance_revision().unwrap(),
            },
        )
        .await
        .unwrap();
        let metadata = BlockMetadata {
            slot: 3,
            blockhash: Hash(field(3)),
            ..Default::default()
        };
        storage::save_journal(
            &tx,
            &BlockJournal {
                metadata: metadata.clone(),
                previous_tip: None,
                undo: BlockUndo {
                    head_map: vec![],
                    key_registry: vec![undo],
                },
            },
        )
        .await
        .unwrap();
        cursor.tip = Some(metadata);
        cursor.scanned_slot = 3;
        storage::save_cursor(&tx, &cursor).await.unwrap();
        tx.commit().await.unwrap();

        let mut restarted = storage::cursor(&db).await.unwrap().unwrap();
        let tx = db.begin().await.unwrap();
        storage::rollback(&tx, &mut restarted).await.unwrap();
        tx.commit().await.unwrap();
        assert!(store.member(&subject).await.unwrap().is_none());
        assert_eq!(store.root().await.unwrap().unwrap().root, root.root);
        assert!(restarted.tip.is_none());
        assert!(!restarted.is_ready());

        let tx = db.begin().await.unwrap();
        let path = proof::path::<KeyRegistry>(&tx, &root, 0).await.unwrap();
        let sentinel = RingStore::<_, KeyRegistry>::new(&tx, root.program)
            .member(&[0; 32])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sentinel.hash().unwrap(), path.leaf);
        assert_eq!(path.root(0).unwrap(), root.root);
        KeyRegistry::apply(
            &RingStore::new(&tx, root.program),
            Step {
                root: &root,
                transition: registration(&root, 8, registered.new_root),
                revision: restarted.advance_revision().unwrap(),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            store.root().await.unwrap().unwrap().root,
            registered.new_root
        );
    }

    #[tokio::test]
    async fn key_lookup_fails_closed_before_rpc_when_projection_or_root_is_stale() {
        let (db, root, mut cursor) = fixture::<KeyRegistry>().await;
        let rpc = RpcClient::new("http://127.0.0.1:1".into());
        let request = RingMemberProofRequest {
            ring_program_id: Pubkey::new_from_array(root.program).into(),
            member: Hash(member(4)),
            expected_root: Hash(root.root),
            expected_next_index: 1,
        };
        assert!(matches!(
            lookup(&db, &rpc, request.clone()).await,
            Err(PhotonApiError::RingProjection(
                RingProjectionError::OutOfSync {
                    kind: ProjectionKind::KeyRegistry,
                    ..
                }
            ))
        ));
        cursor.resume(&db).await.unwrap();
        let mut stale = request.clone();
        stale.expected_next_index = 2;
        assert_eq!(
            lookup(&db, &rpc, stale).await,
            Err(RingProjectionError::RootChanged(ProjectionKind::KeyRegistry).into())
        );
        assert_eq!(
            lookup(&db, &rpc, request).await,
            Err(RingProjectionError::MemberUnregistered(ProjectionKind::KeyRegistry).into())
        );
    }
}
