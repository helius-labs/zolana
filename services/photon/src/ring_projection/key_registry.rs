use anyhow::Context;
use custom_ring_interface::KEY_REGISTRY_CAPACITY;
use sea_orm::{DatabaseConnection, DatabaseTransaction};
use zolana_indexer_api::{
    Base64String, GetRingKeyRegistryEntryResponse, GetRingKeyRegistryRegisterProofResponse, Hash,
    RingMemberProofRequest,
};
use zolana_ring_indexer::key_registry::Spliced;

use super::{
    api::{self, Insertion, MemberPath},
    fault, instruction_view, proof,
    storage::{LeafWrite, MemberRestore, RingRoot, RingStore, Undo},
    Invocation, ProjectError, Step,
};
use crate::{api::error::PhotonApiError, rpc::RpcClient};

pub(crate) use zolana_ring_indexer::key_registry::{MemberKey, Registration};

pub(crate) fn transition(
    invocation: &Invocation<'_>,
) -> Result<Option<Registration>, ProjectError> {
    zolana_ring_indexer::key_registry::registration(instruction_view(invocation.instruction))
        .map_err(|error| fault(format!("{error:#}")))
}

pub(crate) async fn apply(
    store: &RingStore<'_, DatabaseTransaction>,
    step: Step<'_>,
) -> Result<Undo, ProjectError> {
    let Step {
        root,
        transition,
        revision,
    } = step;
    let &Registration {
        old_root,
        new_root,
        next_index,
        member,
        ..
    } = &transition;
    // 1. Require the current root, append cursor and an absent member.
    if next_index != root.next_index || next_index >= KEY_REGISTRY_CAPACITY {
        return Err(fault("append cursor mismatch"));
    }
    if old_root != root.root {
        return Err(fault("old root mismatch"));
    }
    if store.member(&member).await?.is_some() {
        return Err(fault("duplicate member"));
    }
    let low = store.predecessor(&member).await?;
    if proof::path(store.conn(), root, next_index).await?.leaf != [0; 32] {
        return Err(fault("append slot occupied"));
    }
    // 2. Rollback needs both leaves before the ordered chain changes.
    let undo = Undo {
        program: root.program,
        before: Some(root.clone()),
        members: vec![
            MemberRestore {
                member: low.member,
                before: Some(low.clone()),
            },
            MemberRestore {
                member,
                before: None,
            },
        ],
        leaves: vec![
            LeafWrite {
                index: low.index,
                hash: low.hash()?,
            },
            LeafWrite {
                index: next_index,
                hash: [0; 32],
            },
        ],
    };
    let Spliced {
        predecessor: spliced,
        added,
    } = transition
        .splice(low)
        .map_err(|error| fault(error.to_string()))?;
    let computed = store
        .write_leaves(
            &root.address,
            &[
                LeafWrite {
                    index: spliced.index,
                    hash: spliced.hash()?,
                },
                LeafWrite {
                    index: added.index,
                    hash: added.hash()?,
                },
            ],
            revision,
        )
        .await?;
    // 3. Reconstructed leaves must match the proven root before publication.
    if computed != new_root {
        return Err(fault("new root mismatch"));
    }
    store.save_member(&spliced).await?;
    store.save_member(&added).await?;
    store
        .save_root(&RingRoot {
            root: new_root,
            next_index: next_index
                .checked_add(1)
                .context("append cursor overflow")?,
            ..root.clone()
        })
        .await?;
    Ok(undo)
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
    } = api::insertion(db, rpc, &request).await?;
    Ok(GetRingKeyRegistryRegisterProofResponse {
        context,
        root: Hash(root.root),
        next_index: root.next_index,
        member: request.member,
        low_member: Hash(low.member),
        low_next: Hash(low.next),
        low_key_hash: Hash(low.key_hash),
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
    } = api::member_path(db, rpc, &request).await?;
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
    use custom_ring_interface::RegisteredKey;
    use sea_orm::TransactionTrait;
    use solana_pubkey::Pubkey;
    use zolana_ring_key_registry::KeyRegistryTree;

    fn key_hash(seed: u8) -> [u8; 32] {
        RegisteredKey {
            nullifier_pk: &field(seed),
            ciphertext: &[seed; 32],
        }
        .hash()
        .unwrap()
    }

    fn registration(root: &storage::RingRoot, seed: u8, new_root: [u8; 32]) -> Registration {
        Registration {
            old_root: root.root,
            new_root,
            next_index: root.next_index,
            member: member(seed),
            key_hash: key_hash(seed),
            eph_pk: [seed; 33],
            ciphertext: [seed; 32],
        }
    }

    #[tokio::test]
    async fn key_insert_path_matches_reference_without_mutating_reads() {
        let (db, mut root, mut cursor) = fixture().await;
        let mut reference = KeyRegistryTree::new().unwrap();
        for seed in [5u8, 9, 2, 8] {
            let subject = member(seed);
            let tx = db.begin().await.unwrap();
            let store = RingStore::new(&tx, root.program);
            let low = store.predecessor(&subject).await.unwrap();
            let low_path = proof::path(&tx, &root, low.index).await.unwrap();
            let slot = proof::path(&tx, &root, root.next_index).await.unwrap();
            assert_eq!(slot.leaf, [0; 32]);
            let inputs = reference
                .register(zolana_ring_key_registry::Registration {
                    member: subject,
                    key: key_hash(seed),
                })
                .unwrap();
            assert_eq!(low_path.siblings, inputs.low_proof);
            assert_eq!(store.root().await.unwrap().unwrap().root, root.root);
            apply(
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
            root = RingStore::new(&db, root.program)
                .root()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(root.root, reference.root());
        }
    }

    #[tokio::test]
    async fn failed_key_registration_rolls_back_and_committed_block_rewinds_and_replays() {
        let (db, root, mut cursor) = fixture().await;
        let subject = member(8);
        let mut reference = KeyRegistryTree::new().unwrap();
        let registered = reference
            .register(zolana_ring_key_registry::Registration {
                member: subject,
                key: key_hash(8),
            })
            .unwrap();
        let tx = db.begin().await.unwrap();
        assert!(apply(
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
        let store = RingStore::new(&db, root.program);
        assert!(store.member(&subject).await.unwrap().is_none());
        assert_eq!(store.root().await.unwrap().unwrap().root, root.root);

        let tx = db.begin().await.unwrap();
        let undo = apply(
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
                    spend_records: vec![],
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
        let path = proof::path(&tx, &root, 0).await.unwrap();
        let sentinel = RingStore::new(&tx, root.program)
            .member(&[0; 32])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sentinel.hash().unwrap(), path.leaf);
        assert_eq!(path.root(0).unwrap(), root.root);
        apply(
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
        let (db, root, mut cursor) = fixture().await;
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
                RingProjectionError::OutOfSync(_)
            ))
        ));
        cursor.resume(&db).await.unwrap();
        let mut stale = request.clone();
        stale.expected_next_index = 2;
        assert_eq!(
            lookup(&db, &rpc, stale).await,
            Err(RingProjectionError::RootChanged.into())
        );
        assert_eq!(
            lookup(&db, &rpc, request).await,
            Err(RingProjectionError::MemberUnregistered.into())
        );
    }
}
