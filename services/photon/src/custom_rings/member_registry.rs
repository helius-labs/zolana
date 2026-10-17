use std::collections::BTreeMap;

use custom_ring_interface::{MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_ROOT_HISTORY};
use sea_orm::DatabaseTransaction;

use super::{
    fault, instruction_view, proof,
    storage::{LeafWrite, MemberRestore, PredecessorError, RingRoot, RingStore, Undo},
    ApplyError, Invocation,
};

pub(crate) use super::api::{member_record, registry_root};
pub(crate) use zolana_ring_indexer::member_registry::{Batch, MemberRecordRow};

pub(crate) fn transition(invocation: &Invocation<'_>) -> Result<Option<Batch>, ApplyError> {
    zolana_ring_indexer::member_registry::batch(instruction_view(invocation.instruction))
        .map_err(|error| fault(format!("{error:#}")))
}

/// Applies the batch in item order against the stored rows, then writes each touched
/// leaf once. The computed root must be the proven one before anything is published.
pub(crate) async fn apply(
    store: &RingStore<'_, DatabaseTransaction>,
    root: &RingRoot,
    batch: Batch,
    revision: u64,
) -> Result<Undo, ApplyError> {
    let mut rows = Rows::default();
    let mut undo = Undo::root(root.program, Some(root.clone()));
    let mut next_index = root.next_index;
    for item in &batch.items {
        match rows.load(store, &item.member).await? {
            Some(existing) => {
                if existing.index != item.index
                    || (batch.seal.is_none() && existing.lists != item.old_lists)
                    || existing.escrow_key != item.old_escrow_key
                {
                    return Err(fault("record mismatch"));
                }
                rows.capture(&mut undo, &existing)?;
                let mut written = existing.clone();
                // Registration proves that list bits stay unchanged but does not
                // expose them as public inputs. Use the authenticated stored row.
                // List-update batches bind their wire values to the proven root.
                if batch.seal.is_none() {
                    written.lists = item.lists;
                }
                written.escrow_key = item.escrow_key;
                if item.escrow_key != item.old_escrow_key {
                    written.seal = batch.seal.clone();
                }
                rows.put(written);
            }
            None => {
                if item.index != next_index
                    || next_index >= MEMBER_REGISTRY_CAPACITY
                    || item.old_lists != 0
                    || item.old_escrow_key != [0; 32]
                {
                    return Err(fault("append cursor mismatch"));
                }
                if proof::path(store.conn, root, next_index).await?.leaf != [0; 32] {
                    return Err(fault("append slot occupied"));
                }
                let low = rows.predecessor(store, &item.member).await?;
                rows.capture(&mut undo, &low)?;
                let added = MemberRecordRow {
                    member: item.member,
                    index: next_index,
                    next: low.next,
                    lists: item.lists,
                    escrow_key: item.escrow_key,
                    seal: batch.seal.clone(),
                };
                undo.members.push(MemberRestore {
                    member: item.member,
                    before: None,
                });
                undo.leaves.push(LeafWrite {
                    index: next_index,
                    hash: [0; 32],
                });
                let mut relinked = low;
                relinked.next = item.member;
                rows.put(relinked);
                rows.put(added);
                next_index += 1;
            }
        }
    }
    let leaves = rows
        .touched
        .values()
        .map(LeafWrite::of)
        .collect::<Result<Vec<_>, _>>()?;
    let computed = store.write_leaves(&root.address, &leaves, revision).await?;
    if computed != batch.new_root {
        return Err(fault("new root mismatch"));
    }
    for row in rows.touched.values() {
        store.save_member(row).await?;
    }
    let history_cursor = (root.history_cursor as usize + 1) % MEMBER_REGISTRY_ROOT_HISTORY;
    store
        .save_root(&RingRoot {
            root: batch.new_root,
            next_index,
            history_cursor: history_cursor as u8,
            ..root.clone()
        })
        .await?;
    Ok(undo)
}

/// Rows the batch reads and writes, earlier items are visible to later ones.
#[derive(Default)]
struct Rows {
    touched: BTreeMap<[u8; 32], MemberRecordRow>,
    captured: Vec<[u8; 32]>,
}

impl Rows {
    async fn load(
        &self,
        store: &RingStore<'_, DatabaseTransaction>,
        member: &[u8; 32],
    ) -> Result<Option<MemberRecordRow>, ApplyError> {
        if let Some(row) = self.touched.get(member) {
            return Ok(Some(row.clone()));
        }
        Ok(store.member(member).await?)
    }

    /// The stored predecessor loses to a touched record that sits closer below `member`.
    async fn predecessor(
        &self,
        store: &RingStore<'_, DatabaseTransaction>,
        member: &[u8; 32],
    ) -> Result<MemberRecordRow, ApplyError> {
        let stored = match store.predecessor(member).await {
            Ok(low) => Some(low),
            Err(PredecessorError::NotAbsent) => None,
            Err(PredecessorError::Storage(error)) => return Err(error.into()),
        };
        let touched = self
            .touched
            .range(..*member)
            .next_back()
            .map(|(_, row)| row);
        let low = match (stored, touched) {
            (Some(stored), Some(touched)) if touched.member > stored.member => touched.clone(),
            (Some(stored), _) => self.touched.get(&stored.member).cloned().unwrap_or(stored),
            (None, Some(touched)) => touched.clone(),
            (None, None) => return Err(fault("no covering predecessor")),
        };
        if !(low.member < *member && *member < low.next) {
            return Err(fault("member is not absent"));
        }
        Ok(low)
    }

    /// Rollback restores the first state of each touched row.
    fn capture(&mut self, undo: &mut Undo, before: &MemberRecordRow) -> Result<(), ApplyError> {
        if self.captured.contains(&before.member) {
            return Ok(());
        }
        self.captured.push(before.member);
        undo.members.push(MemberRestore {
            member: before.member,
            before: Some(before.clone()),
        });
        undo.leaves.push(LeafWrite::of(before)?);
        Ok(())
    }

    fn put(&mut self, row: MemberRecordRow) {
        self.touched.insert(row.member, row);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::error::{CustomRingError, PhotonApiError},
        custom_rings::{
            proof,
            storage::{self, BlockJournal, BlockUndo},
            tests::{field, fixture, member},
        },
        ingester::typedefs::block_info::BlockMetadata,
        rpc::RpcClient,
    };
    use custom_ring_interface::{EscrowKey, MemberUpdate};
    use sea_orm::TransactionTrait;
    use solana_pubkey::Pubkey;
    use zolana_indexer_api::{GetRingMemberRecordRequest, Hash};
    use zolana_ring_indexer::member_registry::SealedKey;
    use zolana_ring_member_registry::MemberRegistryTree;

    fn escrow_key(seed: u8) -> [u8; 32] {
        EscrowKey {
            nullifier_pk: &field(seed),
            ciphertext: &[seed; 32],
        }
        .hash()
        .unwrap()
    }

    fn batch(items: Vec<MemberUpdate>, new_root: [u8; 32]) -> Batch {
        Batch {
            new_root,
            items,
            seal: None,
        }
    }

    #[tokio::test]
    async fn batches_follow_the_reference_tree_through_inserts_and_rewrites() {
        let (db, mut root, mut cursor) = fixture().await;
        let mut reference = MemberRegistryTree::new().unwrap();
        let writes: [Vec<([u8; 32], u64)>; 3] = [
            vec![(member(5), 1), (member(9), 2)],
            vec![(member(2), 1), (member(5), 3), (member(8), 1)],
            vec![(member(9), 0)],
        ];
        for writes in writes {
            let items = reference.list_items(&writes).unwrap();
            reference.apply(&items).unwrap();
            let tx = db.begin().await.unwrap();
            let store = RingStore::new(&tx, root.program);
            apply(
                &store,
                &root,
                batch(items, reference.root()),
                cursor.advance_revision().unwrap(),
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
            assert_eq!(root.next_index, reference.next_index());
        }
        assert_eq!(root.history_cursor, 3);
        let store = RingStore::new(&db, root.program);
        let five = store.member(&member(5)).await.unwrap().unwrap();
        assert_eq!(five.lists, 3);
        assert_eq!(five.next, reference.find(&member(5)).unwrap().1.next);
        let tx = db.begin().await.unwrap();
        let path = proof::path(&tx, &root, five.index).await.unwrap();
        assert_eq!(path.leaf, five.hash().unwrap());
    }

    #[tokio::test]
    async fn a_registration_keeps_the_seal_with_its_record() {
        let (db, root, mut cursor) = fixture().await;
        let mut reference = MemberRegistryTree::new().unwrap();
        let item = reference.register_item(&member(5), escrow_key(5)).unwrap();
        reference.apply(&[item]).unwrap();
        let tx = db.begin().await.unwrap();
        apply(
            &RingStore::new(&tx, root.program),
            &root,
            Batch {
                new_root: reference.root(),
                items: vec![item],
                seal: Some(SealedKey {
                    eph_pk: [5; 33],
                    ciphertext: [5; 32],
                }),
            },
            cursor.advance_revision().unwrap(),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let row = RingStore::new(&db, root.program)
            .member(&member(5))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.escrow_key, escrow_key(5));
        assert_eq!(row.seal.unwrap().ciphertext, [5; 32]);
    }

    #[tokio::test]
    async fn registration_reconstructs_lists_from_the_authenticated_record() {
        let (db, mut root, mut cursor) = fixture().await;
        let mut reference = MemberRegistryTree::new().unwrap();
        let subject = member(5);
        let items = reference.list_items(&[(subject, 3)]).unwrap();
        reference.apply(&items).unwrap();
        let tx = db.begin().await.unwrap();
        apply(
            &RingStore::new(&tx, root.program),
            &root,
            batch(items, reference.root()),
            cursor.advance_revision().unwrap(),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        root = RingStore::new(&db, root.program)
            .root()
            .await
            .unwrap()
            .unwrap();

        let mut item = reference.register_item(&subject, escrow_key(5)).unwrap();
        reference.apply(&[item]).unwrap();
        // These redundant fields are not in the registration's public inputs.
        // This storage fixture has no proof. The proven root authenticates the
        // reconstructed row, including its existing list membership.
        item.old_lists = 0;
        item.lists = 0;
        let tx = db.begin().await.unwrap();
        let store = RingStore::new(&tx, root.program);
        apply(
            &store,
            &root,
            Batch {
                new_root: reference.root(),
                items: vec![item],
                seal: Some(SealedKey {
                    eph_pk: [5; 33],
                    ciphertext: [5; 32],
                }),
            },
            cursor.advance_revision().unwrap(),
        )
        .await
        .unwrap();
        let row = store.member(&subject).await.unwrap().unwrap();
        assert_eq!(row.lists, 3);
        assert_eq!(row.escrow_key, escrow_key(5));
        assert_eq!(row.seal.unwrap().ciphertext, [5; 32]);
        assert_eq!(store.root().await.unwrap().unwrap().root, reference.root());
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn failed_batches_roll_back_and_committed_blocks_rewind_and_replay() {
        let (db, root, mut cursor) = fixture().await;
        let subject = member(8);
        let mut reference = MemberRegistryTree::new().unwrap();
        let items = reference.list_items(&[(subject, 1)]).unwrap();
        reference.apply(&items).unwrap();
        let tx = db.begin().await.unwrap();
        assert!(apply(
            &RingStore::new(&tx, root.program),
            &root,
            batch(items.clone(), field(99)),
            2,
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
            &root,
            batch(items.clone(), reference.root()),
            cursor.advance_revision().unwrap(),
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
                    member_registry: vec![undo],
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
            &root,
            batch(items, reference.root()),
            restarted.advance_revision().unwrap(),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(store.root().await.unwrap().unwrap().root, reference.root());
    }

    #[tokio::test]
    async fn record_reads_fail_closed_before_rpc_when_projection_or_root_is_stale() {
        let (db, root, mut cursor) = fixture().await;
        let rpc = RpcClient::new("http://127.0.0.1:1".into());
        let request = GetRingMemberRecordRequest {
            ring_program_id: Pubkey::new_from_array(root.program).into(),
            member: Hash(member(4)),
            expected_root: Hash(root.root),
            expected_next_index: 1,
        };
        assert!(matches!(
            member_record(&db, &rpc, request.clone()).await,
            Err(PhotonApiError::CustomRing(CustomRingError::OutOfSync(_)))
        ));
        cursor.resume(&db).await.unwrap();
        let mut stale = request.clone();
        stale.expected_next_index = 2;
        assert_eq!(
            member_record(&db, &rpc, stale).await,
            Err(CustomRingError::RootChanged.into())
        );
        // The read succeeds up to the chain confirmation, which the dead RPC refuses.
        assert!(matches!(
            member_record(&db, &rpc, request).await,
            Err(PhotonApiError::CustomRing(CustomRingError::OutOfSync(_)))
        ));
    }
}
