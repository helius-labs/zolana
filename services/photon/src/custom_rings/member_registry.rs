use std::collections::{BTreeMap, BTreeSet};

use custom_ring_interface::{
    ApplyRecordsIxData, CustomRingError, MemberRegistry, PendingApplication, QueueEntry,
    RecordQueue, MEMBER_REGISTRY_CAPACITY,
};
use sea_orm::ConnectionTrait;
use zolana_indexer_api::Hash;
use zolana_ring_indexer::{
    records::{CanonicalAccounts, QueuedWrite, RecordAction, RecordChange, SealedKey},
    tree::{node_keys, LoadedTree, MemberRead, MemberRecord, ReadRows, WrittenRows},
};

use super::{
    fault, from_storage,
    storage::{HistoryRoot, RegistryState, RegistryStore, StoredEntry, StoredRecord},
    ApplyError,
};

pub(crate) use super::api::{
    apply_proof_inputs, member_openings, member_record, member_records, record_queue, registry_root,
};

/// `stored` keeps the sealed keys the tree does not hold.
pub(crate) struct LoadedRegistry {
    pub tree: LoadedTree,
    pub stored: BTreeMap<[u8; 32], StoredRecord>,
}

pub(crate) struct TreeRead<'r> {
    pub root: &'r HistoryRoot,
    pub records: RecordRead,
    /// Empty leaves past `next_index` the read loads for new records.
    pub inserts: u64,
}

pub(crate) enum RecordRead {
    /// Each member's record, the low record of an absent member.
    Members(BTreeSet<[u8; 32]>),
    Leaves(Vec<StoredRecord>),
}

impl<'r> TreeRead<'r> {
    /// Reads for applying `entries`, each entry may insert a record.
    pub fn batch(root: &'r HistoryRoot, entries: &[QueueEntry]) -> Self {
        Self {
            root,
            records: RecordRead::Members(entries.iter().map(|entry| entry.member).collect()),
            inserts: entries.len() as u64,
        }
    }

    pub async fn load<C: ConnectionTrait>(
        self,
        store: &RegistryStore<'_, C>,
    ) -> anyhow::Result<LoadedRegistry> {
        let applied = self.root.applied;
        let mut reads = Vec::new();
        let mut stored = BTreeMap::new();
        match self.records {
            RecordRead::Members(members) => {
                for member in members {
                    let read = match store.record(&member, applied).await? {
                        Some(record) => {
                            stored.insert(member, record);
                            MemberRead::Present(record.record)
                        }
                        None => {
                            let low = store.low_record(&member, applied).await?;
                            stored.insert(low.record.record.member, low);
                            MemberRead::Absent {
                                member,
                                low: low.record,
                            }
                        }
                    };
                    reads.push(read);
                }
            }
            RecordRead::Leaves(rows) => {
                for row in rows {
                    reads.push(MemberRead::Present(row.record));
                    stored.insert(row.record.record.member, row);
                }
            }
        }
        let next_index = self.root.next_index;
        let appended = next_index..(next_index + self.inserts).min(MEMBER_REGISTRY_CAPACITY);
        let leaves = stored.values().map(|record| record.record.index);
        let nodes = store
            .nodes(&node_keys(leaves.chain(appended))?, applied)
            .await?;
        let rows = ReadRows {
            next_index,
            reads,
            nodes,
        };
        Ok(LoadedRegistry {
            tree: rows.into_tree(),
            stored,
        })
    }
}

/// The accounts as `CreateMemberRegistry` writes them at `slot`.
pub(crate) fn created(program: [u8; 32], slot: u64) -> RegistryState {
    let canonical = CanonicalAccounts::of(&program.into());
    RegistryState {
        program,
        registry_address: canonical.accounts.registry.to_bytes(),
        queue_address: canonical.accounts.queue.to_bytes(),
        registry: Box::new(MemberRegistry::new(canonical.registry_bump, slot)),
        queue: Box::new(RecordQueue::new(canonical.queue_bump)),
        fault: None,
    }
}

pub(crate) async fn create<C: ConnectionTrait>(
    store: &RegistryStore<'_, C>,
    state: &RegistryState,
) -> anyhow::Result<()> {
    let rows = WrittenRows::fresh()?;
    let records = rows
        .records
        .values()
        .map(|record| StoredRecord {
            record: *record,
            seal: None,
        })
        .collect::<Vec<_>>();
    store.save_records(&records, 0).await?;
    store.save_nodes(&rows.nodes, 0).await?;
    store.save_root(&HistoryRoot::newest(state)).await?;
    store.save_state(state).await
}

pub(crate) struct Projection<'p, 'c, C> {
    pub store: &'p RegistryStore<'c, C>,
    pub state: &'p mut RegistryState,
    pub slot: u64,
}

#[derive(Clone, Copy)]
enum Settlement {
    Permissionless,
    Authority,
}

impl<C: ConnectionTrait> Projection<'_, '_, C> {
    /// A refusal of the program's own admission checks means the projection drifted.
    pub async fn project(mut self, change: RecordChange) -> Result<(), ApplyError> {
        if change.accounts != self.state.accounts() {
            return Err(fault("record instruction names another registry or queue"));
        }
        let state = &*self.state;
        match change.action {
            RecordAction::Queue(write) => {
                admitted(state.queue.admit_member_write(&state.registry))?;
                self.queue(write).await
            }
            RecordAction::AuthorityWrite { writes, apply } => {
                let count = writes.len() as u64;
                admitted(state.queue.admit_authority_writes(count))?;
                for entry in writes {
                    self.queue(QueuedWrite { entry, seal: None }).await?;
                }
                self.apply(&apply, Settlement::Authority).await
            }
            RecordAction::Apply(apply) => {
                admitted(state.queue.apply_due(self.slot))?;
                self.apply(&apply, Settlement::Permissionless).await
            }
        }
    }

    async fn queue(&mut self, write: QueuedWrite) -> Result<(), ApplyError> {
        let position = self.state.queue.tail();
        self.state
            .queue
            .push(&write.entry, self.slot)
            .map_err(|error| fault(format!("queue chain failed ({error})")))?;
        let entry = StoredEntry {
            position,
            write,
            slot: self.slot,
            chain: self.state.queue.chain_tail(),
        };
        self.store.save_entry(&entry).await?;
        Ok(())
    }

    /// The projected root must be the one the program recorded.
    async fn apply(
        &mut self,
        recorded: &ApplyRecordsIxData,
        settlement: Settlement,
    ) -> Result<(), ApplyError> {
        let pending = self.state.queue.head()..self.state.queue.tail();
        if pending.is_empty() {
            return Err(fault(
                "the program applied a queue the projection holds empty",
            ));
        }
        let rows = self
            .store
            .entries(pending.clone())
            .await
            .map_err(from_storage)?;
        let entries = rows.iter().map(|row| row.write.entry).collect::<Vec<_>>();
        let base = HistoryRoot::newest(self.state);
        let loaded = TreeRead::batch(&base, &entries)
            .load(self.store)
            .await
            .map_err(from_storage)?;
        let batch = loaded
            .tree
            .apply_batch(self.state.queue.chain_head, &entries)
            .map_err(|error| fault(format!("records do not apply ({error})")))?;
        let inputs = &batch.inputs;
        let recorded_next_index = u64::from(recorded.new_next_index());
        if inputs.new_root != recorded.new_root || inputs.new_next_index != recorded_next_index {
            return Err(fault(format!(
                "applied root mismatch at position {}, projected {} at {}, program {} at {}",
                pending.end,
                Hash(inputs.new_root),
                inputs.new_next_index,
                Hash(recorded.new_root),
                recorded_next_index
            )));
        }
        let sealing = Sealing {
            base: &loaded.stored,
            pending: &rows,
        };
        let records = batch
            .rows
            .records
            .values()
            .map(|record| {
                Ok(StoredRecord {
                    record: *record,
                    seal: sealing.seal(&record.record)?,
                })
            })
            .collect::<Result<Vec<_>, ApplyError>>()?;
        self.store.save_records(&records, pending.end).await?;
        self.store
            .save_nodes(&batch.rows.nodes, pending.end)
            .await?;
        let application = PendingApplication {
            registry: &mut self.state.registry,
            queue: &mut self.state.queue,
        };
        match settlement {
            Settlement::Permissionless => application.settle_permissionless(recorded, self.slot),
            Settlement::Authority => application.settle_authority(recorded, self.slot),
        }
        self.store
            .save_root(&HistoryRoot::newest(self.state))
            .await?;
        Ok(())
    }
}

fn admitted(admission: Result<(), CustomRingError>) -> Result<(), ApplyError> {
    admission.map_err(|error| fault(format!("the projected queue refuses the change ({error})")))
}

struct Sealing<'a> {
    base: &'a BTreeMap<[u8; 32], StoredRecord>,
    pending: &'a [StoredEntry],
}

impl Sealing<'_> {
    /// A record keeps its sealed key, an escrow key the batch filled takes the seal of its entry.
    fn seal(&self, record: &MemberRecord) -> Result<Option<SealedKey>, ApplyError> {
        if record.escrow_key == [0; 32] {
            return Ok(None);
        }
        if let Some(kept) = self
            .base
            .get(&record.member)
            .filter(|stored| stored.record.record.escrow_key == record.escrow_key)
        {
            return Ok(kept.seal);
        }
        self.pending
            .iter()
            .map(|pending| pending.write)
            .find(|write| {
                write.entry.member == record.member && write.entry.escrow_key == record.escrow_key
            })
            .and_then(|write| write.seal)
            .map(Some)
            .ok_or_else(|| fault("an escrow key has no registration in its batch"))
    }
}
