use std::{collections::BTreeSet, fmt::Display};

use custom_ring_interface::{
    check_member, tagged_x25519, RecordWriteData, RootEntry, WriteRecordsIxData,
    MEMBER_REGISTRY_CAPACITY,
};
use sea_orm::{DatabaseConnection, DatabaseTransaction, TransactionTrait};
use solana_pubkey::Pubkey;
use solana_transaction_status_client_types::TransactionDetails;
use zolana_indexer_api::{
    Base64String, Context as ApiContext, GetRingApplyProofInputsRequest,
    GetRingApplyProofInputsResponse, GetRingMemberOpeningsRequest, GetRingMemberOpeningsResponse,
    GetRingMemberRecordRequest, GetRingMemberRecordResponse, GetRingMemberRecordsRequest,
    GetRingMemberRecordsResponse, GetRingMemberRegistryRootRequest,
    GetRingMemberRegistryRootResponse, GetRingRecordQueueRequest, GetRingRecordQueueResponse, Hash,
    RingIndexedMemberRecordView, RingMemberOpening, RingMemberRecordView, RingQueueEntryView,
    RingRecordPathView, RingRecordWriteView, RingRegistryRootView, RingRootEntryView,
    SerializablePubkey, MAX_RING_MEMBER_PAGE_LIMIT,
};
use zolana_ring_indexer::tree::{
    MemberRecord, QuadPath, RecordOpening, RecordTree, RecordWriteProofInput,
};

use super::{
    member_registry::{LoadedRegistry, RecordRead, TreeRead},
    storage::{self, CustomRingCursor, HistoryRoot, RegistryState, RegistryStore, StoredRecord},
    ChainRead, ChainRegistry,
};
use crate::{
    api::{
        error::{CustomRingError, PhotonApiError},
        set_transaction_isolation_if_needed,
    },
    ingester::typedefs::block_info::BlockMetadata,
    rpc::RpcClient,
};

pub(crate) async fn member_record(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: GetRingMemberRecordRequest,
) -> Result<GetRingMemberRecordResponse, PhotonApiError> {
    let members = std::slice::from_ref(&request.member);
    check_members(members)?;
    let read = Snapshot::open(db, &request.ring_program_id)
        .await?
        .at_root(&request.expected_root.0)
        .await?;
    if read.root.next_index != request.expected_next_index {
        return Err(CustomRingError::RootChanged.into());
    }
    let GetRingMemberOpeningsResponse {
        context,
        root,
        openings,
    } = read.openings(rpc, members).await?;
    let [opening] = <[RingMemberOpening; 1]>::try_from(openings)
        .map_err(|_| internal("one member did not open exactly once"))?;
    Ok(GetRingMemberRecordResponse {
        context,
        root,
        opening,
    })
}

pub(crate) async fn member_openings(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: GetRingMemberOpeningsRequest,
) -> Result<GetRingMemberOpeningsResponse, PhotonApiError> {
    check_members(&request.members)?;
    Snapshot::open(db, &request.ring_program_id)
        .await?
        .at_root(&request.expected_root.0)
        .await?
        .openings(rpc, &request.members)
        .await
}

/// Contiguous, authenticated member leaves at the newest root.
pub(crate) async fn member_records(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: GetRingMemberRecordsRequest,
) -> Result<GetRingMemberRecordsResponse, PhotonApiError> {
    if request.limit == 0 || request.limit > MAX_RING_MEMBER_PAGE_LIMIT {
        return Err(validation("invalid member registry page limit"));
    }
    if request.start_index == 0 || request.start_index > request.expected_next_index {
        return Err(validation("invalid member registry page start"));
    }
    let snapshot = Snapshot::open(db, &request.ring_program_id).await?;
    let root = HistoryRoot::newest(&snapshot.state);
    if root.root != request.expected_root.0 || root.next_index != request.expected_next_index {
        return Err(CustomRingError::RootChanged.into());
    }
    let end = request
        .start_index
        .saturating_add(request.limit)
        .min(root.next_index);
    let leaves = request.start_index..end;
    let store = snapshot.store();
    let rows = store
        .records_by_index(leaves.clone(), root.applied)
        .await
        .map_err(internal)?;
    if !rows.iter().map(|row| row.record.index).eq(leaves) {
        return Err(CustomRingError::PageGap.into());
    }
    let members = rows
        .iter()
        .map(|row| row.record.record.member)
        .collect::<Vec<_>>();
    let read = TreeRead {
        root: &root,
        records: RecordRead::Leaves(rows),
        inserts: 0,
    };
    let loaded = read.load(&store).await.map_err(internal)?;
    let records = members
        .iter()
        .map(|member| {
            let opening = loaded.opening(&root, member)?;
            Ok(RingIndexedMemberRecordView {
                record: opening.record,
                path: opening.path,
            })
        })
        .collect::<Result<Vec<_>, PhotonApiError>>()?;
    let context = snapshot.confirm(rpc, Served::Root(&root)).await?.context;
    Ok(GetRingMemberRecordsResponse {
        context,
        root: root_view(&root),
        records,
        next_leaf_index: (end < root.next_index).then_some(end),
    })
}

pub(crate) async fn registry_root(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: GetRingMemberRegistryRootRequest,
) -> Result<GetRingMemberRegistryRootResponse, PhotonApiError> {
    let snapshot = Snapshot::open(db, &request.ring_program_id).await?;
    let root = HistoryRoot::newest(&snapshot.state);
    let append_path = if root.next_index < MEMBER_REGISTRY_CAPACITY {
        let read = TreeRead {
            root: &root,
            records: RecordRead::Members(BTreeSet::new()),
            inserts: 1,
        };
        let loaded = read.load(&snapshot.store()).await.map_err(internal)?;
        let path = loaded.tree.path(root.next_index).map_err(internal)?;
        if path.root([0; 32]).map_err(internal)? != root.root {
            return Err(internal("the append path does not reach the newest root"));
        }
        Some(path_view(&path))
    } else {
        None
    };
    let Confirmed { context, state } = snapshot.confirm(rpc, Served::Registry).await?;
    let registry = &state.registry;
    Ok(GetRingMemberRegistryRootResponse {
        context,
        history: registry.history.iter().map(root_entry_view).collect(),
        history_cursor: registry.history_cursor,
        next_index: root.next_index,
        floor: registry.floor(),
        prior_floor: registry.prior_floor(),
        floor_slot: registry.floor_slot(),
        append_path,
    })
}

pub(crate) async fn record_queue(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: GetRingRecordQueueRequest,
) -> Result<GetRingRecordQueueResponse, PhotonApiError> {
    let snapshot = Snapshot::open(db, &request.ring_program_id).await?;
    let pending = snapshot.state.queue.head()..snapshot.state.queue.tail();
    let entries = snapshot
        .store()
        .entries(pending)
        .await
        .map_err(internal)?
        .iter()
        .map(|entry| RingQueueEntryView {
            position: entry.position,
            member: Hash(entry.write.entry.member),
            mask: entry.write.entry.mask,
            value: entry.write.entry.value,
            escrow_key: Hash(entry.write.entry.escrow_key),
            slot: entry.slot,
        })
        .collect();
    let Confirmed { context, state } = snapshot.confirm(rpc, Served::Queue).await?;
    Ok(GetRingRecordQueueResponse {
        context,
        head: state.queue.head(),
        tail: state.queue.tail(),
        chain_head: Hash(state.queue.chain_head),
        entries,
    })
}

pub(crate) async fn apply_proof_inputs(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: GetRingApplyProofInputsRequest,
) -> Result<GetRingApplyProofInputsResponse, PhotonApiError> {
    let authority = request
        .authority_writes
        .iter()
        .map(|write| {
            let lists = WriteRecordsIxData {
                mask: write.mask.to_le_bytes(),
                value: write.value.to_le_bytes(),
            };
            RecordWriteData {
                member: write.member.0,
                lists,
            }
            .entry()
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(validation)?;
    let snapshot = Snapshot::open(db, &request.ring_program_id).await?;
    let state = &snapshot.state;
    let count = authority.len() as u64;
    let refusal = match state.queue.admit_authority_writes(count) {
        Err(error) => Some(validation(error)),
        Ok(()) if state.queue.pending() + count == 0 => {
            Some(validation("the record queue is empty"))
        }
        Ok(()) => None,
    };
    if let Some(refusal) = refusal {
        // A refusal of the projected queue stands only while the chain holds the same queue.
        snapshot.confirm(rpc, Served::Application).await?;
        return Err(refusal);
    }
    let store = snapshot.store();
    let pending = store
        .entries(state.queue.head()..state.queue.tail())
        .await
        .map_err(internal)?;
    let entries = pending
        .iter()
        .map(|row| row.write.entry)
        .chain(authority)
        .collect::<Vec<_>>();
    let root = HistoryRoot::newest(state);
    let loaded = TreeRead::batch(&root, &entries)
        .load(&store)
        .await
        .map_err(internal)?;
    let inputs = loaded
        .tree
        .apply_batch(state.queue.chain_head, &entries)
        .map_err(internal)?
        .inputs;
    if inputs.old_root != root.root {
        return Err(internal("the loaded tree does not reach the newest root"));
    }
    let context = snapshot.confirm(rpc, Served::Application).await?.context;
    Ok(GetRingApplyProofInputsResponse {
        context,
        old_root: Hash(inputs.old_root),
        new_root: Hash(inputs.new_root),
        old_next_index: inputs.old_next_index,
        new_next_index: inputs.new_next_index,
        chain_start: Hash(inputs.chain_start),
        chain_end: Hash(inputs.chain_end),
        writes: inputs.writes.iter().map(write_view).collect(),
    })
}

fn check_members(members: &[Hash]) -> Result<(), PhotonApiError> {
    let count = members.len() as u64;
    if count == 0 || count > MAX_RING_MEMBER_PAGE_LIMIT {
        return Err(validation("invalid member count"));
    }
    members
        .iter()
        .try_for_each(|member| check_member(&member.0).map_err(validation))
}

/// One ring read in a repeatable read transaction at the projection's tip.
struct Snapshot {
    tx: DatabaseTransaction,
    state: RegistryState,
    tip: Option<BlockMetadata>,
}

struct RootRead {
    snapshot: Snapshot,
    root: HistoryRoot,
}

struct Confirmed {
    context: ApiContext,
    state: RegistryState,
}

enum Served<'r> {
    Root(&'r HistoryRoot),
    Registry,
    Queue,
    /// Apply proof inputs, they hold while the queue and the root it applies to stay.
    Application,
}

impl Snapshot {
    /// Fails before any RPC while the projection catches up, replays the ring or holds it quarantined.
    async fn open(
        db: &DatabaseConnection,
        ring_program_id: &SerializablePubkey,
    ) -> Result<Self, PhotonApiError> {
        let program = ring_program_id.0.to_bytes();
        let tx = db.begin().await?;
        set_transaction_isolation_if_needed(&tx).await?;
        let cursor = storage::cursor(&tx)
            .await
            .map_err(internal)?
            .filter(CustomRingCursor::is_ready)
            .ok_or_else(|| out_of_sync("indexer is catching up or recovering"))?;
        let pending = storage::pending_ring(&tx, &program)
            .await
            .map_err(internal)?;
        if pending.is_some() {
            return Err(out_of_sync("ring history is being replayed"));
        }
        let state = RegistryStore::new(&tx, program)
            .state()
            .await
            .map_err(internal)?
            .ok_or_else(|| out_of_sync("initialization has not been indexed"))?;
        if let Some(fault) = &state.fault {
            return Err(out_of_sync(format!("ring quarantined, {fault}")));
        }
        Ok(Self {
            tx,
            state,
            tip: cursor.tip,
        })
    }

    fn store(&self) -> RegistryStore<'_, DatabaseTransaction> {
        RegistryStore::new(&self.tx, self.state.program)
    }

    /// The newest history entry holding `root`, its applied position decides the floor rule.
    async fn at_root(self, root: &[u8; 32]) -> Result<RootRead, PhotonApiError> {
        let (index, entry) = (0u8..)
            .zip(self.state.registry.history.iter())
            .filter(|(_, entry)| entry.root == *root && *root != [0; 32])
            .max_by_key(|(_, entry)| entry.applied())
            .ok_or(CustomRingError::RootChanged)?;
        let root = self
            .store()
            .root(entry.applied())
            .await
            .map_err(internal)?
            .filter(|stored| stored.root == entry.root && stored.history_index == index)
            .ok_or_else(|| internal("a history root is missing from the projection"))?;
        Ok(RootRead {
            snapshot: self,
            root,
        })
    }

    /// Commits the read before the RPC calls.
    async fn confirm(
        self,
        rpc: &RpcClient,
        served: Served<'_>,
    ) -> Result<Confirmed, PhotonApiError> {
        self.tx.commit().await?;
        let tip = self
            .tip
            .as_ref()
            .ok_or_else(|| out_of_sync("cursor has no canonical block"))?;
        let context = canonical_context(rpc, tip).await.map_err(out_of_sync)?;
        let read = ChainRead {
            state: &self.state,
            min_slot: tip.slot,
        };
        let chain = read
            .load(rpc)
            .await
            .map_err(|error| out_of_sync(format!("{error:#}")))?;
        if !served.agrees(&chain, &self.state) {
            return Err(served.moved().into());
        }
        Ok(Confirmed {
            context,
            state: self.state,
        })
    }
}

impl RootRead {
    async fn openings(
        self,
        rpc: &RpcClient,
        members: &[Hash],
    ) -> Result<GetRingMemberOpeningsResponse, PhotonApiError> {
        let root = &self.root;
        let read = TreeRead {
            root,
            records: RecordRead::Members(members.iter().map(|member| member.0).collect()),
            inserts: 0,
        };
        let loaded = read.load(&self.snapshot.store()).await.map_err(internal)?;
        let openings = members
            .iter()
            .map(|member| loaded.opening(root, &member.0))
            .collect::<Result<Vec<_>, _>>()?;
        let served = Served::Root(root);
        let context = self.snapshot.confirm(rpc, served).await?.context;
        Ok(GetRingMemberOpeningsResponse {
            context,
            root: root_view(root),
            openings,
        })
    }
}

impl Served<'_> {
    fn agrees(&self, chain: &ChainRegistry, state: &RegistryState) -> bool {
        match self {
            Self::Root(root) => chain.holds(root),
            Self::Registry => chain.records_match(state),
            Self::Queue => chain.queue == state.queue,
            Self::Application => chain.queue_matches(state),
        }
    }

    fn moved(&self) -> CustomRingError {
        match self {
            Self::Root(_) => CustomRingError::RootChanged,
            Self::Application => CustomRingError::QueueChanged,
            Self::Registry | Self::Queue => {
                CustomRingError::OutOfSync("the on-chain registry has moved".into())
            }
        }
    }
}

impl LoadedRegistry {
    fn opening(
        &self,
        root: &HistoryRoot,
        member: &[u8; 32],
    ) -> Result<RingMemberOpening, PhotonApiError> {
        let opening = self.tree.opening(member).map_err(internal)?;
        opening
            .verify(&root.root, member)
            .map_err(|error| internal(format!("member registry opening disagrees ({error})")))?;
        let (present, record, path) = match opening {
            RecordOpening::Present { record, path } => (true, record, path),
            RecordOpening::Absent { low, path } => (false, low, path),
        };
        let stored = self
            .stored
            .get(&record.member)
            .ok_or_else(|| internal("opened record was not loaded"))?;
        Ok(RingMemberOpening {
            present,
            record: record_view(stored),
            path: path_view(&path),
        })
    }
}

fn record_view(stored: &StoredRecord) -> RingMemberRecordView {
    let seal = stored.seal;
    RingMemberRecordView {
        owner_pubkey: seal.map(|seal| Pubkey::new_from_array(seal.owner_pubkey).into()),
        nullifier_pk: seal.map(|seal| Hash(seal.nullifier_pk)),
        eph_pk: seal.map(|seal| Base64String(tagged_x25519(&seal.eph_u).to_vec())),
        ciphertext: seal.map(|seal| Base64String(seal.ciphertext.to_vec())),
        ..member_view(&stored.record.record)
    }
}

fn member_view(record: &MemberRecord) -> RingMemberRecordView {
    RingMemberRecordView {
        member: Hash(record.member),
        next: Hash(record.next),
        lists: record.lists,
        escrow_key: Hash(record.escrow_key),
        owner_pubkey: None,
        nullifier_pk: None,
        eph_pk: None,
        ciphertext: None,
    }
}

fn write_view(write: &RecordWriteProofInput) -> RingRecordWriteView {
    RingRecordWriteView {
        member: Hash(write.entry.member),
        mask: write.entry.mask,
        value: write.entry.value,
        escrow_key: Hash(write.entry.escrow_key),
        exists: write.exists,
        old_next: Hash(write.old_next),
        old_lists: write.old_lists,
        old_escrow: Hash(write.old_escrow),
        slot: path_view(&write.slot),
        low: member_view(&write.low),
        low_path: path_view(&write.low_path),
    }
}

fn path_view(path: &QuadPath) -> RingRecordPathView {
    RingRecordPathView {
        index: path.index,
        siblings: path.siblings.iter().map(|level| level.map(Hash)).collect(),
    }
}

fn root_view(root: &HistoryRoot) -> RingRegistryRootView {
    RingRegistryRootView {
        root: Hash(root.root),
        root_index: root.history_index,
        applied: root.applied,
        next_index: root.next_index,
    }
}

fn root_entry_view(entry: &RootEntry) -> Option<RingRootEntryView> {
    (entry.root != [0; 32]).then(|| RingRootEntryView {
        root: Hash(entry.root),
        applied: entry.applied(),
        slot: entry.slot(),
    })
}

async fn canonical_context(rpc: &RpcClient, tip: &BlockMetadata) -> anyhow::Result<ApiContext> {
    let block = rpc.get_block(tip.slot, TransactionDetails::None).await?;
    anyhow::ensure!(
        block.blockhash == tip.blockhash.to_string(),
        "cursor is on an orphaned block"
    );
    Ok(ApiContext {
        slot: tip.slot,
        block_time: tip.block_time,
    })
}

fn out_of_sync(reason: impl Display) -> PhotonApiError {
    CustomRingError::OutOfSync(reason.to_string()).into()
}

fn validation(reason: impl Display) -> PhotonApiError {
    PhotonApiError::ValidationError(reason.to_string())
}

fn internal(error: impl Display) -> PhotonApiError {
    PhotonApiError::UnexpectedError(format!("{error:#}"))
}
