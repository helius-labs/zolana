//! A rollback never changes SPP state.

pub(crate) mod api;
pub(crate) mod key_registry;
mod proof;
pub(crate) mod spend_record;
mod storage;

use std::{collections::HashMap, ops::RangeInclusive, sync::Arc, time::Duration};

use anyhow::{bail, ensure, Context, Result};
use custom_ring_interface::{
    instruction::{accounts, tag},
    pda, KeyRegistryRoot, PolicyConfig, RingAccount,
};
use futures::{stream, StreamExt};
use sea_orm::{DatabaseConnection, DatabaseTransaction, TransactionTrait};
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_transaction_status_client_types::TransactionDetails;
use thiserror::Error;
use zolana_hasher::HasherError;
use zolana_interface::state::{discriminator::RING_CONFIG, RingConfig};

use crate::{
    ingester::typedefs::block_info::{
        parse_ui_confirmed_blocked, BlockInfo, BlockMetadata, Instruction, InstructionGroup,
        TransactionInfo,
    },
    rpc::{RpcClient, RpcError},
};
use key_registry::MemberKey;
use spend_record::SpendUndo;
use storage::{
    BlockJournal, BlockUndo, LeafWrite, PendingRing, PredecessorError, ProjectionCursor, RingRoot,
    Store, Undo,
};

const MAX_RETRY_DELAY_SECS: u64 = 15;
const BLOCK_FETCH_CONCURRENCY: usize = 4;
const GET_BLOCKS_PAGE: u64 = 4096;
const BLOCK_BATCH: usize = 32;
const ACCOUNTS_PER_REQUEST: usize = 100;
/// Journal rows older than the deepest confirmed fork are pruned.
const JOURNAL_RETENTION_SLOTS: u64 = 8_192;
/// A ring activated after its pending root expired needs a reindex.
const PENDING_TTL_SLOTS: u64 = 43_200;
const EMPTY_ROOT: [u8; 32] = custom_ring_interface::KEY_REGISTRY_EMPTY_ROOT;

#[derive(Clone, Copy, Debug)]
pub enum StartSlot {
    /// Refused when the stored cursor started elsewhere.
    Explicit(u64),
    Derived(u64),
}

impl StartSlot {
    fn slot(self) -> u64 {
        match self {
            Self::Explicit(slot) | Self::Derived(slot) => slot,
        }
    }
}

pub struct Projector {
    pub db: Arc<DatabaseConnection>,
    pub rpc: Arc<RpcClient>,
    pub start: StartSlot,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Progress {
    CaughtUp,
    Behind,
}

impl Projector {
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut delay = 1;
            loop {
                match self.synchronize().await {
                    Ok(Progress::Behind) => {
                        delay = 1;
                        continue;
                    }
                    Ok(Progress::CaughtUp) => delay = 1,
                    Err(error) => {
                        log::error!("ring projector failed ({error:#})");
                        if let Err(error) = self.suspend().await {
                            log::error!("cannot mark ring projections unavailable ({error:#})");
                        }
                        delay = (delay * 2).min(MAX_RETRY_DELAY_SECS);
                    }
                }
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        })
    }

    async fn synchronize(&self) -> Result<Progress> {
        let db = self.db.as_ref();
        let mut cursor = self.cursor().await?;
        // 1. Rewind orphaned commits before resuming any per-ring replay.
        while let Some(tip) = &cursor.tip {
            if self.canonical(tip).await? {
                break;
            }
            self.rewind_tip(&mut cursor).await?;
        }
        self.replay_pending(&mut cursor).await?;
        // 2. Scan from the canonical tip to include slots filled by a fork.
        cursor.scanned_slot = cursor.tip_slot();
        let target = self.rpc.get_slot().await?;
        if cursor.scanned_slot < target {
            cursor.suspend(db).await?;
            let batch = block_batch(&self.rpc, cursor.scanned_slot + 1..=target).await?;
            for block in self.fetch_blocks(batch.slots).await {
                let block = block?;
                let orphan = cursor
                    .tip
                    .as_ref()
                    .is_some_and(|tip| !tip.is_parent_of(&block.metadata));
                ensure!(!orphan, "ring projection parent mismatch");
                let tx = db.begin().await?;
                self.apply_block(&tx, &block, &mut cursor).await?;
                tx.commit().await?;
            }
            cursor.scanned_slot = batch.scanned_slot;
            storage::save_cursor(db, &cursor).await?;
            let pruned_below = cursor.scanned_slot.saturating_sub(JOURNAL_RETENTION_SLOTS);
            storage::prune_journal(db, pruned_below).await?;
        }
        if cursor.scanned_slot < target {
            return Ok(Progress::Behind);
        }
        // 3. Invalid ring accounts must not serve proofs.
        self.check_roots(&cursor, target).await?;
        cursor.resume(db).await?;
        Ok(Progress::CaughtUp)
    }

    async fn cursor(&self) -> Result<ProjectionCursor> {
        let db = self.db.as_ref();
        let Some(cursor) = storage::cursor(db).await? else {
            let cursor = ProjectionCursor::new(self.start.slot());
            storage::save_cursor(db, &cursor).await?;
            return Ok(cursor);
        };
        if let StartSlot::Explicit(slot) = self.start {
            let start = cursor.start_slot;
            ensure!(
                start == slot,
                "the stored ring projection starts after slot {start}, not {slot}"
            );
        }
        Ok(cursor)
    }

    async fn suspend(&self) -> Result<()> {
        let db = self.db.as_ref();
        if let Some(mut cursor) = storage::cursor(db).await? {
            cursor.suspend(db).await?;
        }
        Ok(())
    }

    async fn rewind_tip(&self, cursor: &mut ProjectionCursor) -> Result<()> {
        let db = self.db.as_ref();
        cursor.suspend(db).await?;
        let tx = db.begin().await?;
        storage::rollback(&tx, cursor).await?;
        tx.commit().await?;
        Ok(())
    }

    /// A pruned slot reads as noncanonical.
    async fn canonical(&self, meta: &BlockMetadata) -> Result<bool> {
        let block = self.rpc.get_block(meta.slot, TransactionDetails::None);
        match block.await {
            Ok(block) => Ok(block.blockhash == meta.blockhash.to_string()),
            Err(error) if error.is_slot_skipped() => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    async fn replay_pending(&self, cursor: &mut ProjectionCursor) -> Result<()> {
        let db = self.db.as_ref();
        let Some(tip) = cursor.tip.clone() else {
            return Ok(());
        };
        let pending = storage::pending(db).await?;
        let programs = pending
            .iter()
            .map(|candidate| Pubkey::new_from_array(candidate.program))
            .collect::<Vec<_>>();
        let registered = registered_rings(&self.rpc, &programs).await?;
        for (candidate, registered) in pending.into_iter().zip(registered) {
            if !registered {
                if candidate.replayed_tip.is_none()
                    && candidate.slot < tip.slot.saturating_sub(PENDING_TTL_SLOTS)
                {
                    storage::delete_pending(db, &candidate.program).await?;
                }
                continue;
            }
            if let Err(error) = self.replay_ring(cursor, &candidate, &tip).await {
                // The checkpoint confines replay retries to the affected ring.
                log::warn!(
                    "ring {} replay paused ({error:#})",
                    Pubkey::new_from_array(candidate.program)
                );
            }
        }
        Ok(())
    }

    /// Other rings keep serving, only the candidate's instructions are applied.
    async fn replay_ring(
        &self,
        cursor: &mut ProjectionCursor,
        candidate: &PendingRing,
        tip: &BlockMetadata,
    ) -> Result<()> {
        let db = self.db.as_ref();
        let mut candidate = candidate.clone();
        // 1. Resume only after the last durable replay block remains canonical.
        if let Some(checkpoint) = &candidate.replayed_tip {
            if !self.canonical(checkpoint).await? {
                bail!("ring replay checkpoint is no longer canonical; waiting for rollback");
            }
        }
        let mut start = candidate
            .replayed_tip
            .as_ref()
            .map_or(Ok(candidate.slot), |tip| {
                tip.slot.checked_add(1).context("slot overflow")
            })?;
        while start <= tip.slot {
            let end = tip.slot.min(start.saturating_add(GET_BLOCKS_PAGE - 1));
            let page = confirmed_page(&self.rpc, start..=end).await?;
            if candidate.replayed_tip.is_none() && page.first() != Some(&candidate.slot) {
                bail!("ring initialization is missing from archive history");
            }
            for chunk in page.chunks(BLOCK_BATCH) {
                for block in self.fetch_blocks(chunk.to_vec()).await {
                    let (block, replayed) = (block?, candidate.replayed_tip.as_ref());
                    let initial =
                        replayed.is_some() || block.metadata.blockhash == candidate.blockhash;
                    ensure!(initial, "ring initialization is no longer canonical");
                    let linked = replayed.is_none_or(|tip| tip.is_parent_of(&block.metadata));
                    ensure!(linked, "ring replay parent mismatch");
                    let journal = storage::journal(db, block.metadata.slot).await?;
                    let hash = &block.metadata.blockhash;
                    let forked = journal
                        .as_ref()
                        .is_some_and(|known| known.metadata.blockhash != *hash);
                    ensure!(!forked, "ring replay crossed a confirmed fork");
                    // 2. Replay progress and undo data must commit together.
                    let tx = db.begin().await?;
                    let undo = self
                        .project_block(&tx, &block, cursor, Scope::Ring(candidate.program))
                        .await?;
                    if let Some(mut journal) = journal {
                        journal.undo.extend(undo);
                        storage::save_journal(&tx, &journal).await?;
                    }
                    storage::save_cursor(&tx, cursor).await?;
                    candidate.replayed_tip = Some(block.metadata.clone());
                    storage::checkpoint_pending(&tx, &candidate).await?;
                    tx.commit().await?;
                }
            }
            start = end.checked_add(1).context("slot overflow")?;
        }
        // 3. Serve the ring only after replay reaches the global tip.
        if !candidate.replayed_tip.as_ref().is_some_and(|checkpoint| {
            checkpoint.slot == tip.slot && checkpoint.blockhash == tip.blockhash
        }) {
            bail!("ring replay has not reached the confirmed projection tip");
        }
        storage::delete_pending(db, &candidate.program).await
    }

    async fn fetch_blocks(&self, slots: Vec<u64>) -> Vec<Result<BlockInfo>> {
        stream::iter(slots)
            .map(|slot| async move {
                let block = self.rpc.get_block(slot, TransactionDetails::Full).await?;
                Ok(parse_ui_confirmed_blocked(block, slot)?)
            })
            .buffered(BLOCK_FETCH_CONCURRENCY)
            .collect()
            .await
    }

    async fn apply_block(
        &self,
        tx: &DatabaseTransaction,
        block: &BlockInfo,
        cursor: &mut ProjectionCursor,
    ) -> Result<()> {
        let undo = self.project_block(tx, block, cursor, Scope::Every).await?;
        storage::save_journal(
            tx,
            &BlockJournal {
                metadata: block.metadata.clone(),
                previous_tip: cursor.tip.clone(),
                undo,
            },
        )
        .await?;
        cursor.tip = Some(block.metadata.clone());
        cursor.scanned_slot = block.metadata.slot;
        cursor.suspend(tx).await
    }

    async fn project_block(
        &self,
        tx: &DatabaseTransaction,
        block: &BlockInfo,
        cursor: &mut ProjectionCursor,
        scope: Scope,
    ) -> Result<BlockUndo> {
        BlockWork {
            tx,
            cursor,
            block,
            scope,
            env: BlockEnv {
                rpc: &self.rpc,
                policies: HashMap::new(),
                tree_ids: HashMap::new(),
            },
        }
        .run()
        .await
    }

    async fn check_roots(&self, cursor: &ProjectionCursor, target: u64) -> Result<()> {
        let db = self.db.as_ref();
        for root in storage::roots(db).await? {
            if root.fault.is_some() || storage::pending_ring(db, &root.program).await?.is_some() {
                continue;
            }
            match load_root(&self.rpc, &Pubkey::new_from_array(root.program)).await {
                // Each proof request checks the exact current root.
                Ok(_) => {}
                Err(ProjectError::Retry(error)) => return Err(error),
                Err(ProjectError::Fault(reason)) => {
                    if self.rpc.get_slot().await? > target {
                        continue;
                    }
                    let tip = cursor
                        .tip
                        .as_ref()
                        .context("root exists without a projection tip")?;
                    let tx = db.begin().await?;
                    let mut journal = storage::journal(&tx, tip.slot)
                        .await?
                        .context("ring projection journal gap")?;
                    let undo = Store::new(&tx, root.program)
                        .quarantine_root(root, reason)
                        .await?;
                    journal.undo.key_registry.push(undo);
                    storage::save_journal(&tx, &journal).await?;
                    tx.commit().await?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Scope {
    Every,
    Ring([u8; 32]),
}

/// The projected families, each with its own undo journal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Spend,
    Key,
}

impl Family {
    fn of(instruction: &Instruction) -> Option<Self> {
        match *instruction.data.first()? {
            tag::REGISTER_SPEND | tag::TRANSACT => Some(Self::Spend),
            tag::CREATE_KEY_REGISTRY_ROOT | tag::REGISTER_KEY => Some(Self::Key),
            _ => None,
        }
    }
}

fn instruction_view(instruction: &Instruction) -> zolana_ring_indexer::InstructionView<'_> {
    zolana_ring_indexer::InstructionView {
        program_id: &instruction.program_id,
        accounts: &instruction.accounts,
        data: &instruction.data,
    }
}

#[derive(Debug, Error)]
pub(crate) enum ProjectError {
    /// Confined to one ring.
    #[error("{0}")]
    Fault(String),
    #[error(transparent)]
    Retry(#[from] anyhow::Error),
}

impl From<sea_orm::DbErr> for ProjectError {
    fn from(error: sea_orm::DbErr) -> Self {
        Self::Retry(error.into())
    }
}

impl From<RpcError> for ProjectError {
    fn from(error: RpcError) -> Self {
        Self::Retry(error.into())
    }
}

impl From<HasherError> for ProjectError {
    fn from(error: HasherError) -> Self {
        fault(format!("hashing failed ({error:?})"))
    }
}

impl From<PredecessorError> for ProjectError {
    fn from(error: PredecessorError) -> Self {
        match error {
            PredecessorError::NotAbsent => fault(error.to_string()),
            PredecessorError::Storage(error) => Self::Retry(error),
        }
    }
}

pub(crate) fn fault(reason: impl Into<String>) -> ProjectError {
    ProjectError::Fault(reason.into())
}

/// A missing or foreign ring account is the ring's fault.
fn ring_account(result: Result<Account, RpcError>) -> Result<Account, ProjectError> {
    match result {
        Err(RpcError::InvalidAccount(reason)) => Err(fault(reason)),
        other => Ok(other?),
    }
}

pub(crate) struct ChainRoot {
    pub root: [u8; 32],
    pub next_index: u64,
}

pub(crate) async fn load_root(
    rpc: &RpcClient,
    program: &Pubkey,
) -> Result<ChainRoot, ProjectError> {
    let (address, bump) = pda::key_registry_root(program);
    let account = ring_account(rpc.get_account(&address).await)?;
    let root = KeyRegistryRoot::decode(&account.owner, program, &account.data)
        .filter(|root| root.bump == bump)
        .ok_or_else(|| fault("key registry root is not the ring's initialized account"))?;
    let current = root
        .root()
        .ok_or_else(|| fault("key registry root has no current root"))?;
    Ok(ChainRoot {
        root: current,
        next_index: root.next_index(),
    })
}

pub(crate) struct BlockEnv<'a> {
    rpc: &'a RpcClient,
    policies: HashMap<[u8; 32], PolicyConfig>,
    tree_ids: HashMap<[u8; 32], u16>,
}

impl BlockEnv<'_> {
    /// One read per ring and block, a ring without a policy is at fault.
    pub(crate) async fn policy(&mut self, program: &Pubkey) -> Result<PolicyConfig, ProjectError> {
        if let Some(policy) = self.policies.get(&program.to_bytes()) {
            return Ok(*policy);
        }
        let address = Pubkey::find_program_address(&[PolicyConfig::SEED], program).0;
        let account = ring_account(self.rpc.get_account(&address).await)?;
        let policy = PolicyConfig::decode(&account.owner, program, &account.data)
            .ok_or_else(|| fault("policy config is not the ring's initialized account"))?;
        self.policies.insert(program.to_bytes(), policy);
        Ok(policy)
    }

    /// A leaf hashes under the id of the tree it lands in.
    pub(crate) async fn tree_id(&mut self, tree: &Pubkey) -> Result<u16, ProjectError> {
        if let Some(id) = self.tree_ids.get(&tree.to_bytes()) {
            return Ok(*id);
        }
        let account = ring_account(self.rpc.get_account(tree).await)?;
        let id = crate::monitor::tree_metadata_sync::rings_tree_id(*tree, &account)
            .filter(|id| zolana_interface::pda::tree(*id).to_bytes() == tree.to_bytes())
            .ok_or_else(|| fault("output tree is not the SPP tree of its id"))?;
        self.tree_ids.insert(tree.to_bytes(), id);
        Ok(id)
    }
}

pub(crate) struct Invocation<'a> {
    pub instruction: &'a Instruction,
    pub subtree: TransactionInfo,
    pub slot: u64,
}

struct Invocations<'a> {
    transaction: &'a TransactionInfo,
    instructions: Vec<&'a Instruction>,
    slot: u64,
}

impl<'a> Invocations<'a> {
    fn new(transaction: &'a TransactionInfo, slot: u64) -> Self {
        let instructions = transaction
            .instruction_groups
            .iter()
            .flat_map(|group| {
                std::iter::once(&group.outer_instruction).chain(group.inner_instructions.iter())
            })
            .collect();
        Self {
            transaction,
            instructions,
            slot,
        }
    }

    fn instructions(&self) -> impl Iterator<Item = (usize, &'a Instruction)> + '_ {
        self.instructions.iter().copied().enumerate()
    }

    fn tag(&self, position: usize) -> Option<u8> {
        self.instructions.get(position)?.data.first().copied()
    }

    /// Sibling invocations cannot supply a transition's SPP event.
    fn invocation(&self, position: usize) -> Result<Invocation<'a>, ProjectError> {
        let (instruction, rest) = self
            .instructions
            .get(position..)
            .and_then(<[&Instruction]>::split_first)
            .context("invocation position out of range")?;
        let depth = instruction
            .stack_height
            .ok_or_else(|| fault("invocation has no stack height"))?;
        let mut children = Vec::new();
        for child in rest {
            let child_depth = child
                .stack_height
                .ok_or_else(|| fault("descendant has no stack height"))?;
            if child_depth <= depth {
                break;
            }
            children.push((*child).clone());
        }
        Ok(Invocation {
            instruction,
            subtree: TransactionInfo {
                instruction_groups: vec![InstructionGroup {
                    outer_instruction: (*instruction).clone(),
                    inner_instructions: children,
                }],
                signature: self.transaction.signature,
                error: None,
            },
            slot: self.slot,
        })
    }
}

struct BlockWork<'a> {
    tx: &'a DatabaseTransaction,
    cursor: &'a mut ProjectionCursor,
    block: &'a BlockInfo,
    scope: Scope,
    env: BlockEnv<'a>,
}

impl BlockWork<'_> {
    async fn run(mut self) -> Result<BlockUndo> {
        let mut undo = BlockUndo::default();
        let (block, slot) = (self.block, self.block.metadata.slot);
        for transaction in block.transactions.iter().filter(|tx| tx.error.is_none()) {
            let invocations = Invocations::new(transaction, slot);
            // A transaction's spend records project before its key registrations.
            for family in [Family::Spend, Family::Key] {
                for (position, instruction) in invocations.instructions() {
                    if Family::of(instruction) == Some(family) {
                        self.project(family, &invocations, position, &mut undo)
                            .await?;
                    }
                }
            }
        }
        Ok(undo)
    }

    async fn project(
        &mut self,
        family: Family,
        invocations: &Invocations<'_>,
        position: usize,
        undo: &mut BlockUndo,
    ) -> Result<()> {
        let program = invocations.instructions[position].program_id.to_bytes();
        let skip = match self.scope {
            Scope::Ring(ring) => ring != program,
            // A pending ring waits for its own replay.
            Scope::Every => storage::pending_ring(self.tx, &program).await?.is_some(),
        };
        let store = Store::new(self.tx, program);
        match family {
            _ if skip => Ok(()),
            Family::Spend => {
                self.spend(&store, invocations, position, &mut undo.spend_records)
                    .await
            }
            Family::Key => {
                self.key(&store, invocations, position, &mut undo.key_registry)
                    .await
            }
        }
    }

    async fn spend(
        &mut self,
        store: &Store<'_, DatabaseTransaction>,
        invocations: &Invocations<'_>,
        position: usize,
        undo: &mut Vec<SpendUndo>,
    ) -> Result<()> {
        match store.records_fault().await? {
            Some(None) => {}
            // A ring's first registration opens its records.
            None if invocations.tag(position) == Some(tag::REGISTER_SPEND) => {
                if !self.admit(store.program).await? {
                    return Ok(());
                }
                undo.push(store.open_records().await?);
            }
            None | Some(Some(_)) => return Ok(()),
        }
        let outcome = async {
            let invocation = invocations.invocation(position)?;
            store.advance(&invocation, &mut self.env).await
        }
        .await;
        match outcome {
            Ok(entry) => undo.extend(entry),
            Err(ProjectError::Fault(reason)) => undo.push(store.quarantine_records(reason).await?),
            Err(ProjectError::Retry(error)) => return Err(error),
        }
        Ok(())
    }

    async fn key(
        &mut self,
        store: &Store<'_, DatabaseTransaction>,
        invocations: &Invocations<'_>,
        position: usize,
        undo: &mut Vec<Undo>,
    ) -> Result<()> {
        if invocations.tag(position) == Some(tag::CREATE_KEY_REGISTRY_ROOT) {
            if let Some(address) = initialization(invocations.instructions[position]) {
                undo.extend(self.initialize(store, address).await?);
            }
            return Ok(());
        }
        let Some(root) = store.root().await?.filter(|root| root.fault.is_none()) else {
            return Ok(());
        };
        let outcome = async { self.advance(&root, invocations.invocation(position)?).await }.await;
        match outcome {
            Ok(entry) => undo.extend(entry),
            Err(ProjectError::Fault(reason)) => {
                undo.push(store.quarantine_root(root, reason).await?)
            }
            Err(ProjectError::Retry(error)) => return Err(error),
        }
        Ok(())
    }

    /// `false` parks an inactive ring for replay once it activates.
    async fn admit(&mut self, program: [u8; 32]) -> Result<bool> {
        if registered_ring(self.env.rpc, &Pubkey::new_from_array(program)).await? {
            return Ok(true);
        }
        if matches!(self.scope, Scope::Ring(_)) {
            bail!("ring became inactive during replay");
        }
        storage::save_pending(
            self.tx,
            &PendingRing {
                program,
                slot: self.block.metadata.slot,
                blockhash: self.block.metadata.blockhash.clone(),
                replayed_tip: None,
            },
        )
        .await?;
        Ok(false)
    }

    async fn initialize(
        &mut self,
        store: &Store<'_, DatabaseTransaction>,
        address: [u8; 32],
    ) -> Result<Option<Undo>> {
        let program = Pubkey::new_from_array(store.program);
        if !self.admit(store.program).await? {
            return Ok(None);
        }
        if let Some(existing) = store.root().await? {
            let reason = "initialized twice".into();
            return Ok(Some(store.quarantine_root(existing, reason).await?));
        }
        let root = RingRoot {
            program: store.program,
            address,
            root: EMPTY_ROOT,
            next_index: 1,
            fault: None,
        };
        match load_root(self.env.rpc, &program).await {
            Ok(_) => {}
            Err(ProjectError::Fault(reason)) => {
                let mut created = store.quarantine_root(root, reason).await?;
                created.before = None;
                return Ok(Some(created));
            }
            Err(ProjectError::Retry(error)) => return Err(error),
        }
        let sentinel = MemberKey::sentinel();
        let leaves = [LeafWrite::of(&sentinel)?];
        let revision = self.cursor.advance_revision()?;
        if store.write_leaves(&address, &leaves, revision).await? != EMPTY_ROOT {
            bail!("key registry sentinel root mismatch");
        }
        store.save_root(&root).await?;
        store.save_member(&sentinel).await?;
        Ok(Some(Undo::root(root.program, None)))
    }

    async fn advance(
        &mut self,
        root: &RingRoot,
        invocation: Invocation<'_>,
    ) -> Result<Option<Undo>, ProjectError> {
        let Some(transition) = key_registry::transition(&invocation)? else {
            return Ok(None);
        };
        let revision = self.cursor.advance_revision()?;
        let savepoint = self.tx.begin().await?;
        let store = Store::new(&savepoint, root.program);
        let applied = key_registry::apply(&store, root, transition, revision).await;
        match applied {
            Ok(_) => savepoint.commit().await?,
            Err(_) => savepoint.rollback().await?,
        }
        applied.map(Some)
    }
}

fn initialization(instruction: &Instruction) -> Option<[u8; 32]> {
    let root = pda::key_registry_root(&instruction.program_id).0;
    let named = instruction
        .accounts
        .get(accounts::CREATE_KEY_REGISTRY_ROOT_ROOT);
    (named == Some(&root)).then_some(root.to_bytes())
}

async fn registered_ring(rpc: &RpcClient, program: &Pubkey) -> Result<bool> {
    Ok(registered_rings(rpc, std::slice::from_ref(program)).await? == [true])
}

async fn registered_rings(rpc: &RpcClient, programs: &[Pubkey]) -> Result<Vec<bool>> {
    let mut registered = Vec::with_capacity(programs.len());
    for chunk in programs.chunks(ACCOUNTS_PER_REQUEST) {
        let addresses = chunk
            .iter()
            .map(|program| zolana_interface::pda::ring_auth(program).0)
            .collect::<Vec<_>>();
        let accounts = rpc.get_multiple_accounts(&addresses).await?;
        registered.extend(chunk.iter().zip(accounts).map(|(program, account)| {
            account.is_some_and(|account| activated_ring_config(&account, program))
        }));
    }
    Ok(registered)
}

fn activated_ring_config(account: &Account, program: &Pubkey) -> bool {
    account.owner == zolana_interface::pda::shielded_pool_program_id()
        && bytemuck::try_from_bytes::<RingConfig>(&account.data).is_ok_and(|config| {
            config.discriminator == RING_CONFIG
                && config.program_id == *program
                && config.is_activated()
        })
}

struct BlockBatch {
    slots: Vec<u64>,
    scanned_slot: u64,
}

async fn block_batch(rpc: &RpcClient, slots: RangeInclusive<u64>) -> Result<BlockBatch> {
    let mut start = *slots.start();
    let target = *slots.end();
    let mut batch = Vec::new();
    loop {
        let end = target.min(start.saturating_add(GET_BLOCKS_PAGE - 1));
        let page = confirmed_page(rpc, start..=end).await?;
        let available = BLOCK_BATCH - batch.len();
        if page.len() > available {
            batch.extend(page.into_iter().take(available));
            let scanned = *batch.last().context("empty block batch")?;
            return Ok(BlockBatch {
                slots: batch,
                scanned_slot: scanned,
            });
        }
        batch.extend(page);
        if end == target || batch.len() == BLOCK_BATCH {
            return Ok(BlockBatch {
                slots: batch,
                scanned_slot: end,
            });
        }
        start = end.checked_add(1).context("slot overflow")?;
    }
}

async fn confirmed_page(rpc: &RpcClient, range: RangeInclusive<u64>) -> Result<Vec<u64>> {
    let page = rpc.get_blocks(range.clone()).await?;
    if page.iter().any(|slot| !range.contains(slot))
        || page.windows(2).any(|pair| pair[0] >= pair[1])
    {
        bail!("invalid confirmed block order");
    }
    Ok(page)
}

#[cfg(test)]
mod replay_tests;
#[cfg(test)]
mod tests;
