//! A rollback never changes SPP state.

pub(crate) mod api;
pub(crate) mod key_registry;
mod proof;
pub(crate) mod spend_record;
mod storage;

use std::{collections::HashMap, ops::RangeInclusive, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use custom_ring_interface::{
    instruction::{accounts, tag},
    pda, KeyRegistryRoot, PolicyConfig, KEY_REGISTRY_ROOT, POLICY_CONFIG,
};
use futures::{Stream, StreamExt};
use sea_orm::{DatabaseConnection, DatabaseTransaction, TransactionTrait};
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_transaction_status_client_types::TransactionDetails;
use thiserror::Error;
use zolana_hasher::HasherError;
use zolana_indexer_api::Hash;
use zolana_interface::state::{discriminator::RING_CONFIG, RingConfig};

use crate::{
    ingester::{
        fetchers::{
            range::{block_range, RangeError},
            spawn_stream,
        },
        typedefs::block_info::{
            BlockInfo, BlockMetadata, Instruction, InstructionGroup, TransactionInfo,
        },
    },
    rpc::{RpcClient, RpcError},
};
use key_registry::{MemberKey, Registration};
use spend_record::{SpendRing, SpendStore, SpendUndo};
use storage::{
    BlockJournal, BlockUndo, CustomRingCursor, LeafWrite, PendingRing, PredecessorError, RingRoot,
    RingStore, Undo,
};

const MAX_RETRY_DELAY_SECS: u64 = 15;
/// Slots scanned per synchronization pass, so a long backfill still returns
/// to rewinds and pending-ring replays between passes.
const PASS_SLOTS: u64 = 1_024;
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

pub struct CustomRingIndexer {
    pub db: Arc<DatabaseConnection>,
    pub rpc: Arc<RpcClient>,
    pub start: StartSlot,
    /// Concurrent `getBlock` requests, photon's `--max-concurrent-block-fetches`.
    pub block_fetches: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Progress {
    CaughtUp,
    Behind,
}

impl CustomRingIndexer {
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
                        log::error!("custom ring indexer failed ({error:#})");
                        if let Err(error) = self.suspend().await {
                            log::error!("cannot mark custom ring lookups unavailable ({error:#})");
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
        cursor.scanned_slot = cursor
            .tip
            .as_ref()
            .map_or(cursor.start_slot, |tip| tip.slot);
        let target = self.rpc.get_slot().await?;
        if cursor.scanned_slot < target {
            cursor.suspend(db).await?;
            let through = target.min(cursor.scanned_slot.saturating_add(PASS_SLOTS));
            let mut blocks = self.blocks(cursor.tip.clone(), cursor.scanned_slot + 1..=through);
            while let Some(block) = blocks.next().await {
                let block = block?;
                let tx = db.begin().await?;
                self.apply_block(&tx, &block, &mut cursor).await?;
                tx.commit().await?;
            }
            cursor.scanned_slot = through;
            storage::save_cursor(db, &cursor).await?;
            let pruned_below = cursor.scanned_slot.saturating_sub(JOURNAL_RETENTION_SLOTS);
            storage::prune_journal(db, pruned_below).await?;
        }
        if cursor.scanned_slot < target {
            log::info!(
                "custom rings indexed through slot {} of {target}",
                cursor.scanned_slot
            );
            return Ok(Progress::Behind);
        }
        // 3. Invalid ring accounts must not serve proofs.
        self.check_roots(&cursor, target).await?;
        cursor.resume(db).await?;
        Ok(Progress::CaughtUp)
    }

    async fn cursor(&self) -> Result<CustomRingCursor> {
        let db = self.db.as_ref();
        match storage::cursor(db).await? {
            Some(cursor) => {
                if let StartSlot::Explicit(slot) = self.start {
                    if cursor.start_slot != slot {
                        bail!(
                            "the stored custom ring index starts after slot {}, not {slot}",
                            cursor.start_slot
                        );
                    }
                }
                Ok(cursor)
            }
            None => {
                let cursor = CustomRingCursor::new(self.start.slot());
                storage::save_cursor(db, &cursor).await?;
                Ok(cursor)
            }
        }
    }

    async fn suspend(&self) -> Result<()> {
        let db = self.db.as_ref();
        if let Some(mut cursor) = storage::cursor(db).await? {
            cursor.suspend(db).await?;
        }
        Ok(())
    }

    async fn rewind_tip(&self, cursor: &mut CustomRingCursor) -> Result<()> {
        let db = self.db.as_ref();
        cursor.suspend(db).await?;
        let tx = db.begin().await?;
        storage::rollback(&tx, cursor).await?;
        tx.commit().await?;
        Ok(())
    }

    /// A pruned slot reads as noncanonical.
    async fn canonical(&self, meta: &BlockMetadata) -> Result<bool> {
        match self
            .rpc
            .get_block(meta.slot, TransactionDetails::None)
            .await
        {
            Ok(block) => Ok(block.blockhash == meta.blockhash.to_string()),
            Err(error) if error.is_slot_skipped() => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    async fn replay_pending(&self, cursor: &mut CustomRingCursor) -> Result<()> {
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
        cursor: &mut CustomRingCursor,
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
        // The first replayed block is the initialization, linked to its parent.
        let (after, start) = match &candidate.replayed_tip {
            Some(checkpoint) => (
                checkpoint.clone(),
                checkpoint.slot.checked_add(1).context("slot overflow")?,
            ),
            None => (
                self.initialization_parent(&candidate).await?,
                candidate.slot,
            ),
        };
        if start <= tip.slot {
            let mut blocks = self.blocks(Some(after), start..=tip.slot);
            while let Some(block) = blocks.next().await {
                let block = block.context("ring replay")?;
                if candidate.replayed_tip.is_none()
                    && block.metadata.blockhash != candidate.blockhash
                {
                    bail!("ring initialization is no longer canonical");
                }
                let journal = storage::journal(db, block.metadata.slot).await?;
                if journal
                    .as_ref()
                    .is_some_and(|journal| journal.metadata.blockhash != block.metadata.blockhash)
                {
                    bail!("ring replay crossed a confirmed fork");
                }
                // 2. Replay progress and undo data must commit together.
                let tx = db.begin().await?;
                let undo = self
                    .index_block(&tx, &block, cursor, Scope::Ring(candidate.program))
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
        // 3. Serve the ring only after replay reaches the global tip.
        if !candidate.replayed_tip.as_ref().is_some_and(|checkpoint| {
            checkpoint.slot == tip.slot && checkpoint.blockhash == tip.blockhash
        }) {
            bail!("ring replay has not reached the confirmed custom ring tip");
        }
        storage::delete_pending(db, &candidate.program).await
    }

    /// Blocks in `slots` linked to `after`, fetched in their own task while
    /// the caller applies the ones before.
    fn blocks(
        &self,
        after: Option<BlockMetadata>,
        slots: RangeInclusive<u64>,
    ) -> impl Stream<Item = Result<BlockInfo, RangeError>> + Unpin {
        spawn_stream(
            block_range(self.rpc.clone(), after, slots, self.block_fetches),
            self.block_fetches,
        )
    }

    /// The block a ring's initialization block names as parent, so replay
    /// starts at the initialization itself.
    async fn initialization_parent(&self, candidate: &PendingRing) -> Result<BlockMetadata> {
        let block = match self
            .rpc
            .get_block(candidate.slot, TransactionDetails::None)
            .await
        {
            Ok(block) => block,
            Err(error) if error.is_slot_skipped() => {
                bail!("ring initialization is missing from archive history")
            }
            Err(error) => return Err(error.into()),
        };
        if block.blockhash != candidate.blockhash.to_string() {
            bail!("ring initialization is no longer canonical");
        }
        Ok(BlockMetadata {
            slot: block.parent_slot,
            blockhash: Hash::try_from(block.previous_blockhash.as_str())
                .map_err(|error| anyhow::anyhow!("invalid parent blockhash ({error})"))?,
            ..Default::default()
        })
    }

    async fn apply_block(
        &self,
        tx: &DatabaseTransaction,
        block: &BlockInfo,
        cursor: &mut CustomRingCursor,
    ) -> Result<()> {
        let undo = self.index_block(tx, block, cursor, Scope::Every).await?;
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

    async fn index_block(
        &self,
        tx: &DatabaseTransaction,
        block: &BlockInfo,
        cursor: &mut CustomRingCursor,
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

    async fn check_roots(&self, cursor: &CustomRingCursor, target: u64) -> Result<()> {
        let db = self.db.as_ref();
        for root in storage::roots(db).await? {
            if root.fault.is_some() || storage::pending_ring(db, &root.program).await?.is_some() {
                continue;
            }
            match load_root(&self.rpc, &Pubkey::new_from_array(root.program)).await {
                // Each proof request checks the exact current root.
                Ok(_) => {}
                Err(ApplyError::Retry(error)) => return Err(error),
                Err(ApplyError::Fault(reason)) => {
                    if self.rpc.get_slot().await? > target {
                        continue;
                    }
                    let tip = cursor
                        .tip
                        .as_ref()
                        .context("root exists without a custom ring tip")?;
                    let tx = db.begin().await?;
                    let mut journal = storage::journal(&tx, tip.slot)
                        .await?
                        .context("custom ring journal gap")?;
                    let undo = RingStore::new(&tx, root.program)
                        .quarantine(root, reason)
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

impl Scope {
    fn covers(self, program: &[u8; 32]) -> bool {
        match self {
            Self::Every => true,
            Self::Ring(ring) => ring == *program,
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

pub(crate) struct Step<'a> {
    pub root: &'a RingRoot,
    pub transition: Registration,
    pub revision: u64,
}

#[derive(Debug, Error)]
pub(crate) enum ApplyError {
    /// Confined to one ring.
    #[error("{0}")]
    Fault(String),
    #[error(transparent)]
    Retry(#[from] anyhow::Error),
}

impl From<sea_orm::DbErr> for ApplyError {
    fn from(error: sea_orm::DbErr) -> Self {
        Self::Retry(error.into())
    }
}

impl From<RpcError> for ApplyError {
    fn from(error: RpcError) -> Self {
        Self::Retry(error.into())
    }
}

impl From<HasherError> for ApplyError {
    fn from(error: HasherError) -> Self {
        fault(format!("hashing failed ({error:?})"))
    }
}

impl From<PredecessorError> for ApplyError {
    fn from(error: PredecessorError) -> Self {
        match error {
            PredecessorError::NotAbsent => fault(error.to_string()),
            PredecessorError::Storage(error) => Self::Retry(error),
        }
    }
}

pub(crate) fn fault(reason: impl Into<String>) -> ApplyError {
    ApplyError::Fault(reason.into())
}

/// A missing or foreign ring account is the ring's fault.
fn ring_account(result: Result<Account, RpcError>) -> Result<Account, ApplyError> {
    match result {
        Err(RpcError::InvalidAccount(reason)) => Err(fault(reason)),
        other => Ok(other?),
    }
}

pub(crate) struct ChainRoot {
    pub root: [u8; 32],
    pub next_index: u64,
}

pub(crate) async fn load_root(rpc: &RpcClient, program: &Pubkey) -> Result<ChainRoot, ApplyError> {
    let (address, bump) = pda::key_registry_root(program);
    let account = ring_account(rpc.get_account(&address).await)?;
    if account.owner != *program {
        return Err(fault("key registry root has the wrong owner"));
    }
    let root = bytemuck::try_from_bytes::<KeyRegistryRoot>(&account.data)
        .map_err(|_| fault("key registry root has the wrong layout"))?;
    if root.discriminator != KEY_REGISTRY_ROOT || root.bump != bump {
        return Err(fault(
            "key registry root has the wrong discriminator or bump",
        ));
    }
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
    pub(crate) async fn policy(&mut self, program: &Pubkey) -> Result<PolicyConfig, ApplyError> {
        if let Some(policy) = self.policies.get(&program.to_bytes()) {
            return Ok(*policy);
        }
        let address = Pubkey::find_program_address(&[PolicyConfig::SEED], program).0;
        let account = ring_account(self.rpc.get_account(&address).await)?;
        if account.owner != *program {
            return Err(fault("policy config has the wrong owner"));
        }
        let policy = bytemuck::try_from_bytes::<PolicyConfig>(&account.data)
            .map_err(|_| fault("policy config has the wrong layout"))?;
        if policy.discriminator != POLICY_CONFIG {
            return Err(fault("policy config has the wrong discriminator"));
        }
        self.policies.insert(program.to_bytes(), *policy);
        Ok(*policy)
    }

    /// A leaf hashes under the id of the tree it lands in.
    pub(crate) async fn tree_id(&mut self, tree: &Pubkey) -> Result<u16, ApplyError> {
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

    /// Sibling invocations cannot supply a transition's SPP event.
    fn invocation(&self, position: usize) -> Result<Invocation<'a>, ApplyError> {
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
    cursor: &'a mut CustomRingCursor,
    block: &'a BlockInfo,
    scope: Scope,
    env: BlockEnv<'a>,
}

impl BlockWork<'_> {
    async fn run(mut self) -> Result<BlockUndo> {
        let mut undo = BlockUndo::default();
        for transaction in &self.block.transactions {
            if transaction.error.is_some() {
                continue;
            }
            self.index_spend_records(transaction, &mut undo.spend_records)
                .await?;
            self.index_key_registry(transaction, &mut undo.key_registry)
                .await?;
        }
        Ok(undo)
    }

    async fn index_key_registry(
        &mut self,
        transaction: &TransactionInfo,
        undo: &mut Vec<Undo>,
    ) -> Result<()> {
        let tx = self.tx;
        let invocations = Invocations::new(transaction, self.block.metadata.slot);
        for (position, instruction) in invocations.instructions() {
            let program = instruction.program_id.to_bytes();
            if !self.scope.covers(&program) {
                continue;
            }
            let initializes = match instruction.data.first() {
                Some(&tag::CREATE_KEY_REGISTRY_ROOT) => true,
                Some(&tag::REGISTER_KEY) => false,
                _ => continue,
            };
            if matches!(self.scope, Scope::Every)
                && storage::pending_ring(tx, &program).await?.is_some()
            {
                continue;
            }
            let store = RingStore::new(tx, program);
            if initializes {
                if let Some(address) = initialization(instruction) {
                    undo.extend(self.initialize(&store, address).await?);
                }
                continue;
            }
            let Some(root) = store.root().await? else {
                continue;
            };
            if root.fault.is_some() {
                continue;
            }
            let outcome = async {
                let invocation = invocations.invocation(position)?;
                self.advance(&root, invocation).await
            }
            .await;
            match outcome {
                Ok(Some(entry)) => undo.push(entry),
                Ok(None) => {}
                Err(ApplyError::Fault(reason)) => {
                    undo.push(store.quarantine(root, reason).await?);
                }
                Err(ApplyError::Retry(error)) => return Err(error),
            }
        }
        Ok(())
    }

    async fn index_spend_records(
        &mut self,
        transaction: &TransactionInfo,
        undo: &mut Vec<SpendUndo>,
    ) -> Result<()> {
        let tx = self.tx;
        let invocations = Invocations::new(transaction, self.block.metadata.slot);
        for (position, instruction) in invocations.instructions() {
            let program = instruction.program_id.to_bytes();
            let Some(tag) = instruction.data.first().copied() else {
                continue;
            };
            if !self.scope.covers(&program) || !spend_record::TAGS.contains(&tag) {
                continue;
            }
            if matches!(self.scope, Scope::Every)
                && storage::pending_ring(tx, &program).await?.is_some()
            {
                continue;
            }
            let store = SpendStore::new(tx, program);
            // A ring's first registration opens its records.
            let ring = match store.ring().await? {
                Some(ring) => ring,
                None if tag == custom_ring_interface::instruction::tag::REGISTER_SPEND => {
                    if !self.admit(program).await? {
                        continue;
                    }
                    undo.push(store.open().await?);
                    SpendRing { fault: None }
                }
                None => continue,
            };
            if ring.fault.is_some() {
                continue;
            }
            let outcome = async {
                let invocation = invocations.invocation(position)?;
                store.advance(&invocation, &mut self.env).await
            }
            .await;
            match outcome {
                Ok(Some(entry)) => undo.push(entry),
                Ok(None) => {}
                Err(ApplyError::Fault(reason)) => undo.push(store.quarantine(reason).await?),
                Err(ApplyError::Retry(error)) => return Err(error),
            }
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
        store: &RingStore<'_, DatabaseTransaction>,
        address: [u8; 32],
    ) -> Result<Option<Undo>> {
        let program = Pubkey::new_from_array(store.program());
        if !self.admit(store.program()).await? {
            return Ok(None);
        }
        if let Some(existing) = store.root().await? {
            return Ok(Some(
                store
                    .quarantine(existing, "initialized twice".into())
                    .await?,
            ));
        }
        let root = RingRoot {
            program: store.program(),
            address,
            root: EMPTY_ROOT,
            next_index: 1,
            fault: None,
        };
        match load_root(self.env.rpc, &program).await {
            Ok(_) => {}
            Err(ApplyError::Fault(reason)) => {
                let mut created = store.quarantine(root, reason).await?;
                created.before = None;
                return Ok(Some(created));
            }
            Err(ApplyError::Retry(error)) => return Err(error),
        }
        let sentinel = MemberKey::sentinel();
        let computed = store
            .write_leaves(
                &address,
                &[LeafWrite {
                    index: 0,
                    hash: sentinel.hash()?,
                }],
                self.cursor.advance_revision()?,
            )
            .await?;
        if computed != EMPTY_ROOT {
            bail!("key registry sentinel root mismatch");
        }
        store.save_root(&root).await?;
        store.save_member(&sentinel).await?;
        Ok(Some(Undo {
            program: root.program,
            before: None,
            members: vec![],
            leaves: vec![],
        }))
    }

    async fn advance(
        &mut self,
        root: &RingRoot,
        invocation: Invocation<'_>,
    ) -> Result<Option<Undo>, ApplyError> {
        let Some(transition) = key_registry::transition(&invocation)? else {
            return Ok(None);
        };
        let revision = self.cursor.advance_revision()?;
        let savepoint = self.tx.begin().await?;
        let applied = key_registry::apply(
            &RingStore::new(&savepoint, root.program),
            Step {
                root,
                transition,
                revision,
            },
        )
        .await;
        match applied {
            Ok(entry) => {
                savepoint.commit().await?;
                Ok(Some(entry))
            }
            Err(error) => {
                savepoint.rollback().await?;
                Err(error)
            }
        }
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

#[cfg(test)]
mod replay_tests;
#[cfg(test)]
mod tests;
