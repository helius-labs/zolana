use anyhow::{bail, Context, Result};
use sea_orm::{ConnectionTrait, DatabaseTransaction, QueryResult, Statement, Value};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use solana_pubkey::Pubkey;
use thiserror::Error;
use zolana_hasher::HasherError;
use zolana_indexer_api::Hash;

use super::key_registry::MemberKey;
use crate::{
    common::rings_tree::RingsTreeKind,
    ingester::{
        persist::{persist_leaf_nodes, LeafNode},
        typedefs::block_info::BlockMetadata,
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RingRoot {
    pub program: [u8; 32],
    pub address: [u8; 32],
    pub root: [u8; 32],
    pub next_index: u64,
    /// Cleared only by a rollback.
    pub fault: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ProjectionCursor {
    pub start_slot: u64,
    pub scanned_slot: u64,
    pub tip: Option<BlockMetadata>,
    /// Rollback writes must increase the storage sequence.
    pub revision: u64,
    ready: bool,
}

impl ProjectionCursor {
    pub fn new(start_slot: u64) -> Self {
        Self {
            start_slot,
            scanned_slot: start_slot,
            tip: None,
            revision: 0,
            ready: false,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn tip_slot(&self) -> u64 {
        self.tip.as_ref().map_or(self.start_slot, |tip| tip.slot)
    }

    pub async fn suspend<C: ConnectionTrait>(&mut self, conn: &C) -> Result<()> {
        self.ready = false;
        save_cursor(conn, self).await
    }

    pub async fn resume<C: ConnectionTrait>(&mut self, conn: &C) -> Result<()> {
        self.ready = true;
        save_cursor(conn, self).await
    }

    pub fn advance_revision(&mut self) -> Result<u64> {
        self.revision = self
            .revision
            .checked_add(1)
            .filter(|revision| i64::try_from(*revision).is_ok())
            .context("ring projection storage revision exhausted")?;
        Ok(self.revision)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LeafWrite {
    pub index: u64,
    pub hash: [u8; 32],
}

impl LeafWrite {
    pub fn of(key: &MemberKey) -> Result<Self, HasherError> {
        Ok(Self {
            index: key.index,
            hash: key.hash()?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct MemberRestore {
    pub member: [u8; 32],
    pub before: Option<MemberKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Undo {
    pub program: [u8; 32],
    pub before: Option<RingRoot>,
    pub members: Vec<MemberRestore>,
    pub leaves: Vec<LeafWrite>,
}

impl Undo {
    pub fn root(program: [u8; 32], before: Option<RingRoot>) -> Self {
        Self {
            program,
            before,
            members: vec![],
            leaves: vec![],
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct BlockUndo {
    pub key_registry: Vec<Undo>,
}

impl BlockUndo {
    pub fn extend(&mut self, other: Self) {
        self.key_registry.extend(other.key_registry);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct BlockJournal {
    pub metadata: BlockMetadata,
    pub previous_tip: Option<BlockMetadata>,
    pub undo: BlockUndo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PendingRing {
    pub program: [u8; 32],
    pub slot: u64,
    pub blockhash: Hash,
    /// Last historical block committed with the ring's projection changes.
    pub replayed_tip: Option<BlockMetadata>,
}

#[derive(Debug, Error)]
pub(crate) enum PredecessorError {
    #[error("member is not absent")]
    NotAbsent,
    #[error(transparent)]
    Storage(#[from] anyhow::Error),
}

const DELETE_MEMBER: &str = "DELETE FROM ring_key_registry_members WHERE program=$1 AND member=$2";

pub(crate) async fn save_pending<C: ConnectionTrait>(conn: &C, value: &PendingRing) -> Result<()> {
    let sql = "INSERT INTO ring_projection_pending(program,slot,state) VALUES($1,$2,$3) \
               ON CONFLICT(program) DO NOTHING";
    let values = vec![
        value.program.to_vec().into(),
        int(value.slot)?,
        json(value)?,
    ];
    exec(conn, sql, values).await
}

pub(crate) async fn pending<C: ConnectionTrait>(conn: &C) -> Result<Vec<PendingRing>> {
    read_all(
        conn,
        "SELECT state FROM ring_projection_pending ORDER BY slot",
    )
    .await
}

pub(crate) async fn pending_ring<C: ConnectionTrait>(
    conn: &C,
    program: &[u8; 32],
) -> Result<Option<PendingRing>> {
    let sql = "SELECT state FROM ring_projection_pending WHERE program=$1";
    read_json(conn, sql, vec![program.to_vec().into()]).await
}

pub(crate) async fn checkpoint_pending<C: ConnectionTrait>(
    conn: &C,
    pending: &PendingRing,
) -> Result<()> {
    let sql = "UPDATE ring_projection_pending SET state=$2 WHERE program=$1";
    let values = vec![pending.program.to_vec().into(), json(pending)?];
    exec(conn, sql, values).await
}

pub(crate) async fn delete_pending<C: ConnectionTrait>(conn: &C, program: &[u8; 32]) -> Result<()> {
    let sql = "DELETE FROM ring_projection_pending WHERE program=$1";
    exec(conn, sql, vec![program.to_vec().into()]).await
}

pub(crate) async fn cursor<C: ConnectionTrait>(conn: &C) -> Result<Option<ProjectionCursor>> {
    let sql = "SELECT state FROM ring_projection_cursor WHERE id=1";
    read_json(conn, sql, vec![]).await
}

pub(crate) async fn save_cursor<C: ConnectionTrait>(
    conn: &C,
    value: &ProjectionCursor,
) -> Result<()> {
    let sql = "INSERT INTO ring_projection_cursor(id,state) VALUES(1,$1) \
               ON CONFLICT(id) DO UPDATE SET state=excluded.state";
    exec(conn, sql, vec![json(value)?]).await
}

pub(crate) async fn journal<C: ConnectionTrait>(
    conn: &C,
    slot: u64,
) -> Result<Option<BlockJournal>> {
    let sql = "SELECT state FROM ring_projection_blocks WHERE slot=$1";
    read_json(conn, sql, vec![int(slot)?]).await
}

pub(crate) async fn save_journal<C: ConnectionTrait>(
    conn: &C,
    journal: &BlockJournal,
) -> Result<()> {
    let sql = "INSERT INTO ring_projection_blocks(slot,state) VALUES($1,$2) \
               ON CONFLICT(slot) DO UPDATE SET state=excluded.state";
    exec(conn, sql, vec![int(journal.metadata.slot)?, json(journal)?]).await
}

pub(crate) async fn prune_journal<C: ConnectionTrait>(conn: &C, below: u64) -> Result<()> {
    let sql = "DELETE FROM ring_projection_blocks WHERE slot<$1";
    exec(conn, sql, vec![int(below)?]).await
}

pub(crate) async fn roots<C: ConnectionTrait>(conn: &C) -> Result<Vec<RingRoot>> {
    read_all(
        conn,
        "SELECT state FROM ring_key_registry_roots ORDER BY program",
    )
    .await
}

pub(crate) async fn rollback(
    tx: &DatabaseTransaction,
    cursor: &mut ProjectionCursor,
) -> Result<()> {
    let tip = cursor
        .tip
        .as_ref()
        .context("cannot rewind before the ring projection start")?;
    let journal = journal(tx, tip.slot)
        .await?
        .context("ring projection journal gap")?;
    let slot = vec![int(journal.metadata.slot)?];
    let sql = "DELETE FROM ring_projection_pending WHERE slot=$1";
    exec(tx, sql, slot.clone()).await?;
    restore(tx, cursor, &journal.undo.key_registry).await?;
    // Partial replay must rewind with the block that advanced it.
    for mut candidate in pending(tx).await? {
        if candidate
            .replayed_tip
            .as_ref()
            .is_some_and(|tip| tip.slot == journal.metadata.slot)
        {
            candidate.replayed_tip = journal
                .previous_tip
                .clone()
                .filter(|tip| tip.slot >= candidate.slot);
            checkpoint_pending(tx, &candidate).await?;
        }
    }
    exec(tx, "DELETE FROM ring_projection_blocks WHERE slot=$1", slot).await?;
    cursor.tip = journal.previous_tip;
    cursor.scanned_slot = cursor.tip_slot();
    cursor.suspend(tx).await
}

async fn restore(
    tx: &DatabaseTransaction,
    cursor: &mut ProjectionCursor,
    undos: &[Undo],
) -> Result<()> {
    for undo in undos.iter().rev() {
        let store = Store::new(tx, undo.program);
        let Some(before) = &undo.before else {
            let created = store
                .root()
                .await?
                .context("created key registry missing on rollback")?;
            let sql = "DELETE FROM state_trees WHERE tree=$1 AND tree_kind=$2";
            let kind = i32::from(RingsTreeKind::KeyRegistry);
            exec(tx, sql, vec![created.address.to_vec().into(), kind.into()]).await?;
            let tables = ["ring_key_registry_members", "ring_key_registry_roots"];
            store.delete_rows(&tables).await?;
            continue;
        };
        if !undo.leaves.is_empty() {
            let revision = cursor.advance_revision()?;
            let root = store.write_leaves(&before.address, &undo.leaves, revision);
            if root.await? != before.root {
                bail!("key registry rollback root mismatch");
            }
        }
        store.save_root(before).await?;
        for restore in &undo.members {
            let member = vec![restore.member.to_vec().into()];
            match &restore.before {
                Some(leaf) => store.save_member(leaf).await?,
                None => store.exec(DELETE_MEMBER, member).await?,
            }
        }
    }
    Ok(())
}

/// One ring's rows across both projected families.
pub(crate) struct Store<'c, C> {
    pub(super) conn: &'c C,
    pub(super) program: [u8; 32],
}

impl<'c, C: ConnectionTrait> Store<'c, C> {
    pub fn new(conn: &'c C, program: [u8; 32]) -> Self {
        Self { conn, program }
    }

    /// Binds the program as `$1` ahead of `values`.
    pub(super) fn statement(&self, sql: &str, values: Vec<Value>) -> Statement {
        let program = std::iter::once(self.program.to_vec().into());
        statement(self.conn, sql, program.chain(values).collect())
    }

    pub(super) async fn exec(&self, sql: &str, values: Vec<Value>) -> Result<()> {
        self.conn.execute(self.statement(sql, values)).await?;
        Ok(())
    }

    async fn read<T: DeserializeOwned>(&self, sql: &str, values: Vec<Value>) -> Result<Option<T>> {
        let row = self.conn.query_one(self.statement(sql, values)).await?;
        row.as_ref().map(state).transpose()
    }

    pub(super) async fn delete_rows(&self, tables: &[&str]) -> Result<()> {
        for table in tables {
            self.exec(&format!("DELETE FROM {table} WHERE program=$1"), vec![])
                .await?;
        }
        Ok(())
    }

    pub async fn root(&self) -> Result<Option<RingRoot>> {
        let sql = "SELECT state FROM ring_key_registry_roots WHERE program=$1";
        self.read(sql, vec![]).await
    }

    pub async fn save_root(&self, root: &RingRoot) -> Result<()> {
        let sql = "INSERT INTO ring_key_registry_roots(program,state) VALUES($1,$2) \
                   ON CONFLICT(program) DO UPDATE SET state=excluded.state";
        self.exec(sql, vec![json(root)?]).await
    }

    pub async fn quarantine_root(&self, root: RingRoot, reason: String) -> Result<Undo> {
        let program = Pubkey::new_from_array(self.program);
        log::warn!("key registry of ring {program} quarantined ({reason})");
        let faulted = RingRoot {
            fault: Some(reason),
            ..root.clone()
        };
        self.save_root(&faulted).await?;
        Ok(Undo::root(root.program, Some(root)))
    }

    pub async fn member(&self, member: &[u8; 32]) -> Result<Option<MemberKey>> {
        let sql = "SELECT state FROM ring_key_registry_members WHERE program=$1 AND member=$2";
        self.read(sql, vec![member.to_vec().into()]).await
    }

    pub async fn predecessor(&self, member: &[u8; 32]) -> Result<MemberKey, PredecessorError> {
        let sql = "SELECT state FROM ring_key_registry_members WHERE program=$1 AND member<$2 \
                   ORDER BY member DESC LIMIT 1";
        let low: MemberKey = self
            .read(sql, vec![member.to_vec().into()])
            .await?
            .context("no covering predecessor")?;
        if !(low.member < *member && *member < low.next) {
            return Err(PredecessorError::NotAbsent);
        }
        Ok(low)
    }

    pub async fn save_member(&self, leaf: &MemberKey) -> Result<()> {
        let sql = "INSERT INTO ring_key_registry_members(program,member,leaf_index,state) \
                   VALUES($1,$2,$3,$4) ON CONFLICT(program,member) \
                   DO UPDATE SET leaf_index=excluded.leaf_index,state=excluded.state";
        let values = vec![leaf.member.to_vec().into(), int(leaf.index)?, json(leaf)?];
        self.exec(sql, values).await
    }
}

impl Store<'_, DatabaseTransaction> {
    pub async fn write_leaves(
        &self,
        tree: &[u8; 32],
        leaves: &[LeafWrite],
        revision: u64,
    ) -> Result<[u8; 32]> {
        let kind = RingsTreeKind::KeyRegistry;
        let leaves = leaves
            .iter()
            .map(|leaf| LeafNode {
                tree: tree.to_vec(),
                tree_kind: kind,
                leaf_index: leaf.index,
                hash: Hash(leaf.hash),
                seq: Some(revision),
            })
            .collect();
        persist_leaf_nodes(self.conn, leaves, kind.tree_height() + 1).await?;
        let sql = "SELECT hash FROM state_trees WHERE tree=$1 AND tree_kind=$2 AND node_idx=1";
        let values = vec![tree.to_vec().into(), i32::from(kind).into()];
        let row = self
            .conn
            .query_one(statement(self.conn, sql, values))
            .await?;
        let row = row.context("key registry root missing")?;
        let hash: Vec<u8> = row.try_get("", "hash")?;
        hash.try_into()
            .map_err(|_| anyhow::anyhow!("invalid key registry root length"))
    }
}

fn statement<C: ConnectionTrait>(conn: &C, sql: &str, values: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(conn.get_database_backend(), sql, values)
}

async fn exec<C: ConnectionTrait>(conn: &C, sql: &str, values: Vec<Value>) -> Result<()> {
    conn.execute(statement(conn, sql, values)).await?;
    Ok(())
}

fn json<T: Serialize>(value: &T) -> Result<Value> {
    Ok(serde_json::to_string(value)?.into())
}

pub(super) fn int(value: u64) -> Result<Value> {
    Ok(i64::try_from(value)?.into())
}

async fn read_json<T: DeserializeOwned, C: ConnectionTrait>(
    conn: &C,
    sql: &str,
    values: Vec<Value>,
) -> Result<Option<T>> {
    let row = conn.query_one(statement(conn, sql, values)).await?;
    row.as_ref().map(state).transpose()
}

async fn read_all<T: DeserializeOwned, C: ConnectionTrait>(conn: &C, sql: &str) -> Result<Vec<T>> {
    let rows = conn.query_all(statement(conn, sql, vec![])).await?;
    rows.iter().map(state).collect()
}

fn state<T: DeserializeOwned>(row: &QueryResult) -> Result<T> {
    Ok(serde_json::from_str(&row.try_get::<String>("", "state")?)?)
}
