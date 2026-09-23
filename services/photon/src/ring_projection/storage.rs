use std::marker::PhantomData;

use anyhow::{bail, Context, Result};
use sea_orm::{ConnectionTrait, DatabaseTransaction, Statement, Value};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use solana_pubkey::Pubkey;
use thiserror::Error;
use zolana_indexer_api::Hash;

use super::{key_registry::MemberKey, spend_record::SpendUndo, Leaf, Projection};
use crate::ingester::{
    persist::{persist_leaf_nodes, LeafNode},
    typedefs::block_info::BlockMetadata,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct MemberRestore<L> {
    pub member: [u8; 32],
    pub before: Option<L>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Undo<L> {
    pub program: [u8; 32],
    pub before: Option<RingRoot>,
    pub members: Vec<MemberRestore<L>>,
    pub leaves: Vec<LeafWrite>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct BlockUndo {
    pub spend_records: Vec<SpendUndo>,
    pub key_registry: Vec<Undo<MemberKey>>,
}

impl BlockUndo {
    pub fn extend(&mut self, other: Self) {
        self.spend_records.extend(other.spend_records);
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
    #[serde(default)]
    pub replayed_tip: Option<BlockMetadata>,
}

#[derive(Debug, Error)]
pub(crate) enum PredecessorError {
    #[error("member is not absent")]
    NotAbsent,
    #[error(transparent)]
    Storage(#[from] anyhow::Error),
}

const CURSOR_TABLE: &str = "ring_projection_cursor";
const JOURNAL_TABLE: &str = "ring_projection_blocks";
const PENDING_TABLE: &str = "ring_projection_pending";

pub(crate) async fn save_pending<C: ConnectionTrait>(conn: &C, value: &PendingRing) -> Result<()> {
    conn.execute(statement(
        conn,
        &format!(
            "INSERT INTO {PENDING_TABLE}(program,slot,state) VALUES($1,$2,$3) \
             ON CONFLICT(program) DO NOTHING"
        ),
        vec![
            value.program.to_vec().into(),
            i64::try_from(value.slot)?.into(),
            serde_json::to_string(value)?.into(),
        ],
    ))
    .await?;
    Ok(())
}

pub(crate) async fn pending<C: ConnectionTrait>(conn: &C) -> Result<Vec<PendingRing>> {
    read_all(
        conn,
        &format!("SELECT state FROM {PENDING_TABLE} ORDER BY slot"),
        vec![],
    )
    .await
}

pub(crate) async fn pending_ring<C: ConnectionTrait>(
    conn: &C,
    program: &[u8; 32],
) -> Result<Option<PendingRing>> {
    read_json(
        conn,
        &format!("SELECT state FROM {PENDING_TABLE} WHERE program=$1"),
        vec![program.to_vec().into()],
    )
    .await
}

pub(crate) async fn checkpoint_pending<C: ConnectionTrait>(
    conn: &C,
    pending: &PendingRing,
) -> Result<()> {
    conn.execute(statement(
        conn,
        &format!("UPDATE {PENDING_TABLE} SET state=$2 WHERE program=$1"),
        vec![
            pending.program.to_vec().into(),
            serde_json::to_string(pending)?.into(),
        ],
    ))
    .await?;
    Ok(())
}

pub(crate) async fn delete_pending<C: ConnectionTrait>(conn: &C, program: &[u8; 32]) -> Result<()> {
    conn.execute(statement(
        conn,
        &format!("DELETE FROM {PENDING_TABLE} WHERE program=$1"),
        vec![program.to_vec().into()],
    ))
    .await?;
    Ok(())
}

pub(crate) async fn cursor<C: ConnectionTrait>(conn: &C) -> Result<Option<ProjectionCursor>> {
    read_json(
        conn,
        &format!("SELECT state FROM {CURSOR_TABLE} WHERE id=1"),
        vec![],
    )
    .await
}

pub(crate) async fn save_cursor<C: ConnectionTrait>(
    conn: &C,
    value: &ProjectionCursor,
) -> Result<()> {
    conn.execute(statement(
        conn,
        &format!(
            "INSERT INTO {CURSOR_TABLE}(id,state) VALUES(1,$1) \
             ON CONFLICT(id) DO UPDATE SET state=excluded.state"
        ),
        vec![serde_json::to_string(value)?.into()],
    ))
    .await?;
    Ok(())
}

pub(crate) async fn journal<C: ConnectionTrait>(
    conn: &C,
    slot: u64,
) -> Result<Option<BlockJournal>> {
    read_json(
        conn,
        &format!("SELECT state FROM {JOURNAL_TABLE} WHERE slot=$1"),
        vec![i64::try_from(slot)?.into()],
    )
    .await
}

pub(crate) async fn save_journal<C: ConnectionTrait>(
    conn: &C,
    journal: &BlockJournal,
) -> Result<()> {
    conn.execute(statement(
        conn,
        &format!(
            "INSERT INTO {JOURNAL_TABLE}(slot,state) VALUES($1,$2) \
             ON CONFLICT(slot) DO UPDATE SET state=excluded.state"
        ),
        vec![
            i64::try_from(journal.metadata.slot)?.into(),
            serde_json::to_string(journal)?.into(),
        ],
    ))
    .await?;
    Ok(())
}

pub(crate) async fn prune_journal<C: ConnectionTrait>(conn: &C, below: u64) -> Result<()> {
    conn.execute(statement(
        conn,
        &format!("DELETE FROM {JOURNAL_TABLE} WHERE slot<$1"),
        vec![i64::try_from(below)?.into()],
    ))
    .await?;
    Ok(())
}

async fn delete_journal<C: ConnectionTrait>(conn: &C, slot: u64) -> Result<()> {
    conn.execute(statement(
        conn,
        &format!("DELETE FROM {JOURNAL_TABLE} WHERE slot=$1"),
        vec![i64::try_from(slot)?.into()],
    ))
    .await?;
    Ok(())
}

pub(crate) async fn roots<P: Projection, C: ConnectionTrait>(conn: &C) -> Result<Vec<RingRoot>> {
    read_all(
        conn,
        &format!(
            "SELECT state FROM {roots} ORDER BY program",
            roots = table::<P>("roots")
        ),
        vec![],
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
    tx.execute(statement(
        tx,
        &format!("DELETE FROM {PENDING_TABLE} WHERE slot=$1"),
        vec![i64::try_from(journal.metadata.slot)?.into()],
    ))
    .await?;
    super::spend_record::restore(tx, &journal.undo.spend_records).await?;
    restore::<super::key_registry::KeyRegistry>(tx, cursor, &journal.undo.key_registry).await?;
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
    delete_journal(tx, journal.metadata.slot).await?;
    cursor.tip = journal.previous_tip;
    cursor.scanned_slot = cursor
        .tip
        .as_ref()
        .map_or(cursor.start_slot, |tip| tip.slot);
    cursor.suspend(tx).await
}

async fn restore<P: Projection>(
    tx: &DatabaseTransaction,
    cursor: &mut ProjectionCursor,
    undos: &[Undo<P::Leaf>],
) -> Result<()> {
    for undo in undos.iter().rev() {
        let store = RingStore::<_, P>::new(tx, undo.program);
        match &undo.before {
            Some(before) => {
                if !undo.leaves.is_empty() {
                    let root = store
                        .write_leaves(&before.address, &undo.leaves, cursor.advance_revision()?)
                        .await?;
                    if root != before.root {
                        bail!("{} rollback root mismatch", P::KIND);
                    }
                }
                store.save_root(before).await?;
                for restore in &undo.members {
                    match &restore.before {
                        Some(leaf) => store.save_member(leaf).await?,
                        None => store.delete_member(&restore.member).await?,
                    }
                }
            }
            None => {
                let created = store
                    .root()
                    .await?
                    .with_context(|| format!("created {} missing on rollback", P::KIND))?;
                store.delete_tree(&created.address).await?;
                store.delete_members().await?;
                store.delete_root().await?;
            }
        }
    }
    Ok(())
}

pub(crate) struct RingStore<'c, C, P> {
    conn: &'c C,
    program: [u8; 32],
    projection: PhantomData<P>,
}

impl<'c, C: ConnectionTrait, P: Projection> RingStore<'c, C, P> {
    pub fn new(conn: &'c C, program: [u8; 32]) -> Self {
        Self {
            conn,
            program,
            projection: PhantomData,
        }
    }

    pub fn conn(&self) -> &'c C {
        self.conn
    }

    pub fn program(&self) -> [u8; 32] {
        self.program
    }

    pub async fn root(&self) -> Result<Option<RingRoot>> {
        read_json(
            self.conn,
            &format!(
                "SELECT state FROM {roots} WHERE program=$1",
                roots = table::<P>("roots")
            ),
            vec![self.program.to_vec().into()],
        )
        .await
    }

    pub async fn save_root(&self, root: &RingRoot) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                &format!(
                    "INSERT INTO {roots}(program,state) VALUES($1,$2) \
                     ON CONFLICT(program) DO UPDATE SET state=excluded.state",
                    roots = table::<P>("roots")
                ),
                vec![
                    self.program.to_vec().into(),
                    serde_json::to_string(root)?.into(),
                ],
            ))
            .await?;
        Ok(())
    }

    pub async fn quarantine(&self, root: RingRoot, reason: String) -> Result<Undo<P::Leaf>> {
        log::warn!(
            "{} of ring {} quarantined ({reason})",
            P::KIND,
            Pubkey::new_from_array(self.program)
        );
        self.save_root(&RingRoot {
            fault: Some(reason),
            ..root.clone()
        })
        .await?;
        Ok(Undo {
            program: root.program,
            before: Some(root),
            members: vec![],
            leaves: vec![],
        })
    }

    pub async fn delete_root(&self) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                &format!(
                    "DELETE FROM {roots} WHERE program=$1",
                    roots = table::<P>("roots")
                ),
                vec![self.program.to_vec().into()],
            ))
            .await?;
        Ok(())
    }

    pub async fn member(&self, member: &[u8; 32]) -> Result<Option<P::Leaf>> {
        read_json(
            self.conn,
            &format!(
                "SELECT state FROM {members} WHERE program=$1 AND member=$2",
                members = table::<P>("members")
            ),
            vec![self.program.to_vec().into(), member.to_vec().into()],
        )
        .await
    }

    pub async fn predecessor(&self, member: &[u8; 32]) -> Result<P::Leaf, PredecessorError> {
        let low: P::Leaf = read_json(
            self.conn,
            &format!(
                "SELECT state FROM {members} WHERE program=$1 AND member<$2 \
                 ORDER BY member DESC LIMIT 1",
                members = table::<P>("members")
            ),
            vec![self.program.to_vec().into(), member.to_vec().into()],
        )
        .await?
        .context("no covering predecessor")?;
        if !(low.member() < *member && *member < low.next()) {
            return Err(PredecessorError::NotAbsent);
        }
        Ok(low)
    }

    pub async fn save_member(&self, leaf: &P::Leaf) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                &format!(
                    "INSERT INTO {members}(program,member,leaf_index,state) VALUES($1,$2,$3,$4) \
                     ON CONFLICT(program,member) \
                     DO UPDATE SET leaf_index=excluded.leaf_index,state=excluded.state",
                    members = table::<P>("members")
                ),
                vec![
                    self.program.to_vec().into(),
                    leaf.member().to_vec().into(),
                    i64::try_from(leaf.index())?.into(),
                    serde_json::to_string(leaf)?.into(),
                ],
            ))
            .await?;
        Ok(())
    }

    pub async fn delete_member(&self, member: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                &format!(
                    "DELETE FROM {members} WHERE program=$1 AND member=$2",
                    members = table::<P>("members")
                ),
                vec![self.program.to_vec().into(), member.to_vec().into()],
            ))
            .await?;
        Ok(())
    }

    pub async fn delete_members(&self) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                &format!(
                    "DELETE FROM {members} WHERE program=$1",
                    members = table::<P>("members")
                ),
                vec![self.program.to_vec().into()],
            ))
            .await?;
        Ok(())
    }

    pub async fn delete_tree(&self, tree: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                "DELETE FROM state_trees WHERE tree=$1 AND tree_kind=$2",
                vec![tree.to_vec().into(), i32::from(P::KIND.tree()).into()],
            ))
            .await?;
        Ok(())
    }
}

impl<P: Projection> RingStore<'_, DatabaseTransaction, P> {
    pub async fn write_leaves(
        &self,
        tree: &[u8; 32],
        leaves: &[LeafWrite],
        revision: u64,
    ) -> Result<[u8; 32]> {
        let kind = P::KIND.tree();
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
        let row = self
            .conn
            .query_one(statement(
                self.conn,
                "SELECT hash FROM state_trees WHERE tree=$1 AND tree_kind=$2 AND node_idx=1",
                vec![tree.to_vec().into(), i32::from(kind).into()],
            ))
            .await?
            .with_context(|| format!("{} root missing", P::KIND))?;
        let hash: Vec<u8> = row.try_get("", "hash")?;
        hash.try_into()
            .map_err(|_| anyhow::anyhow!("invalid {} root length", P::KIND))
    }
}

fn table<P: Projection>(suffix: &str) -> String {
    format!("{}_{suffix}", P::KIND.table())
}

pub(super) fn statement<C: ConnectionTrait>(conn: &C, sql: &str, values: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(conn.get_database_backend(), sql, values)
}

async fn read_json<T: DeserializeOwned, C: ConnectionTrait>(
    conn: &C,
    sql: &str,
    values: Vec<Value>,
) -> Result<Option<T>> {
    conn.query_one(statement(conn, sql, values))
        .await?
        .map(|row| {
            let state: String = row.try_get("", "state")?;
            Ok(serde_json::from_str(&state)?)
        })
        .transpose()
}

async fn read_all<T: DeserializeOwned, C: ConnectionTrait>(
    conn: &C,
    sql: &str,
    values: Vec<Value>,
) -> Result<Vec<T>> {
    conn.query_all(statement(conn, sql, values))
        .await?
        .into_iter()
        .map(|row| {
            let state: String = row.try_get("", "state")?;
            Ok(serde_json::from_str(&state)?)
        })
        .collect()
}
