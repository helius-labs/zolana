use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use anyhow::{Context, Result};
use custom_ring_interface::{MemberRegistry, QueueEntry, RecordQueue, ROOT_HISTORY};
use sea_orm::{ConnectionTrait, DatabaseTransaction, QueryResult, Statement, Value};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use solana_pubkey::Pubkey;
use zolana_indexer_api::Hash;
use zolana_ring_indexer::{
    records::{QueuedWrite, RegistryAccounts, SealedKey},
    tree::{IndexedRecord, MemberRecord, NodePosition},
};

use crate::{ingester::typedefs::block_info::BlockMetadata, metric};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RegistryState {
    pub program: [u8; 32],
    pub registry_address: [u8; 32],
    pub queue_address: [u8; 32],
    /// The record fields, the policy fields stay zero.
    #[serde(with = "account_image")]
    pub registry: Box<MemberRegistry>,
    #[serde(with = "account_image")]
    pub queue: Box<RecordQueue>,
    /// Cleared only by a rollback.
    pub fault: Option<String>,
}

impl RegistryState {
    pub fn accounts(&self) -> RegistryAccounts {
        RegistryAccounts {
            registry: self.registry_address.into(),
            queue: self.queue_address.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HistoryRoot {
    pub root: [u8; 32],
    /// Every row carries the position that wrote it, a read at a root takes the newest at or below.
    pub applied: u64,
    pub next_index: u64,
    pub slot: u64,
    pub history_index: u8,
}

impl HistoryRoot {
    pub fn newest(state: &RegistryState) -> Self {
        let index = state.registry.history_cursor;
        let entry = state.registry.history[usize::from(index)];
        Self {
            root: entry.root,
            applied: entry.applied(),
            next_index: state.registry.next_index().into(),
            slot: entry.slot(),
            history_index: index,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoredRecord {
    pub record: IndexedRecord,
    pub seal: Option<SealedKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoredEntry {
    pub position: u64,
    pub write: QueuedWrite,
    pub slot: u64,
    /// `chain(position)`.
    pub chain: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CustomRingCursor {
    pub start_slot: u64,
    pub scanned_slot: u64,
    pub tip: Option<BlockMetadata>,
    ready: bool,
}

impl CustomRingCursor {
    pub fn new(start_slot: u64) -> Self {
        Self {
            start_slot,
            scanned_slot: start_slot,
            tip: None,
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
}

/// Rows of one ring newer than `before`, `None` for a registry the block created.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Undo {
    pub program: [u8; 32],
    pub before: Option<RegistryState>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct BlockUndo {
    pub records: Vec<Undo>,
}

impl BlockUndo {
    pub fn extend(&mut self, other: Self) {
        self.records.extend(other.records);
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
    /// Last historical block committed with the ring's index changes.
    pub replayed_tip: Option<BlockMetadata>,
}

/// Every table a ring's records project into, keyed by `program` first.
const RECORD_TABLES: [&str; 5] = [
    "ring_registries",
    "ring_registry_roots",
    "ring_records",
    "ring_record_nodes",
    "ring_record_queue",
];
const RECORD_COLUMNS: &str = "leaf_index, member, next_member, lists, escrow_key, seal";

pub(crate) async fn save_pending<C: ConnectionTrait>(conn: &C, value: &PendingRing) -> Result<()> {
    let sql = "INSERT INTO custom_ring_pending(program,slot,state) VALUES($1,$2,$3) \
               ON CONFLICT(program) DO NOTHING";
    let values = vec![bytes(&value.program), int(value.slot)?, json(value)?];
    exec(conn, sql, values).await
}

pub(crate) async fn pending<C: ConnectionTrait>(conn: &C) -> Result<Vec<PendingRing>> {
    read_all(conn, "SELECT state FROM custom_ring_pending ORDER BY slot").await
}

pub(crate) async fn pending_programs<C: ConnectionTrait>(conn: &C) -> Result<BTreeSet<[u8; 32]>> {
    programs(conn, "SELECT program FROM custom_ring_pending").await
}

pub(crate) async fn pending_ring<C: ConnectionTrait>(
    conn: &C,
    program: &[u8; 32],
) -> Result<Option<PendingRing>> {
    let sql = "SELECT state FROM custom_ring_pending WHERE program=$1";
    read_json(conn, sql, vec![bytes(program)]).await
}

pub(crate) async fn checkpoint_pending<C: ConnectionTrait>(
    conn: &C,
    pending: &PendingRing,
) -> Result<()> {
    let sql = "UPDATE custom_ring_pending SET state=$2 WHERE program=$1";
    let values = vec![bytes(&pending.program), json(pending)?];
    exec(conn, sql, values).await
}

pub(crate) async fn delete_pending<C: ConnectionTrait>(conn: &C, program: &[u8; 32]) -> Result<()> {
    let sql = "DELETE FROM custom_ring_pending WHERE program=$1";
    exec(conn, sql, vec![bytes(program)]).await
}

pub(crate) async fn cursor<C: ConnectionTrait>(conn: &C) -> Result<Option<CustomRingCursor>> {
    let sql = "SELECT state FROM custom_ring_cursor WHERE id=1";
    read_json(conn, sql, vec![]).await
}

pub(crate) async fn save_cursor<C: ConnectionTrait>(
    conn: &C,
    value: &CustomRingCursor,
) -> Result<()> {
    let sql = "INSERT INTO custom_ring_cursor(id,state) VALUES(1,$1) \
               ON CONFLICT(id) DO UPDATE SET state=excluded.state";
    exec(conn, sql, vec![json(value)?]).await
}

pub(crate) async fn journal<C: ConnectionTrait>(
    conn: &C,
    slot: u64,
) -> Result<Option<BlockJournal>> {
    let sql = "SELECT state FROM custom_ring_blocks WHERE slot=$1";
    read_json(conn, sql, vec![int(slot)?]).await
}

pub(crate) async fn save_journal<C: ConnectionTrait>(
    conn: &C,
    journal: &BlockJournal,
) -> Result<()> {
    let sql = "INSERT INTO custom_ring_blocks(slot,state) VALUES($1,$2) \
               ON CONFLICT(slot) DO UPDATE SET state=excluded.state";
    exec(conn, sql, vec![int(journal.metadata.slot)?, json(journal)?]).await
}

/// Blocks below `below` never roll back.
pub(crate) async fn prune<C: ConnectionTrait>(conn: &C, below: u64) -> Result<()> {
    exec(
        conn,
        "DELETE FROM custom_ring_blocks WHERE slot<$1",
        vec![int(below)?],
    )
    .await?;
    for program in registry_programs(conn).await? {
        RegistryStore::new(conn, program)
            .prune_history(below)
            .await?;
    }
    Ok(())
}

pub(crate) async fn registries<C: ConnectionTrait>(conn: &C) -> Result<Vec<RegistryState>> {
    read_all(conn, "SELECT state FROM ring_registries ORDER BY program").await
}

pub(crate) async fn registry_programs<C: ConnectionTrait>(conn: &C) -> Result<BTreeSet<[u8; 32]>> {
    programs(conn, "SELECT program FROM ring_registries").await
}

pub(crate) async fn rollback(
    tx: &DatabaseTransaction,
    cursor: &mut CustomRingCursor,
) -> Result<()> {
    let tip = cursor
        .tip
        .as_ref()
        .context("cannot rewind before the custom ring start")?;
    let journal = journal(tx, tip.slot)
        .await?
        .context("custom ring index journal gap")?;
    let slot = vec![int(journal.metadata.slot)?];
    exec(
        tx,
        "DELETE FROM custom_ring_pending WHERE slot=$1",
        slot.clone(),
    )
    .await?;
    for undo in journal.undo.records.iter().rev() {
        RegistryStore::new(tx, undo.program).restore(undo).await?;
    }
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
    exec(tx, "DELETE FROM custom_ring_blocks WHERE slot=$1", slot).await?;
    cursor.tip = journal.previous_tip;
    cursor.scanned_slot = cursor.tip_slot();
    cursor.suspend(tx).await
}

/// One ring's projected registry, every statement binds the program as `$1`.
pub(crate) struct RegistryStore<'c, C> {
    conn: &'c C,
    pub(super) program: [u8; 32],
}

impl<'c, C: ConnectionTrait> RegistryStore<'c, C> {
    pub fn new(conn: &'c C, program: [u8; 32]) -> Self {
        Self { conn, program }
    }

    pub async fn state(&self) -> Result<Option<RegistryState>> {
        let sql = "SELECT state FROM ring_registries WHERE program=$1";
        let row = self.query_one(sql, vec![]).await?;
        row.as_ref().map(stored_state).transpose()
    }

    pub async fn save_state(&self, value: &RegistryState) -> Result<()> {
        let sql = "INSERT INTO ring_registries(program,state) VALUES($1,$2) \
                   ON CONFLICT(program) DO UPDATE SET state=excluded.state";
        self.exec(sql, vec![json(value)?]).await
    }

    /// Stops the ring's projection, a rollback of the block resumes it.
    pub async fn quarantine(&self, before: RegistryState, reason: String) -> Result<Undo> {
        log::error!(
            "custom ring {} stopped projecting its member registry ({reason})",
            Pubkey::new_from_array(self.program)
        );
        metric! {
            cadence_macros::statsd_count!("custom_ring_registry_stopped", 1);
        }
        self.save_state(&RegistryState {
            fault: Some(reason),
            ..before.clone()
        })
        .await?;
        Ok(self.undo(Some(before)))
    }

    pub fn undo(&self, before: Option<RegistryState>) -> Undo {
        Undo {
            program: self.program,
            before,
        }
    }

    pub async fn root(&self, applied: u64) -> Result<Option<HistoryRoot>> {
        let sql = "SELECT root, applied, next_index, slot, history_index FROM ring_registry_roots \
                   WHERE program=$1 AND applied=$2";
        let row = self.query_one(sql, vec![int(applied)?]).await?;
        row.as_ref().map(history_root).transpose()
    }

    pub async fn save_root(&self, entry: &HistoryRoot) -> Result<()> {
        let sql =
            "INSERT INTO ring_registry_roots(program,applied,root,next_index,slot,history_index) \
                   VALUES($1,$2,$3,$4,$5,$6)";
        let values = vec![
            int(entry.applied)?,
            bytes(&entry.root),
            int(entry.next_index)?,
            int(entry.slot)?,
            int(entry.history_index.into())?,
        ];
        self.exec(sql, values).await
    }

    pub async fn record(&self, member: &[u8; 32], applied: u64) -> Result<Option<StoredRecord>> {
        let sql = format!(
            "SELECT {RECORD_COLUMNS} FROM ring_records WHERE program=$1 AND member=$2 \
             AND applied<=$3 ORDER BY applied DESC LIMIT 1"
        );
        let values = vec![bytes(member), int(applied)?];
        let row = self.query_one(&sql, values).await?;
        row.as_ref().map(stored_record).transpose()
    }

    pub async fn low_record(&self, member: &[u8; 32], applied: u64) -> Result<StoredRecord> {
        let sql = format!(
            "SELECT {RECORD_COLUMNS} FROM ring_records WHERE program=$1 AND member<$2 \
             AND applied<=$3 ORDER BY member DESC, applied DESC LIMIT 1"
        );
        let values = vec![bytes(member), int(applied)?];
        let row = self.query_one(&sql, values).await?;
        stored_record(&row.context("member registry has no sentinel")?)
    }

    /// A gap shortens the result.
    pub async fn records_by_index(
        &self,
        leaves: Range<u64>,
        applied: u64,
    ) -> Result<Vec<StoredRecord>> {
        let sql = format!(
            "SELECT {RECORD_COLUMNS} FROM ring_records AS r WHERE program=$1 \
             AND leaf_index>=$2 AND leaf_index<$3 AND applied=(SELECT MAX(applied) \
             FROM ring_records AS m WHERE m.program=r.program AND m.leaf_index=r.leaf_index \
             AND m.applied<=$4) ORDER BY leaf_index"
        );
        let values = vec![int(leaves.start)?, int(leaves.end)?, int(applied)?];
        let rows = self.query_all(&sql, values).await?;
        rows.iter().map(stored_record).collect()
    }

    pub async fn save_records(&self, records: &[StoredRecord], applied: u64) -> Result<()> {
        for stored in records {
            let record = &stored.record.record;
            let sql = "INSERT INTO ring_records(program,leaf_index,applied,member,next_member,\
                       lists,escrow_key,seal) VALUES($1,$2,$3,$4,$5,$6,$7,$8)";
            let values = vec![
                int(stored.record.index)?,
                int(applied)?,
                bytes(&record.member),
                bytes(&record.next),
                int(record.lists)?,
                bytes(&record.escrow_key),
                seal_value(stored.seal.as_ref())?,
            ];
            self.exec(sql, values).await?;
        }
        Ok(())
    }

    pub async fn nodes(
        &self,
        keys: &BTreeSet<NodePosition>,
        applied: u64,
    ) -> Result<BTreeMap<NodePosition, [u8; 32]>> {
        let mut by_level = BTreeMap::<usize, Vec<u64>>::new();
        for key in keys {
            by_level.entry(key.level).or_default().push(key.position);
        }
        let mut values = vec![int(applied)?];
        let mut levels = Vec::new();
        for (level, positions) in by_level {
            values.push(int(u64::try_from(level)?)?);
            let level_param = values.len() + 1;
            let mut params = Vec::with_capacity(positions.len());
            for position in positions {
                values.push(int(position)?);
                params.push(format!("${}", values.len() + 1));
            }
            levels.push(format!(
                "(level=${level_param} AND position IN ({}))",
                params.join(",")
            ));
        }
        if levels.is_empty() {
            return Ok(BTreeMap::new());
        }
        let sql = format!(
            "SELECT level, position, hash FROM ring_record_nodes AS n WHERE program=$1 \
             AND applied=(SELECT MAX(applied) FROM ring_record_nodes AS m \
             WHERE m.program=n.program AND m.level=n.level AND m.position=n.position \
             AND m.applied<=$2) AND ({})",
            levels.join(" OR ")
        );
        let rows = self.query_all(&sql, values).await?;
        rows.iter()
            .map(|row| {
                let at = NodePosition {
                    level: usize::try_from(uint(row, "level")?)?,
                    position: uint(row, "position")?,
                };
                Ok((at, field(row, "hash")?))
            })
            .collect()
    }

    pub async fn save_nodes(
        &self,
        nodes: &BTreeMap<NodePosition, [u8; 32]>,
        applied: u64,
    ) -> Result<()> {
        for (at, hash) in nodes {
            let sql = "INSERT INTO ring_record_nodes(program,level,position,applied,hash) \
                       VALUES($1,$2,$3,$4,$5)";
            let values = vec![
                int(u64::try_from(at.level)?)?,
                int(at.position)?,
                int(applied)?,
                bytes(hash),
            ];
            self.exec(sql, values).await?;
        }
        Ok(())
    }

    /// Fails on a gap in `positions`.
    pub async fn entries(&self, positions: Range<u64>) -> Result<Vec<StoredEntry>> {
        let sql = "SELECT position, member, mask, value, escrow_key, slot, chain, seal \
                   FROM ring_record_queue WHERE program=$1 AND position>=$2 AND position<$3 \
                   ORDER BY position";
        let values = vec![int(positions.start)?, int(positions.end)?];
        let rows = self.query_all(sql, values).await?;
        let entries = rows.iter().map(stored_entry).collect::<Result<Vec<_>>>()?;
        let contiguous = entries.iter().map(|entry| entry.position).eq(positions);
        anyhow::ensure!(contiguous, "record queue projection has a gap");
        Ok(entries)
    }

    pub async fn save_entry(&self, entry: &StoredEntry) -> Result<()> {
        let sql = "INSERT INTO ring_record_queue(program,position,member,mask,value,escrow_key,\
                   slot,chain,seal) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)";
        let QueueEntry {
            member,
            mask,
            value,
            escrow_key,
        } = entry.write.entry;
        let values = vec![
            int(entry.position)?,
            bytes(&member),
            int(mask)?,
            int(value)?,
            bytes(&escrow_key),
            int(entry.slot)?,
            bytes(&entry.chain),
            seal_value(entry.write.seal.as_ref())?,
        ];
        self.exec(sql, values).await
    }

    async fn restore(&self, undo: &Undo) -> Result<()> {
        let Some(before) = &undo.before else {
            for table in RECORD_TABLES {
                self.exec(&format!("DELETE FROM {table} WHERE program=$1"), vec![])
                    .await?;
            }
            return Ok(());
        };
        let applied = vec![int(before.queue.head())?];
        for table in ["ring_registry_roots", "ring_records", "ring_record_nodes"] {
            let sql = format!("DELETE FROM {table} WHERE program=$1 AND applied>$2");
            self.exec(&sql, applied.clone()).await?;
        }
        let sql = "DELETE FROM ring_record_queue WHERE program=$1 AND position>=$2";
        self.exec(sql, vec![int(before.queue.tail())?]).await?;
        self.save_state(before).await
    }

    /// Keeps what the history after the deepest possible rollback still reads.
    async fn prune_history(&self, below: u64) -> Result<()> {
        let sql = "SELECT pruned FROM ring_registries WHERE program=$1";
        let row = self.query_one(sql, vec![]).await?;
        let pruned = uint(&row.context("pruned ring has no registry row")?, "pruned")?;
        let sql = format!(
            "SELECT applied FROM ring_registry_roots WHERE program=$1 AND slot<$2 \
             ORDER BY applied DESC LIMIT {ROOT_HISTORY}"
        );
        let rows = self.query_all(&sql, vec![int(below)?]).await?;
        let finals = rows
            .iter()
            .map(|row| uint(row, "applied"))
            .collect::<Result<Vec<_>>>()?;
        let (Some(&final_head), Some(&oldest)) = (finals.first(), finals.get(ROOT_HISTORY - 1))
        else {
            return Ok(());
        };
        if oldest <= pruned {
            return Ok(());
        }
        let sql = "DELETE FROM ring_registry_roots WHERE program=$1 AND applied<$2";
        self.exec(sql, vec![int(oldest)?]).await?;
        let window = vec![int(pruned)?, int(oldest)?];
        let sql =
            "DELETE FROM ring_record_nodes WHERE program=$1 AND (level, position, applied) IN \
                   (SELECT old.level, old.position, old.applied FROM ring_record_nodes AS newer \
                   JOIN ring_record_nodes AS old ON old.program=newer.program \
                   AND old.level=newer.level AND old.position=newer.position \
                   AND old.applied<newer.applied \
                   WHERE newer.program=$1 AND newer.applied>$2 AND newer.applied<=$3)";
        self.exec(sql, window.clone()).await?;
        let sql = "DELETE FROM ring_records WHERE program=$1 AND (leaf_index, applied) IN \
                   (SELECT old.leaf_index, old.applied FROM ring_records AS newer \
                   JOIN ring_records AS old ON old.program=newer.program \
                   AND old.leaf_index=newer.leaf_index AND old.applied<newer.applied \
                   WHERE newer.program=$1 AND newer.applied>$2 AND newer.applied<=$3)";
        self.exec(sql, window).await?;
        let sql = "DELETE FROM ring_record_queue WHERE program=$1 AND position<$2";
        self.exec(sql, vec![int(final_head)?]).await?;
        let sql = "UPDATE ring_registries SET pruned=$2 WHERE program=$1";
        self.exec(sql, vec![int(oldest)?]).await
    }

    fn statement(&self, sql: &str, values: Vec<Value>) -> Statement {
        let program = std::iter::once(bytes(&self.program));
        statement(self.conn, sql, program.chain(values).collect())
    }

    async fn exec(&self, sql: &str, values: Vec<Value>) -> Result<()> {
        self.conn.execute(self.statement(sql, values)).await?;
        Ok(())
    }

    async fn query_one(&self, sql: &str, values: Vec<Value>) -> Result<Option<QueryResult>> {
        Ok(self.conn.query_one(self.statement(sql, values)).await?)
    }

    async fn query_all(&self, sql: &str, values: Vec<Value>) -> Result<Vec<QueryResult>> {
        Ok(self.conn.query_all(self.statement(sql, values)).await?)
    }
}

fn history_root(row: &QueryResult) -> Result<HistoryRoot> {
    Ok(HistoryRoot {
        root: field(row, "root")?,
        applied: uint(row, "applied")?,
        next_index: uint(row, "next_index")?,
        slot: uint(row, "slot")?,
        history_index: u8::try_from(uint(row, "history_index")?)?,
    })
}

fn stored_record(row: &QueryResult) -> Result<StoredRecord> {
    Ok(StoredRecord {
        record: IndexedRecord {
            index: uint(row, "leaf_index")?,
            record: MemberRecord {
                member: field(row, "member")?,
                next: field(row, "next_member")?,
                lists: uint(row, "lists")?,
                escrow_key: field(row, "escrow_key")?,
            },
        },
        seal: seal(row)?,
    })
}

fn stored_entry(row: &QueryResult) -> Result<StoredEntry> {
    Ok(StoredEntry {
        position: uint(row, "position")?,
        write: QueuedWrite {
            entry: QueueEntry {
                member: field(row, "member")?,
                mask: uint(row, "mask")?,
                value: uint(row, "value")?,
                escrow_key: field(row, "escrow_key")?,
            },
            seal: seal(row)?,
        },
        slot: uint(row, "slot")?,
        chain: field(row, "chain")?,
    })
}

fn seal(row: &QueryResult) -> Result<Option<SealedKey>> {
    let text = row.try_get::<Option<String>>("", "seal")?;
    Ok(text.as_deref().map(serde_json::from_str).transpose()?)
}

fn field(row: &QueryResult, column: &str) -> Result<[u8; 32]> {
    row.try_get::<Vec<u8>>("", column)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{column} is not 32 bytes"))
}

fn uint(row: &QueryResult, column: &str) -> Result<u64> {
    Ok(u64::try_from(row.try_get::<i64>("", column)?)?)
}

fn statement<C: ConnectionTrait>(conn: &C, sql: &str, values: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(conn.get_database_backend(), sql, values)
}

async fn exec<C: ConnectionTrait>(conn: &C, sql: &str, values: Vec<Value>) -> Result<()> {
    conn.execute(statement(conn, sql, values)).await?;
    Ok(())
}

fn bytes(value: &[u8; 32]) -> Value {
    value.to_vec().into()
}

fn json<T: Serialize>(value: &T) -> Result<Value> {
    Ok(serde_json::to_string(value)?.into())
}

fn int(value: u64) -> Result<Value> {
    Ok(i64::try_from(value)?.into())
}

fn seal_value(seal: Option<&SealedKey>) -> Result<Value> {
    Ok(seal.map(json).transpose()?.unwrap_or(Value::String(None)))
}

async fn read_json<T: DeserializeOwned, C: ConnectionTrait>(
    conn: &C,
    sql: &str,
    values: Vec<Value>,
) -> Result<Option<T>> {
    let row = conn.query_one(statement(conn, sql, values)).await?;
    row.as_ref().map(stored_state).transpose()
}

async fn read_all<T: DeserializeOwned, C: ConnectionTrait>(conn: &C, sql: &str) -> Result<Vec<T>> {
    let rows = conn.query_all(statement(conn, sql, vec![])).await?;
    rows.iter().map(stored_state).collect()
}

async fn programs<C: ConnectionTrait>(conn: &C, sql: &str) -> Result<BTreeSet<[u8; 32]>> {
    let rows = conn.query_all(statement(conn, sql, vec![])).await?;
    rows.iter().map(|row| field(row, "program")).collect()
}

fn stored_state<T: DeserializeOwned>(row: &QueryResult) -> Result<T> {
    Ok(serde_json::from_str(&row.try_get::<String>("", "state")?)?)
}

/// An account image as base64 of its bytes, decoded through the account's own checks.
mod account_image {
    use std::ops::Deref;

    use base64::{engine::general_purpose::STANDARD, Engine};
    use custom_ring_interface::RingAccount;
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, A: Deref<Target = T>, T: RingAccount>(
        value: &A,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytemuck::bytes_of(&**value)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: RingAccount>(
        deserializer: D,
    ) -> Result<Box<T>, D::Error> {
        let bytes = STANDARD
            .decode(String::deserialize(deserializer)?)
            .map_err(D::Error::custom)?;
        T::from_data(&bytes)
            .map(|account| Box::new(*account))
            .ok_or_else(|| D::Error::custom("invalid account image"))
    }
}
