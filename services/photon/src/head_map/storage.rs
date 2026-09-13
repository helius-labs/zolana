use anyhow::{bail, Context, Result};
use sea_orm::{ConnectionTrait, DatabaseTransaction, Statement, Value};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zolana_indexer_api::{Hash, RingHeadRecord};

use crate::{
    common::rings_tree::RingsTreeKind,
    ingester::{
        persist::{persist_leaf_nodes, LeafNode},
        typedefs::block_info::BlockMetadata,
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Map {
    pub program: [u8; 32],
    pub address: [u8; 32],
    pub root: [u8; 32],
    pub next_index: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    pub member: [u8; 32],
    pub index: u64,
    pub next: [u8; 32],
    pub nullifier: [u8; 32],
    pub record: Option<RingHeadRecord>,
}

impl Member {
    pub fn hash(&self) -> Result<[u8; 32]> {
        custom_ring_interface::head_map_leaf(&self.member, &self.next, &self.nullifier)
            .map_err(|error| anyhow::anyhow!("head leaf hash failed ({error:?})"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cursor {
    pub start_slot: u64,
    pub scanned_slot: u64,
    pub tip: Option<BlockMetadata>,
    /// Undo writes must increase the storage sequence.
    pub revision: u64,
    pub ready: bool,
}

impl Cursor {
    pub fn advance_revision(&mut self) -> Result<u64> {
        self.revision = self
            .revision
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .context("head-map storage revision exhausted")?;
        Ok(self.revision)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Undo {
    pub program: [u8; 32],
    pub before: Option<Map>,
    pub members: Vec<([u8; 32], Option<Member>)>,
    pub leaves: Vec<(u64, [u8; 32])>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockJournal {
    pub metadata: BlockMetadata,
    pub previous_tip: Option<BlockMetadata>,
    pub undo: Vec<Undo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pending {
    pub program: [u8; 32],
    pub slot: u64,
    pub blockhash: Hash,
}

pub async fn save_pending<C: ConnectionTrait>(conn: &C, value: &Pending) -> Result<()> {
    conn.execute(statement(conn,"INSERT INTO ring_head_pending(program,slot,state) VALUES($1,$2,$3) ON CONFLICT(program) DO NOTHING",vec![value.program.to_vec().into(),i64::try_from(value.slot)?.into(),serde_json::to_string(value)?.into()])).await?;
    Ok(())
}

pub async fn pending<C: ConnectionTrait>(conn: &C) -> Result<Vec<Pending>> {
    conn.query_all(statement(
        conn,
        "SELECT state FROM ring_head_pending ORDER BY slot",
        vec![],
    ))
    .await?
    .into_iter()
    .map(|row| {
        let state: String = row.try_get("", "state")?;
        Ok(serde_json::from_str(&state)?)
    })
    .collect()
}

pub async fn delete_pending<C: ConnectionTrait>(conn: &C, program: &[u8; 32]) -> Result<()> {
    conn.execute(statement(
        conn,
        "DELETE FROM ring_head_pending WHERE program=$1",
        vec![program.to_vec().into()],
    ))
    .await?;
    Ok(())
}

pub fn statement<C: ConnectionTrait>(conn: &C, sql: &str, values: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(conn.get_database_backend(), sql, values)
}

pub async fn read_json<T: DeserializeOwned, C: ConnectionTrait>(
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

pub async fn cursor<C: ConnectionTrait>(conn: &C) -> Result<Option<Cursor>> {
    read_json(
        conn,
        "SELECT state FROM ring_head_cursor WHERE id = 1",
        vec![],
    )
    .await
}

pub async fn save_cursor<C: ConnectionTrait>(conn: &C, value: &Cursor) -> Result<()> {
    conn.execute(statement(conn, "INSERT INTO ring_head_cursor(id,state) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET state=excluded.state", vec![serde_json::to_string(value)?.into()])).await?;
    Ok(())
}

pub async fn map<C: ConnectionTrait>(conn: &C, program: &[u8; 32]) -> Result<Option<Map>> {
    read_json(
        conn,
        "SELECT state FROM ring_head_maps WHERE program=$1",
        vec![program.to_vec().into()],
    )
    .await
}

pub async fn maps<C: ConnectionTrait>(conn: &C) -> Result<Vec<Map>> {
    conn.query_all(statement(
        conn,
        "SELECT state FROM ring_head_maps ORDER BY program",
        vec![],
    ))
    .await?
    .into_iter()
    .map(|row| {
        let state: String = row.try_get("", "state")?;
        Ok(serde_json::from_str(&state)?)
    })
    .collect()
}

pub async fn save_map<C: ConnectionTrait>(conn: &C, value: &Map) -> Result<()> {
    conn.execute(statement(conn, "INSERT INTO ring_head_maps(program,state) VALUES($1,$2) ON CONFLICT(program) DO UPDATE SET state=excluded.state", vec![value.program.to_vec().into(), serde_json::to_string(value)?.into()])).await?;
    Ok(())
}

pub async fn member<C: ConnectionTrait>(
    conn: &C,
    program: &[u8; 32],
    member: &[u8; 32],
) -> Result<Option<Member>> {
    read_json(
        conn,
        "SELECT state FROM ring_head_members WHERE program=$1 AND member=$2",
        vec![program.to_vec().into(), member.to_vec().into()],
    )
    .await
}

pub async fn predecessor<C: ConnectionTrait>(
    conn: &C,
    program: &[u8; 32],
    member: &[u8; 32],
) -> Result<Member> {
    let low: Member = read_json(conn, "SELECT state FROM ring_head_members WHERE program=$1 AND member<$2 ORDER BY member DESC LIMIT 1", vec![program.to_vec().into(), member.to_vec().into()]).await?.context("no covering head-map predecessor")?;
    if !(low.member < *member && *member < low.next) {
        bail!("member is not absent in the head map");
    }
    Ok(low)
}

pub async fn save_member<C: ConnectionTrait>(
    conn: &C,
    program: &[u8; 32],
    member: &Member,
) -> Result<()> {
    let index = i64::try_from(member.index)?;
    conn.execute(statement(conn, "INSERT INTO ring_head_members(program,member,leaf_index,state) VALUES($1,$2,$3,$4) ON CONFLICT(program,member) DO UPDATE SET leaf_index=excluded.leaf_index,state=excluded.state", vec![program.to_vec().into(), member.member.to_vec().into(), index.into(), serde_json::to_string(member)?.into()])).await?;
    Ok(())
}

pub async fn write_leaves(
    tx: &DatabaseTransaction,
    map: &Map,
    leaves: &[(u64, [u8; 32])],
    revision: u64,
) -> Result<[u8; 32]> {
    let leaves = leaves
        .iter()
        .map(|(index, hash)| LeafNode {
            tree: map.address.to_vec(),
            tree_kind: RingsTreeKind::HeadMap,
            leaf_index: *index,
            hash: Hash(*hash),
            seq: Some(revision),
        })
        .collect();
    persist_leaf_nodes(
        tx,
        leaves,
        custom_ring_interface::HEAD_MAP_HEIGHT as u32 + 1,
    )
    .await?;
    let row = tx
        .query_one(statement(
            tx,
            "SELECT hash FROM state_trees WHERE tree=$1 AND tree_kind=$2 AND node_idx=1",
            vec![
                map.address.to_vec().into(),
                i32::from(RingsTreeKind::HeadMap).into(),
            ],
        ))
        .await?
        .context("head-map root missing")?;
    let hash: Vec<u8> = row.try_get("", "hash")?;
    hash.try_into()
        .map_err(|_| anyhow::anyhow!("invalid head-map root length"))
}

pub async fn save_journal(tx: &DatabaseTransaction, journal: &BlockJournal) -> Result<()> {
    tx.execute(statement(
        tx,
        "INSERT INTO ring_head_blocks(slot,state) VALUES($1,$2)",
        vec![
            i64::try_from(journal.metadata.slot)?.into(),
            serde_json::to_string(journal)?.into(),
        ],
    ))
    .await?;
    Ok(())
}

pub async fn rollback(tx: &DatabaseTransaction, cursor: &mut Cursor) -> Result<()> {
    let tip = cursor
        .tip
        .as_ref()
        .context("cannot rewind before head-map start")?;
    let journal: BlockJournal = read_json(
        tx,
        "SELECT state FROM ring_head_blocks WHERE slot=$1",
        vec![i64::try_from(tip.slot)?.into()],
    )
    .await?
    .context("head-map journal gap")?;
    tx.execute(statement(
        tx,
        "DELETE FROM ring_head_pending WHERE slot=$1",
        vec![i64::try_from(journal.metadata.slot)?.into()],
    ))
    .await?;
    for undo in journal.undo.iter().rev() {
        if let Some(before) = &undo.before {
            let root = write_leaves(tx, before, &undo.leaves, cursor.advance_revision()?).await?;
            if root != before.root {
                bail!("head-map rollback root mismatch");
            }
            save_map(tx, before).await?;
            for (key, before_member) in &undo.members {
                match before_member {
                    Some(value) => save_member(tx, &undo.program, value).await?,
                    None => {
                        tx.execute(statement(
                            tx,
                            "DELETE FROM ring_head_members WHERE program=$1 AND member=$2",
                            vec![undo.program.to_vec().into(), key.to_vec().into()],
                        ))
                        .await?;
                    }
                }
            }
        } else {
            let created = map(tx, &undo.program)
                .await?
                .context("created head map missing on rollback")?;
            tx.execute(statement(
                tx,
                "DELETE FROM state_trees WHERE tree=$1 AND tree_kind=$2",
                vec![
                    created.address.to_vec().into(),
                    i32::from(RingsTreeKind::HeadMap).into(),
                ],
            ))
            .await?;
            tx.execute(statement(
                tx,
                "DELETE FROM ring_head_members WHERE program=$1",
                vec![undo.program.to_vec().into()],
            ))
            .await?;
            tx.execute(statement(
                tx,
                "DELETE FROM ring_head_maps WHERE program=$1",
                vec![undo.program.to_vec().into()],
            ))
            .await?;
        }
    }
    tx.execute(statement(
        tx,
        "DELETE FROM ring_head_blocks WHERE slot=$1",
        vec![i64::try_from(journal.metadata.slot)?.into()],
    ))
    .await?;
    cursor.tip = journal.previous_tip;
    cursor.scanned_slot = cursor
        .tip
        .as_ref()
        .map_or(cursor.start_slot, |tip| tip.slot);
    cursor.ready = false;
    save_cursor(tx, cursor).await
}
