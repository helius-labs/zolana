use std::fmt::Display;

use anyhow::Context as _;

use custom_ring_interface::{FIELD_MAX, MEMBER_REGISTRY_CAPACITY};
use sea_orm::{DatabaseConnection, DatabaseTransaction, TransactionTrait};
use solana_pubkey::Pubkey;
use solana_transaction_status_client_types::TransactionDetails;
use zolana_indexer_api::{
    Base64String, Context as ApiContext, GetRingMemberRecordRequest, GetRingMemberRecordResponse,
    GetRingMemberRegistryRootRequest, GetRingMemberRegistryRootResponse, Hash, RingLowRecordView,
    RingMemberRecordView, SerializablePubkey,
};

use super::{
    load_root, member_registry_root_pda, proof,
    storage::{self, PredecessorError, ProjectionCursor, RingRoot, Store},
    ChainRoot,
};
use crate::{
    api::{
        error::{PhotonApiError, RingProjectionError},
        set_transaction_isolation_if_needed,
    },
    ingester::typedefs::block_info::BlockMetadata,
    rpc::RpcClient,
};

/// The member's record, or the record bracketing it, at the root the caller saw.
pub(crate) async fn member_record(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: GetRingMemberRecordRequest,
) -> Result<GetRingMemberRecordResponse, PhotonApiError> {
    let member = request.member.0;
    if member == [0; 32] || member >= FIELD_MAX {
        return Err(validation("invalid member registry member"));
    }
    let expected = Expected {
        root: request.expected_root.0,
        next_index: request.expected_next_index,
    };
    let (tx, snapshot) = snapshot(db, &request.ring_program_id, Some(expected)).await?;
    let root = &snapshot.root;
    let store = Store::new(&tx, root.program);
    let (present, record, index, path, low) = match store.member(&member).await.map_err(internal)? {
        Some(row) => {
            let path = proof::path(&tx, root, row.index).await.map_err(internal)?;
            if row.hash().map_err(internal)? != path.leaf {
                return Err(internal("member record disagrees with its leaf"));
            }
            let view = RingMemberRecordView {
                member: Hash(row.member),
                next: Hash(row.next),
                lists: row.lists,
                escrow_key: Hash(row.escrow_key),
                eph_pk: row
                    .seal
                    .as_ref()
                    .map(|seal| Base64String(seal.eph_pk.to_vec())),
                ciphertext: row
                    .seal
                    .as_ref()
                    .map(|seal| Base64String(seal.ciphertext.to_vec())),
            };
            (true, Some(view), row.index, hashes(path.siblings), None)
        }
        None => {
            let low = store
                .predecessor(&member)
                .await
                .map_err(|error| match error {
                    PredecessorError::NotAbsent => {
                        internal("member registry order is inconsistent")
                    }
                    PredecessorError::Storage(error) => internal(error),
                })?;
            let path = proof::path(&tx, root, low.index).await.map_err(internal)?;
            if low.hash().map_err(internal)? != path.leaf {
                return Err(internal(
                    "member registry predecessor disagrees with its leaf",
                ));
            }
            let view = RingLowRecordView {
                member: Hash(low.member),
                next: Hash(low.next),
                lists: low.lists,
                escrow_key: Hash(low.escrow_key),
                index: low.index,
                path: hashes(path.siblings),
            };
            (false, None, 0, Vec::new(), Some(view))
        }
    };
    tx.commit().await?;
    let (context, chain) = confirm(rpc, &snapshot).await?;
    Ok(GetRingMemberRecordResponse {
        context,
        root: Hash(root.root),
        root_index: chain.history_cursor,
        next_index: root.next_index,
        present,
        record,
        index,
        path,
        low,
    })
}

/// The registry tip with the path a batch appends its first record along.
pub(crate) async fn registry_root(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: GetRingMemberRegistryRootRequest,
) -> Result<GetRingMemberRegistryRootResponse, PhotonApiError> {
    let (tx, snapshot) = snapshot(db, &request.ring_program_id, None).await?;
    let root = &snapshot.root;
    if root.next_index >= MEMBER_REGISTRY_CAPACITY {
        return Err(validation("member registry capacity exhausted"));
    }
    let append = proof::path(&tx, root, root.next_index)
        .await
        .map_err(internal)?;
    if append.leaf != [0; 32] {
        return Err(internal("member registry append slot is occupied"));
    }
    tx.commit().await?;
    let (context, chain) = confirm(rpc, &snapshot).await?;
    Ok(GetRingMemberRegistryRootResponse {
        context,
        root: Hash(root.root),
        root_index: chain.history_cursor,
        next_index: root.next_index,
        append_path: hashes(append.siblings),
    })
}

fn hashes(siblings: Vec<[u8; 32]>) -> Vec<Hash> {
    siblings.into_iter().map(Hash).collect()
}

/// Opens a read of `program` once the projection serves it at its tip.
pub(super) async fn ready(
    db: &DatabaseConnection,
    program: &[u8; 32],
    out_of_sync: fn(String) -> RingProjectionError,
) -> Result<(DatabaseTransaction, ProjectionCursor), PhotonApiError> {
    let tx = db.begin().await?;
    set_transaction_isolation_if_needed(&tx).await?;
    let stale = |reason: &str| PhotonApiError::from(out_of_sync(reason.to_owned()));
    let cursor = storage::cursor(&tx)
        .await
        .map_err(internal)?
        .filter(ProjectionCursor::is_ready)
        .ok_or_else(|| stale("projector is catching up or recovering"))?;
    let pending = storage::pending_ring(&tx, program)
        .await
        .map_err(internal)?;
    if pending.is_some() {
        return Err(stale("ring history is being replayed"));
    }
    Ok((tx, cursor))
}

async fn check_chain(rpc: &RpcClient, root: &RingRoot) -> anyhow::Result<ChainRoot> {
    let program = Pubkey::new_from_array(root.program);
    anyhow::ensure!(
        member_registry_root_pda(&program).0.to_bytes() == root.address,
        "noncanonical member registry address"
    );
    let chain = load_root(rpc, &program).await?;
    anyhow::ensure!(
        chain.root == root.root
            && chain.next_index == root.next_index
            && chain.history_cursor == root.history_cursor,
        "on-chain member registry root or cursor has advanced"
    );
    Ok(chain)
}

struct Expected {
    root: [u8; 32],
    next_index: u64,
}

struct Snapshot {
    root: RingRoot,
    tip: Option<BlockMetadata>,
}

async fn snapshot(
    db: &DatabaseConnection,
    ring_program_id: &SerializablePubkey,
    expected: Option<Expected>,
) -> Result<(DatabaseTransaction, Snapshot), PhotonApiError> {
    if expected.as_ref().is_some_and(|expected| {
        expected.next_index == 0 || expected.next_index > MEMBER_REGISTRY_CAPACITY
    }) {
        return Err(validation("invalid member registry cursor"));
    }
    let program = ring_program_id.0.to_bytes();
    let (tx, cursor) = ready(db, &program, RingProjectionError::OutOfSync).await?;
    let root = Store::new(&tx, program)
        .root()
        .await
        .map_err(internal)?
        .ok_or_else(|| out_of_sync("initialization has not been indexed"))?;
    if let Some(fault) = &root.fault {
        return Err(out_of_sync(format!("ring quarantined, {fault}")));
    }
    if let Some(expected) = expected {
        if root.root != expected.root || root.next_index != expected.next_index {
            return Err(RingProjectionError::RootChanged.into());
        }
    }
    let tip = cursor.tip;
    Ok((tx, Snapshot { root, tip }))
}

/// Runs after the read transaction commits.
async fn confirm(
    rpc: &RpcClient,
    snapshot: &Snapshot,
) -> Result<(ApiContext, ChainRoot), PhotonApiError> {
    let context = canonical_context(rpc, snapshot.tip.as_ref())
        .await
        .map_err(out_of_sync)?;
    let chain = check_chain(rpc, &snapshot.root)
        .await
        .map_err(out_of_sync)?;
    Ok((context, chain))
}

pub(super) async fn canonical_context(
    rpc: &RpcClient,
    tip: Option<&BlockMetadata>,
) -> anyhow::Result<ApiContext> {
    let tip = tip.context("cursor has no canonical block")?;
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
    RingProjectionError::OutOfSync(reason.to_string()).into()
}

pub(super) fn validation(reason: impl Display) -> PhotonApiError {
    PhotonApiError::ValidationError(reason.to_string())
}

pub(super) fn internal(error: impl Display) -> PhotonApiError {
    PhotonApiError::UnexpectedError(format!("{error:#}"))
}
