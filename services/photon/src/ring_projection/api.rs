use std::fmt::Display;

use anyhow::Context as _;

use custom_ring_interface::{pda, FIELD_MAX, KEY_REGISTRY_CAPACITY};
use sea_orm::{DatabaseConnection, DatabaseTransaction, TransactionTrait};
use solana_pubkey::Pubkey;
use solana_transaction_status_client_types::TransactionDetails;
use zolana_indexer_api::{
    Base64String, Context as ApiContext, GetRingKeyRegistryEntryResponse,
    GetRingKeyRegistryRegisterProofResponse, Hash, RingMemberProofRequest,
};

use super::{
    load_root,
    proof::{self, PathOverlay},
    storage::{self, PredecessorError, ProjectionCursor, RingRoot, Store},
};
use crate::{
    api::{
        error::{PhotonApiError, RingProjectionError},
        set_transaction_isolation_if_needed,
    },
    ingester::typedefs::block_info::BlockMetadata,
    rpc::RpcClient,
};

pub(crate) async fn register(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: RingMemberProofRequest,
) -> Result<GetRingKeyRegistryRegisterProofResponse, PhotonApiError> {
    // 1. Read the requested root and both paths from one database snapshot.
    let (tx, snapshot) = snapshot(db, &request).await?;
    let root = &snapshot.root;
    if root.next_index >= KEY_REGISTRY_CAPACITY {
        return Err(validation("key registry capacity exhausted"));
    }
    let (store, member) = (Store::new(&tx, root.program), &request.member.0);
    if store.member(member).await.map_err(internal)?.is_some() {
        return Err(RingProjectionError::MemberAlreadyRegistered.into());
    }
    let low = store
        .predecessor(member)
        .await
        .map_err(|error| match error {
            PredecessorError::NotAbsent => validation(error),
            PredecessorError::Storage(error) => internal(error),
        })?;
    let low_path = proof::path(&tx, root, low.index).await.map_err(internal)?;
    if low.hash().map_err(internal)? != low_path.leaf {
        return Err(internal("key registry predecessor disagrees with its leaf"));
    }
    let mut new_path = proof::path(&tx, root, root.next_index)
        .await
        .map_err(internal)?;
    if new_path.leaf != [0; 32] {
        return Err(internal("key registry append slot is occupied"));
    }
    tx.commit().await?;
    // 2. Rebase the empty append path onto the predecessor's updated root.
    let mut spliced = low.clone();
    spliced.next = request.member.0;
    PathOverlay {
        updated_index: low.index,
        updated_leaf: spliced.hash().map_err(internal)?,
        updated_path: &low_path.siblings,
    }
    .apply(root.next_index, &mut new_path)
    .map_err(internal)?;
    // 3. Require the proof's block and root to match the chain.
    Ok(GetRingKeyRegistryRegisterProofResponse {
        context: confirm(rpc, &snapshot).await?,
        root: Hash(root.root),
        next_index: root.next_index,
        member: request.member,
        low_member: Hash(low.member),
        low_next: Hash(low.next),
        low_key_hash: Hash(low.key_hash),
        low_index: low.index,
        low_proof: low_path.siblings.into_iter().map(Hash).collect(),
        new_proof: new_path.siblings.into_iter().map(Hash).collect(),
    })
}

pub(crate) async fn lookup(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: RingMemberProofRequest,
) -> Result<GetRingKeyRegistryEntryResponse, PhotonApiError> {
    let (tx, snapshot) = snapshot(db, &request).await?;
    let root = &snapshot.root;
    let leaf = Store::new(&tx, root.program)
        .member(&request.member.0)
        .await
        .map_err(internal)?
        .ok_or(RingProjectionError::MemberUnregistered)?;
    let path = proof::path(&tx, root, leaf.index).await.map_err(internal)?;
    if leaf.hash().map_err(internal)? != path.leaf {
        return Err(internal("key registry member disagrees with its leaf"));
    }
    tx.commit().await?;
    Ok(GetRingKeyRegistryEntryResponse {
        context: confirm(rpc, &snapshot).await?,
        root: Hash(root.root),
        next_index: root.next_index,
        member: request.member,
        next: Hash(leaf.next),
        index: leaf.index,
        eph_pk: Base64String(leaf.eph_pk.to_vec()),
        ciphertext: Base64String(leaf.ciphertext.to_vec()),
        proof: path.siblings.into_iter().map(Hash).collect(),
    })
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

async fn check_chain(rpc: &RpcClient, root: &RingRoot) -> anyhow::Result<()> {
    let program = Pubkey::new_from_array(root.program);
    anyhow::ensure!(
        pda::key_registry_root(&program).0.to_bytes() == root.address,
        "noncanonical key registry address"
    );
    let chain = load_root(rpc, &program).await?;
    anyhow::ensure!(
        chain.root == root.root && chain.next_index == root.next_index,
        "on-chain key registry root or cursor has advanced"
    );
    Ok(())
}

struct Snapshot {
    root: RingRoot,
    tip: Option<BlockMetadata>,
}

async fn snapshot(
    db: &DatabaseConnection,
    request: &RingMemberProofRequest,
) -> Result<(DatabaseTransaction, Snapshot), PhotonApiError> {
    if request.expected_next_index == 0
        || request.expected_next_index > KEY_REGISTRY_CAPACITY
        || request.member.0 == [0; 32]
        || request.member.0 >= FIELD_MAX
    {
        return Err(validation("invalid key registry member or cursor"));
    }
    let program = request.ring_program_id.0.to_bytes();
    let (tx, cursor) = ready(db, &program, RingProjectionError::OutOfSync).await?;
    let root = Store::new(&tx, program)
        .root()
        .await
        .map_err(internal)?
        .ok_or_else(|| out_of_sync("initialization has not been indexed"))?;
    if let Some(fault) = &root.fault {
        return Err(out_of_sync(format!("ring quarantined, {fault}")));
    }
    if root.root != request.expected_root.0 || root.next_index != request.expected_next_index {
        return Err(RingProjectionError::RootChanged.into());
    }
    let tip = cursor.tip;
    Ok((tx, Snapshot { root, tip }))
}

/// Runs after the read transaction commits.
async fn confirm(rpc: &RpcClient, snapshot: &Snapshot) -> Result<ApiContext, PhotonApiError> {
    let context = canonical_context(rpc, snapshot.tip.as_ref())
        .await
        .map_err(out_of_sync)?;
    check_chain(rpc, &snapshot.root)
        .await
        .map_err(out_of_sync)?;
    Ok(context)
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
