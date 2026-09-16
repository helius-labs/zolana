use std::fmt::Display;

use custom_ring_interface::HEAD_MAP_CAPACITY;
use sea_orm::{DatabaseConnection, DatabaseTransaction, TransactionTrait};
use solana_pubkey::Pubkey;
use solana_transaction_status_client_types::TransactionDetails;
use zolana_indexer_api::{Context as ApiContext, RingMemberProofRequest};
use zolana_ring_head_map::FIELD_MAX;

use super::{
    load_root,
    proof::{self, PathOverlay},
    storage::{self, PredecessorError, ProjectionCursor, RingRoot, RingStore},
    Leaf, Projection,
};
use crate::{
    api::{
        error::{PhotonApiError, RingProjectionError},
        set_transaction_isolation_if_needed,
    },
    ingester::typedefs::block_info::BlockMetadata,
    rpc::RpcClient,
};

pub(crate) struct Insertion<L> {
    pub context: ApiContext,
    pub root: RingRoot,
    pub low: L,
    pub low_proof: Vec<[u8; 32]>,
    pub new_proof: Vec<[u8; 32]>,
}

pub(crate) struct MemberPath<L> {
    pub context: ApiContext,
    pub root: RingRoot,
    pub leaf: L,
    pub proof: Vec<[u8; 32]>,
}

pub(crate) async fn insertion<P: Projection>(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: &RingMemberProofRequest,
) -> Result<Insertion<P::Leaf>, PhotonApiError> {
    // 1. Read the requested root and both paths from one database snapshot.
    let tx = db.begin().await?;
    set_transaction_isolation_if_needed(&tx).await?;
    let snapshot = snapshot::<P>(&tx, request).await?;
    let root = &snapshot.root;
    if root.next_index >= HEAD_MAP_CAPACITY {
        return Err(PhotonApiError::ValidationError(format!(
            "{} capacity exhausted",
            P::KIND
        )));
    }
    let store = RingStore::<_, P>::new(&tx, root.program);
    if store
        .member(&request.member.0)
        .await
        .map_err(internal)?
        .is_some()
    {
        return Err(RingProjectionError::MemberAlreadyRegistered(P::KIND).into());
    }
    let low = store
        .predecessor(&request.member.0)
        .await
        .map_err(|error| match error {
            PredecessorError::NotAbsent => PhotonApiError::ValidationError(error.to_string()),
            PredecessorError::Storage(error) => internal(error),
        })?;
    let low_path = proof::path::<P>(&tx, root, low.index())
        .await
        .map_err(internal)?;
    if low.hash().map_err(internal)? != low_path.leaf {
        return Err(internal(format!(
            "{} predecessor disagrees with its leaf",
            P::KIND
        )));
    }
    let mut new_path = proof::path::<P>(&tx, root, root.next_index)
        .await
        .map_err(internal)?;
    if new_path.leaf != [0; 32] {
        return Err(internal(format!("{} append slot is occupied", P::KIND)));
    }
    tx.commit().await?;
    // 2. Rebase the empty append path onto the predecessor's updated root.
    let mut spliced = low.clone();
    spliced.set_next(request.member.0);
    PathOverlay {
        updated_index: low.index(),
        updated_leaf: spliced.hash().map_err(internal)?,
        updated_path: &low_path.siblings,
    }
    .apply(root.next_index, &mut new_path)
    .map_err(internal)?;
    // 3. Require the proof's block and root to match the chain.
    let context = confirm::<P>(rpc, &snapshot).await?;
    Ok(Insertion {
        context,
        root: snapshot.root,
        low,
        low_proof: low_path.siblings,
        new_proof: new_path.siblings,
    })
}

pub(crate) async fn member_path<P: Projection>(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: &RingMemberProofRequest,
) -> Result<MemberPath<P::Leaf>, PhotonApiError> {
    let tx = db.begin().await?;
    set_transaction_isolation_if_needed(&tx).await?;
    let snapshot = snapshot::<P>(&tx, request).await?;
    let root = &snapshot.root;
    let leaf = RingStore::<_, P>::new(&tx, root.program)
        .member(&request.member.0)
        .await
        .map_err(internal)?
        .ok_or(RingProjectionError::MemberUnregistered(P::KIND))?;
    let path = proof::path::<P>(&tx, root, leaf.index())
        .await
        .map_err(internal)?;
    if leaf.hash().map_err(internal)? != path.leaf {
        return Err(internal(format!(
            "{} member disagrees with its leaf",
            P::KIND
        )));
    }
    tx.commit().await?;
    let context = confirm::<P>(rpc, &snapshot).await?;
    Ok(MemberPath {
        context,
        root: snapshot.root,
        leaf,
        proof: path.siblings,
    })
}

pub(crate) async fn check_chain<P: Projection>(
    rpc: &RpcClient,
    root: &RingRoot,
) -> anyhow::Result<()> {
    let program = Pubkey::new_from_array(root.program);
    anyhow::ensure!(
        P::root_address(&program).0.to_bytes() == root.address,
        "noncanonical {} address",
        P::KIND
    );
    let chain = load_root::<P>(rpc, &program).await?;
    anyhow::ensure!(
        chain.root == root.root && chain.next_index == root.next_index,
        "on-chain {} root or cursor has advanced",
        P::KIND
    );
    Ok(())
}

struct Snapshot {
    root: RingRoot,
    tip: Option<BlockMetadata>,
}

async fn snapshot<P: Projection>(
    tx: &DatabaseTransaction,
    request: &RingMemberProofRequest,
) -> Result<Snapshot, PhotonApiError> {
    if request.expected_next_index == 0
        || request.expected_next_index > HEAD_MAP_CAPACITY
        || request.member.0 == [0; 32]
        || request.member.0 >= FIELD_MAX
    {
        return Err(PhotonApiError::ValidationError(format!(
            "invalid {} member or cursor",
            P::KIND
        )));
    }
    let cursor = storage::cursor(tx)
        .await
        .map_err(internal)?
        .filter(ProjectionCursor::is_ready)
        .ok_or_else(|| out_of_sync::<P>("projector is catching up or recovering"))?;
    if storage::pending_ring(tx, &request.ring_program_id.0.to_bytes())
        .await
        .map_err(internal)?
        .is_some()
    {
        return Err(out_of_sync::<P>("ring history is being replayed"));
    }
    let root = RingStore::<_, P>::new(tx, request.ring_program_id.0.to_bytes())
        .root()
        .await
        .map_err(internal)?
        .ok_or_else(|| out_of_sync::<P>("initialization has not been indexed"))?;
    if let Some(fault) = &root.fault {
        return Err(out_of_sync::<P>(format!("ring quarantined, {fault}")));
    }
    if root.root != request.expected_root.0 || root.next_index != request.expected_next_index {
        return Err(RingProjectionError::RootChanged(P::KIND).into());
    }
    Ok(Snapshot {
        root,
        tip: cursor.tip,
    })
}

/// Runs after the read transaction commits.
async fn confirm<P: Projection>(
    rpc: &RpcClient,
    snapshot: &Snapshot,
) -> Result<ApiContext, PhotonApiError> {
    let tip = snapshot
        .tip
        .as_ref()
        .ok_or_else(|| out_of_sync::<P>("cursor has no canonical block"))?;
    let block = rpc
        .get_block(tip.slot, TransactionDetails::None)
        .await
        .map_err(out_of_sync::<P>)?;
    if block.blockhash != tip.blockhash.to_string() {
        return Err(out_of_sync::<P>("cursor is on an orphaned block"));
    }
    check_chain::<P>(rpc, &snapshot.root)
        .await
        .map_err(out_of_sync::<P>)?;
    Ok(ApiContext {
        slot: tip.slot,
        block_time: tip.block_time,
    })
}

fn out_of_sync<P: Projection>(reason: impl Display) -> PhotonApiError {
    RingProjectionError::OutOfSync {
        kind: P::KIND,
        reason: reason.to_string(),
    }
    .into()
}

fn internal(error: impl Display) -> PhotonApiError {
    PhotonApiError::UnexpectedError(format!("{error:#}"))
}
