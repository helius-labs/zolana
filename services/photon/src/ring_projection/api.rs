use std::fmt::Display;

use anyhow::Context as _;

use custom_ring_interface::{pda, KEY_REGISTRY_CAPACITY};
use sea_orm::{DatabaseConnection, DatabaseTransaction, TransactionTrait};
use solana_pubkey::Pubkey;
use solana_transaction_status_client_types::TransactionDetails;
use zolana_indexer_api::{Context as ApiContext, RingMemberProofRequest};
use zolana_ring_key_registry::FIELD_MAX;

use super::{
    key_registry::MemberKey,
    load_root,
    proof::{self, PathOverlay},
    storage::{self, PredecessorError, ProjectionCursor, RingRoot, RingStore},
};
use crate::{
    api::{
        error::{PhotonApiError, RingProjectionError},
        set_transaction_isolation_if_needed,
    },
    ingester::typedefs::block_info::BlockMetadata,
    rpc::RpcClient,
};

pub(crate) struct Insertion {
    pub context: ApiContext,
    pub root: RingRoot,
    pub low: MemberKey,
    pub low_proof: Vec<[u8; 32]>,
    pub new_proof: Vec<[u8; 32]>,
}

pub(crate) struct MemberPath {
    pub context: ApiContext,
    pub root: RingRoot,
    pub leaf: MemberKey,
    pub proof: Vec<[u8; 32]>,
}

pub(crate) async fn insertion(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: &RingMemberProofRequest,
) -> Result<Insertion, PhotonApiError> {
    // 1. Read the requested root and both paths from one database snapshot.
    let tx = db.begin().await?;
    set_transaction_isolation_if_needed(&tx).await?;
    let snapshot = snapshot(&tx, request).await?;
    let root = &snapshot.root;
    if root.next_index >= KEY_REGISTRY_CAPACITY {
        return Err(PhotonApiError::ValidationError(
            "key registry capacity exhausted".into(),
        ));
    }
    let store = RingStore::new(&tx, root.program);
    if store
        .member(&request.member.0)
        .await
        .map_err(internal)?
        .is_some()
    {
        return Err(RingProjectionError::MemberAlreadyRegistered.into());
    }
    let low = store
        .predecessor(&request.member.0)
        .await
        .map_err(|error| match error {
            PredecessorError::NotAbsent => PhotonApiError::ValidationError(error.to_string()),
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
    let context = confirm(rpc, &snapshot).await?;
    Ok(Insertion {
        context,
        root: snapshot.root,
        low,
        low_proof: low_path.siblings,
        new_proof: new_path.siblings,
    })
}

pub(crate) async fn member_path(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: &RingMemberProofRequest,
) -> Result<MemberPath, PhotonApiError> {
    let tx = db.begin().await?;
    set_transaction_isolation_if_needed(&tx).await?;
    let snapshot = snapshot(&tx, request).await?;
    let root = &snapshot.root;
    let leaf = RingStore::new(&tx, root.program)
        .member(&request.member.0)
        .await
        .map_err(internal)?
        .ok_or(RingProjectionError::MemberUnregistered)?;
    let path = proof::path(&tx, root, leaf.index).await.map_err(internal)?;
    if leaf.hash().map_err(internal)? != path.leaf {
        return Err(internal("key registry member disagrees with its leaf"));
    }
    tx.commit().await?;
    let context = confirm(rpc, &snapshot).await?;
    Ok(MemberPath {
        context,
        root: snapshot.root,
        leaf,
        proof: path.siblings,
    })
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
    tx: &DatabaseTransaction,
    request: &RingMemberProofRequest,
) -> Result<Snapshot, PhotonApiError> {
    if request.expected_next_index == 0
        || request.expected_next_index > KEY_REGISTRY_CAPACITY
        || request.member.0 == [0; 32]
        || request.member.0 >= FIELD_MAX
    {
        return Err(PhotonApiError::ValidationError(
            "invalid key registry member or cursor".into(),
        ));
    }
    let cursor = storage::cursor(tx)
        .await
        .map_err(internal)?
        .filter(ProjectionCursor::is_ready)
        .ok_or_else(|| out_of_sync("projector is catching up or recovering"))?;
    if storage::pending_ring(tx, &request.ring_program_id.0.to_bytes())
        .await
        .map_err(internal)?
        .is_some()
    {
        return Err(out_of_sync("ring history is being replayed"));
    }
    let root = RingStore::new(tx, request.ring_program_id.0.to_bytes())
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
    Ok(Snapshot {
        root,
        tip: cursor.tip,
    })
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

pub(super) fn internal(error: impl Display) -> PhotonApiError {
    PhotonApiError::UnexpectedError(format!("{error:#}"))
}
