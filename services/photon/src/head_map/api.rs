use anyhow::Context;
use sea_orm::{DatabaseConnection, TransactionTrait};
use solana_pubkey::Pubkey;
use solana_transaction_status_client_types::TransactionDetails;
use zolana_indexer_api::{
    Context as ApiContext, GetRingHeadProofRequest, GetRingHeadRegisterProofResponse,
    GetRingHeadTransferProofResponse, Hash,
};

use super::{proof, storage};
use crate::{
    api::{error::PhotonApiError, set_transaction_isolation_if_needed},
    rpc::RpcClient,
};

fn unavailable(error: impl std::fmt::Display) -> PhotonApiError {
    PhotonApiError::HeadMapOutOfSync(error.to_string())
}

pub async fn check_chain(rpc: &RpcClient, map: &storage::HeadMapState) -> anyhow::Result<()> {
    let program = Pubkey::new_from_array(map.program);
    let (address, bump) =
        Pubkey::find_program_address(&[custom_ring_interface::HeadMapRoot::SEED], &program);
    anyhow::ensure!(
        address.to_bytes() == map.address,
        "noncanonical head-map address"
    );
    let account = rpc.get_account(&address).await?;
    anyhow::ensure!(
        account.owner == program && account.data.len() == custom_ring_interface::HeadMapRoot::SIZE,
        "invalid head-map owner or layout"
    );
    anyhow::ensure!(
        account.data[0] == custom_ring_interface::HEAD_MAP_ROOT && account.data[41] == bump,
        "invalid head-map discriminator or bump"
    );
    let next_index = u64::from_le_bytes(account.data[33..41].try_into()?);
    anyhow::ensure!(
        account.data[1..33] == map.root && next_index == map.next_index,
        "on-chain head-map root or cursor has advanced"
    );
    Ok(())
}

async fn snapshot(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: &GetRingHeadProofRequest,
) -> Result<
    (
        sea_orm::DatabaseTransaction,
        storage::HeadMapState,
        ApiContext,
    ),
    PhotonApiError,
> {
    if request.expected_next_index == 0
        || request.expected_next_index > proof::CAPACITY
        || request.member.0 == [0; 32]
        || request.member.0 >= zolana_ring_head_map::FIELD_MAX
    {
        return Err(PhotonApiError::ValidationError(
            "invalid head-map member or cursor".into(),
        ));
    }
    // 1. Read the root and member paths from one completed projection snapshot.
    let tx = db.begin().await?;
    set_transaction_isolation_if_needed(&tx).await?;
    let cursor = storage::cursor(&tx)
        .await
        .map_err(unavailable)?
        .filter(|c| c.ready)
        .ok_or_else(|| unavailable("head-map projector is catching up or recovering"))?;
    let map = storage::map(&tx, &request.ring_program_id.0.to_bytes())
        .await
        .map_err(unavailable)?
        .ok_or_else(|| unavailable("head-map initialization has not been indexed"))?;
    if map.root != request.expected_root.0 || map.next_index != request.expected_next_index {
        return Err(PhotonApiError::HeadRootChanged);
    }
    // 2. Require the snapshot's block and root to remain canonical on chain.
    let tip = cursor
        .tip
        .context("head-map cursor has no canonical block")
        .map_err(unavailable)?;
    let block = rpc
        .get_block(tip.slot, TransactionDetails::None)
        .await
        .map_err(unavailable)?;
    if block.blockhash != tip.blockhash.to_string() {
        return Err(unavailable("head-map cursor is on an orphaned block"));
    }
    check_chain(rpc, &map).await.map_err(unavailable)?;
    Ok((
        tx,
        map,
        ApiContext {
            slot: tip.slot,
            block_time: tip.block_time,
        },
    ))
}

pub async fn register(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: GetRingHeadProofRequest,
) -> Result<GetRingHeadRegisterProofResponse, PhotonApiError> {
    let (tx, map, context) = snapshot(db, rpc, &request).await?;
    if map.next_index >= proof::CAPACITY {
        return Err(PhotonApiError::ValidationError(
            "head-map capacity exhausted".into(),
        ));
    }
    if storage::member(&tx, &map.program, &request.member.0)
        .await
        .map_err(unavailable)?
        .is_some()
    {
        return Err(PhotonApiError::HeadMemberAlreadyRegistered);
    }
    // 1. Authenticate the predecessor covering the absent member.
    let low = storage::predecessor(&tx, &map.program, &request.member.0)
        .await
        .map_err(|e| PhotonApiError::ValidationError(e.to_string()))?;
    let (low_hash, low_proof) = proof::path(&tx, &map, low.index)
        .await
        .map_err(unavailable)?;
    if low.hash().map_err(unavailable)? != low_hash {
        return Err(unavailable("head-map predecessor disagrees with its leaf"));
    }
    let (empty, mut new_proof) = proof::path(&tx, &map, map.next_index)
        .await
        .map_err(unavailable)?;
    if empty != [0; 32] {
        return Err(unavailable("head-map append slot is occupied"));
    }
    // 2. Bind the empty append path to the root after splicing the predecessor.
    let changed_low =
        custom_ring_interface::head_map_leaf(&low.member, &request.member.0, &low.nullifier)
            .map_err(|e| unavailable(format!("invalid predecessor ({e:?})")))?;
    proof::after_update(
        low.index,
        changed_low,
        &low_proof,
        map.next_index,
        &mut new_proof,
    )
    .map_err(unavailable)?;
    tx.commit().await?;
    Ok(GetRingHeadRegisterProofResponse {
        context,
        root: Hash(map.root),
        next_index: map.next_index,
        member: request.member,
        low_member: Hash(low.member),
        low_next: Hash(low.next),
        low_nullifier: Hash(low.nullifier),
        low_index: low.index,
        low_proof: low_proof.into_iter().map(Hash).collect(),
        new_proof: new_proof.into_iter().map(Hash).collect(),
    })
}

pub async fn transfer(
    db: &DatabaseConnection,
    rpc: &RpcClient,
    request: GetRingHeadProofRequest,
) -> Result<GetRingHeadTransferProofResponse, PhotonApiError> {
    let (tx, map, context) = snapshot(db, rpc, &request).await?;
    let member = storage::member(&tx, &map.program, &request.member.0)
        .await
        .map_err(unavailable)?
        .ok_or(PhotonApiError::HeadMemberUnregistered)?;
    let (leaf, proof) = proof::path(&tx, &map, member.index)
        .await
        .map_err(unavailable)?;
    if member.hash().map_err(unavailable)? != leaf {
        return Err(unavailable("head-map member disagrees with its leaf"));
    }
    let record = member
        .record
        .context("head-map member has no current record")
        .map_err(unavailable)?;
    tx.commit().await?;
    Ok(GetRingHeadTransferProofResponse {
        context,
        root: Hash(map.root),
        next_index: map.next_index,
        member: request.member,
        next: Hash(member.next),
        nullifier: Hash(member.nullifier),
        index: member.index,
        proof: proof.into_iter().map(Hash).collect(),
        record,
    })
}
