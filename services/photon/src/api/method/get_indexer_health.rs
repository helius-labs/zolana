use sea_orm::DatabaseConnection;

use super::super::error::PhotonApiError;
use crate::common::indexer_context::extract as extract_context;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;

pub const HEALTH_CHECK_SLOT_DISTANCE: u64 = 20;

pub async fn get_indexer_health(
    conn: &DatabaseConnection,
    rpc: &RpcClient,
) -> Result<String, PhotonApiError> {
    let context = extract_context(conn).await?;
    let slot = rpc
        .get_slot()
        .await
        .map_err(|e| PhotonApiError::UnexpectedError(format!("RPC error: {}", e)))?;

    let slots_behind = slot.saturating_sub(context.slot);
    if slots_behind > HEALTH_CHECK_SLOT_DISTANCE {
        return Err(PhotonApiError::StaleSlot(slots_behind));
    }
    Ok("ok".to_string())
}
