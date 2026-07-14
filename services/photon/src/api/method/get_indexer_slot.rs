use crate::common::indexer_context::extract as extract_context;
use sea_orm::DatabaseConnection;

use super::super::error::PhotonApiError;

pub async fn get_indexer_slot(conn: &DatabaseConnection) -> Result<u64, PhotonApiError> {
    Ok(extract_context(conn).await?.slot)
}
