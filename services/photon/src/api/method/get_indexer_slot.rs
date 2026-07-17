use crate::common::indexer_context::extract_slot;
use sea_orm::DatabaseConnection;

use super::super::error::PhotonApiError;

pub async fn get_indexer_slot(conn: &DatabaseConnection) -> Result<u64, PhotonApiError> {
    extract_slot(conn).await
}
