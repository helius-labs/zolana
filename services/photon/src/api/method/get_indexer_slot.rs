use crate::common::typedefs::context::extract as extract_context;
use crate::common::typedefs::unsigned_integer::UnsignedInteger;
use sea_orm::DatabaseConnection;

use super::super::error::PhotonApiError;

pub async fn get_indexer_slot(
    conn: &DatabaseConnection,
) -> Result<UnsignedInteger, PhotonApiError> {
    let slot = extract_context(conn).await?.slot;

    Ok(UnsignedInteger(slot))
}
