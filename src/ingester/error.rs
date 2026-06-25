use crate::api::error::PhotonApiError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum IngesterError {
    #[error("Malformed event: {msg}")]
    MalformedEvent { msg: String },
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Parser error: {0}")]
    ParserError(String),
}

impl From<sea_orm::error::DbErr> for IngesterError {
    fn from(err: sea_orm::error::DbErr) -> Self {
        IngesterError::DatabaseError(format!("DatabaseError: {}", err))
    }
}

impl From<PhotonApiError> for IngesterError {
    fn from(err: PhotonApiError) -> Self {
        IngesterError::DatabaseError(format!("API Error: {}", err))
    }
}
