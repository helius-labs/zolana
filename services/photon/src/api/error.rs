use crate::metric;
use cadence_macros::statsd_count;
use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use log::error;
use solana_pubkey::ParsePubkeyError;
use thiserror::Error;
#[cfg(feature = "ring-projection")]
use zolana_indexer_api::error_code::{
    RING_HEAD_MAP_OUT_OF_SYNC, RING_HEAD_MEMBER_ALREADY_REGISTERED, RING_HEAD_MEMBER_UNREGISTERED,
    RING_HEAD_ROOT_CHANGED, RING_KEY_REGISTRY_MEMBER_ALREADY_REGISTERED,
    RING_KEY_REGISTRY_MEMBER_UNREGISTERED, RING_KEY_REGISTRY_OUT_OF_SYNC,
    RING_KEY_REGISTRY_ROOT_CHANGED,
};
use zolana_indexer_api::ParseHashError;

#[cfg(feature = "ring-projection")]
use crate::ring_projection::ProjectionKind;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PhotonApiError {
    #[error("Validation Error: {0}")]
    ValidationError(String),
    #[error("Invalid Public Key: field '{field}'")]
    InvalidPubkey { field: String },
    #[error("Database Error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),
    #[error("Record Not Found: {0}")]
    RecordNotFound(String),
    #[error("Unexpected Error: {0}")]
    UnexpectedError(String),
    #[error("Node is behind {0} slots")]
    StaleSlot(u64),
    /// The indexed root is no longer in the chain's root history, so Photon
    /// cannot provide the history entry a client must quote. Retryable.
    #[error("Stale Root: {0}")]
    StaleRoot(String),
    #[cfg(feature = "ring-projection")]
    #[error(transparent)]
    RingProjection(#[from] RingProjectionError),
}

#[cfg(feature = "ring-projection")]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum RingProjectionError {
    #[error("{kind} is out of sync ({reason})")]
    OutOfSync {
        kind: ProjectionKind,
        reason: String,
    },
    #[error("{0} root changed")]
    RootChanged(ProjectionKind),
    #[error("member is not registered in the {0}")]
    MemberUnregistered(ProjectionKind),
    #[error("member is already registered in the {0}")]
    MemberAlreadyRegistered(ProjectionKind),
}

#[cfg(feature = "ring-projection")]
const HEAD_MAP_CODES: [i32; 4] = [
    wire_code(RING_HEAD_MAP_OUT_OF_SYNC),
    wire_code(RING_HEAD_ROOT_CHANGED),
    wire_code(RING_HEAD_MEMBER_UNREGISTERED),
    wire_code(RING_HEAD_MEMBER_ALREADY_REGISTERED),
];
#[cfg(feature = "ring-projection")]
const KEY_REGISTRY_CODES: [i32; 4] = [
    wire_code(RING_KEY_REGISTRY_OUT_OF_SYNC),
    wire_code(RING_KEY_REGISTRY_ROOT_CHANGED),
    wire_code(RING_KEY_REGISTRY_MEMBER_UNREGISTERED),
    wire_code(RING_KEY_REGISTRY_MEMBER_ALREADY_REGISTERED),
];

#[cfg(feature = "ring-projection")]
const fn wire_code(code: i64) -> i32 {
    assert!(code >= i32::MIN as i64 && code <= i32::MAX as i64);
    code as i32
}

#[cfg(feature = "ring-projection")]
impl RingProjectionError {
    pub fn code(&self) -> i32 {
        let (kind, cause) = match self {
            Self::OutOfSync { kind, .. } => (*kind, 0),
            Self::RootChanged(kind) => (*kind, 1),
            Self::MemberUnregistered(kind) => (*kind, 2),
            Self::MemberAlreadyRegistered(kind) => (*kind, 3),
        };
        match kind {
            ProjectionKind::HeadMap => HEAD_MAP_CODES[cause],
            ProjectionKind::KeyRegistry => KEY_REGISTRY_CODES[cause],
        }
    }
}

impl From<PhotonApiError> for ErrorObjectOwned {
    fn from(val: PhotonApiError) -> Self {
        match val {
            #[cfg(feature = "ring-projection")]
            PhotonApiError::RingProjection(ref error) => {
                ErrorObjectOwned::owned(error.code(), val.to_string(), None::<()>)
            }
            PhotonApiError::ValidationError(_) => {
                metric! {
                    statsd_count!("validation_api_error", 1);
                }
                invalid_request(val)
            }
            PhotonApiError::InvalidPubkey { .. } => {
                metric! {
                    statsd_count!("invalid_pubkey_api_error", 1);
                }
                invalid_request(val)
            }
            PhotonApiError::RecordNotFound(_) => {
                metric! {
                    statsd_count!("record_not_found_api_error", 1);
                }
                invalid_request(val)
            }
            PhotonApiError::StaleSlot(_) => {
                metric! {
                    statsd_count!("stale_slot_api_error", 1);
                }
                invalid_request(val)
            }
            PhotonApiError::StaleRoot(_) => {
                metric! {
                    statsd_count!("stale_root_api_error", 1);
                }
                invalid_request(val)
            }
            PhotonApiError::DatabaseError(e) => {
                error!("Internal server database error: {}", e);
                metric! {
                    statsd_count!("internal_database_api_error", 1);
                }
                internal_server_error()
            }
            PhotonApiError::UnexpectedError(e) => {
                error!("Internal server error: {}", e);
                metric! {
                    statsd_count!("unexpected_api_error", 1);
                }
                internal_server_error()
            }
        }
    }
}

// The API contract receives parsed input from the user, so if we get a ParseHashError it means
// that the database itself returned an invalid hash.
impl From<ParseHashError> for PhotonApiError {
    fn from(_error: ParseHashError) -> Self {
        PhotonApiError::UnexpectedError("Invalid hash in database".to_string())
    }
}

impl From<ParsePubkeyError> for PhotonApiError {
    fn from(_error: ParsePubkeyError) -> Self {
        PhotonApiError::UnexpectedError("Invalid public key in database".to_string())
    }
}

fn invalid_request(e: PhotonApiError) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InvalidRequest.code(), e.to_string(), None::<()>)
}

fn internal_server_error() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        ErrorCode::InternalError.code(),
        "Internal server error",
        None::<()>,
    )
}
