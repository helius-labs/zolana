use crate::metric;
use cadence_macros::statsd_count;
use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};
use log::error;
use solana_pubkey::ParsePubkeyError;
use thiserror::Error;
#[cfg(feature = "custom-rings")]
use zolana_indexer_api::error_code::{
    RING_MEMBER_UNREGISTERED, RING_REGISTRY_OUT_OF_SYNC, RING_REGISTRY_PAGE_GAP,
    RING_REGISTRY_ROOT_CHANGED,
};
use zolana_indexer_api::ParseHashError;

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
    #[cfg(feature = "custom-rings")]
    #[error(transparent)]
    CustomRing(#[from] CustomRingError),
}

#[cfg(feature = "custom-rings")]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum CustomRingError {
    #[error("member registry is out of sync ({0})")]
    OutOfSync(String),
    #[error("member registry root changed")]
    RootChanged,
    #[error("member has no record in the member registry")]
    MemberUnregistered,
    #[error("member registry page has an index gap or inconsistent leaf")]
    PageGap,
}

#[cfg(feature = "custom-rings")]
impl CustomRingError {
    pub fn code(&self) -> i32 {
        match self {
            Self::OutOfSync(_) => const { wire_code(RING_REGISTRY_OUT_OF_SYNC) },
            Self::RootChanged => const { wire_code(RING_REGISTRY_ROOT_CHANGED) },
            Self::MemberUnregistered => const { wire_code(RING_MEMBER_UNREGISTERED) },
            Self::PageGap => const { wire_code(RING_REGISTRY_PAGE_GAP) },
        }
    }
}

#[cfg(feature = "custom-rings")]
const fn wire_code(code: i64) -> i32 {
    assert!(code >= i32::MIN as i64 && code <= i32::MAX as i64);
    code as i32
}

impl From<PhotonApiError> for ErrorObjectOwned {
    fn from(val: PhotonApiError) -> Self {
        match val {
            #[cfg(feature = "custom-rings")]
            PhotonApiError::CustomRing(ref error) => {
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
