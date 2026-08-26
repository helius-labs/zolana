use jsonrpsee::types::{error::ErrorCode, ErrorObjectOwned};
use log::error;
use thiserror::Error;
use zolana_client::ClientError;
use zolana_ring_client::OriginError;

use crate::authorize::Unauthorized;

#[derive(Debug, Error)]
pub enum RingRpcError {
    #[error("ring_program_id is required when keys are derived per ring")]
    RingRequired,
    #[error("ring is not served by the local auditor key")]
    RingNotServed,
    #[error("audit page is invalid")]
    InvalidPage,
    #[error("request is unauthorized because {0}")]
    Unauthorized(#[from] Unauthorized),
    #[error("key derivation failed because {0}")]
    Derivation(#[from] zolana_keypair::KeypairError),
    #[error(transparent)]
    Upstream(#[from] ClientError),
    #[error(transparent)]
    Origin(#[from] OriginError),
    #[error("indexer returned data outside the audit bounds")]
    InvalidIndexerResponse,
    #[error("audit service state is unavailable")]
    StateUnavailable,
    #[error("audit service is busy")]
    Busy,
}

impl From<RingRpcError> for ErrorObjectOwned {
    fn from(error: RingRpcError) -> Self {
        match error {
            RingRpcError::RingRequired
            | RingRpcError::RingNotServed
            | RingRpcError::InvalidPage
            | RingRpcError::Unauthorized(_) => ErrorObjectOwned::owned(
                ErrorCode::InvalidRequest.code(),
                error.to_string(),
                None::<()>,
            ),
            RingRpcError::Upstream(inner) => {
                error!("upstream request failed {inner}");
                ErrorObjectOwned::owned(
                    ErrorCode::InternalError.code(),
                    "upstream request failed",
                    None::<()>,
                )
            }
            RingRpcError::Origin(inner) => {
                error!("transaction origin lookup failed {inner}");
                ErrorObjectOwned::owned(
                    ErrorCode::InternalError.code(),
                    "upstream request failed",
                    None::<()>,
                )
            }
            RingRpcError::InvalidIndexerResponse => {
                error!("indexer returned data outside the audit bounds");
                ErrorObjectOwned::owned(
                    ErrorCode::InternalError.code(),
                    "indexer response is invalid",
                    None::<()>,
                )
            }
            RingRpcError::Derivation(inner) => {
                let _ = inner;
                error!("auditor key derivation failed");
                ErrorObjectOwned::owned(
                    ErrorCode::InternalError.code(),
                    "auditor key is unavailable",
                    None::<()>,
                )
            }
            RingRpcError::StateUnavailable => {
                error!("audit service state is unavailable");
                ErrorObjectOwned::owned(
                    ErrorCode::InternalError.code(),
                    "audit service is unavailable",
                    None::<()>,
                )
            }
            RingRpcError::Busy => ErrorObjectOwned::owned(
                ErrorCode::ServerIsBusy.code(),
                "audit service is busy",
                None::<()>,
            ),
        }
    }
}
