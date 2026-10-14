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

/// A client sees its own request errors, and only a generic message for a server fault.
impl From<RingRpcError> for ErrorObjectOwned {
    fn from(failure: RingRpcError) -> Self {
        use RingRpcError::*;
        let (code, message) = match &failure {
            RingRequired | RingNotServed | InvalidPage | Unauthorized(_) => {
                let message = failure.to_string();
                return ErrorObjectOwned::owned(
                    ErrorCode::InvalidRequest.code(),
                    message,
                    None::<()>,
                );
            }
            Busy => (ErrorCode::ServerIsBusy, "audit service is busy"),
            Upstream(inner) => {
                error!("upstream request failed {inner}");
                (ErrorCode::InternalError, "upstream request failed")
            }
            Origin(inner) => {
                error!("transaction origin lookup failed {inner}");
                (ErrorCode::InternalError, "upstream request failed")
            }
            InvalidIndexerResponse => {
                error!("indexer returned data outside the audit bounds");
                (ErrorCode::InternalError, "indexer response is invalid")
            }
            Derivation(_) => {
                error!("auditor key derivation failed");
                (ErrorCode::InternalError, "auditor key is unavailable")
            }
            StateUnavailable => {
                error!("audit service state is unavailable");
                (ErrorCode::InternalError, "audit service is unavailable")
            }
        };
        ErrorObjectOwned::owned(code.code(), message, None::<()>)
    }
}
