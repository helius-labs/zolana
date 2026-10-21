use jsonrpsee::types::{error::ErrorCode, ErrorObjectOwned};
use log::error;
use thiserror::Error;
use zolana_client::ClientError;
use zolana_ring_client::{
    rpc::{KeyFileError, AUDITED_NOTES_LIMIT},
    AuditError,
};

use crate::authorize::Unauthorized;

#[derive(Debug, Error)]
pub enum RingRpcError {
    #[error("ring_program_id is required when keys are derived per ring")]
    RingRequired,
    #[error("ring is not served by the local auditor key")]
    RingNotServed,
    #[error("audit page is invalid")]
    InvalidPage,
    #[error("a note read names 1 to {AUDITED_NOTES_LIMIT} UTXO hashes")]
    InvalidNoteRequest,
    #[error("request is unauthorized because {0}")]
    Unauthorized(#[from] Unauthorized),
    #[error("key derivation failed because {0}")]
    Derivation(#[from] zolana_keypair::KeypairError),
    #[error("auditor key is unusable because {0}")]
    AuditorKey(#[from] KeyFileError),
    #[error(transparent)]
    Upstream(#[from] ClientError),
    #[error(transparent)]
    Origin(#[from] AuditError),
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
            RingRequired | RingNotServed | InvalidPage | InvalidNoteRequest | Unauthorized(_) => {
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
            Origin(AuditError::MergeAuditWorkBudget) => (
                ErrorCode::InternalError,
                "audit scan exceeded its per-request work budget",
            ),
            Origin(inner) => {
                error!("transaction origin lookup failed {inner}");
                (ErrorCode::InternalError, "upstream request failed")
            }
            InvalidIndexerResponse => {
                error!("indexer returned data outside the audit bounds");
                (ErrorCode::InternalError, "indexer response is invalid")
            }
            Derivation(_) | AuditorKey(_) => {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_merge_scan_has_an_explicit_rpc_error() {
        let response =
            ErrorObjectOwned::from(RingRpcError::Origin(AuditError::MergeAuditWorkBudget));
        assert_eq!(response.code(), ErrorCode::InternalError.code());
        assert_eq!(
            response.message(),
            "audit scan exceeded its per-request work budget"
        );
    }
}
