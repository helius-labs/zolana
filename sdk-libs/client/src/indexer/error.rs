use crate::error::ClientError;

const JSON_RPC_METHOD_NOT_FOUND: i64 = -32601;
const JSON_RPC_INTERNAL_ERROR: i64 = -32603;

/// Split indexer failures into the ones worth polling through and the ones that
/// will never succeed. Photon reports both a transient database failure and a
/// permanent internal bug as `-32603` with the body scrubbed, so `-32603` is
/// retried and the caller is handed the last one it saw rather than a bare
/// timeout.
pub(super) fn indexer_error(error: zolana_api::ApiError) -> ClientError {
    let message = error.to_string();
    match error {
        zolana_api::ApiError::Request(error) if error.is_timeout() || error.is_connect() => {
            ClientError::IndexerUnavailable(message)
        }
        zolana_api::ApiError::Response { status, .. }
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() =>
        {
            ClientError::IndexerUnavailable(message)
        }
        zolana_api::ApiError::JsonRpc {
            method,
            code: Some(JSON_RPC_METHOD_NOT_FOUND),
            ..
        } => ClientError::UnsupportedRpcMethod(method),
        zolana_api::ApiError::JsonRpc {
            code: Some(JSON_RPC_INTERNAL_ERROR),
            ..
        } => ClientError::IndexerUnavailable(message),
        _ => ClientError::Indexer(message),
    }
}
