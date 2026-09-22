use crate::error::ClientError;
use zolana_indexer_api::error_code::{
    RING_HEAD_MAP_OUT_OF_SYNC, RING_HEAD_MEMBER_ALREADY_REGISTERED, RING_HEAD_MEMBER_UNREGISTERED,
    RING_HEAD_ROOT_CHANGED, RING_KEY_REGISTRY_MEMBER_ALREADY_REGISTERED,
    RING_KEY_REGISTRY_MEMBER_UNREGISTERED, RING_KEY_REGISTRY_OUT_OF_SYNC,
    RING_KEY_REGISTRY_ROOT_CHANGED,
};

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
            code: Some(code), ..
        } => match code {
            RING_HEAD_MAP_OUT_OF_SYNC => ClientError::RingHeadMapOutOfSync,
            RING_HEAD_ROOT_CHANGED => ClientError::RingHeadRootChanged,
            RING_HEAD_MEMBER_UNREGISTERED => ClientError::RingHeadMemberUnregistered,
            RING_HEAD_MEMBER_ALREADY_REGISTERED => ClientError::RingHeadMemberAlreadyRegistered,
            RING_KEY_REGISTRY_OUT_OF_SYNC => ClientError::RingKeyRegistryOutOfSync,
            RING_KEY_REGISTRY_ROOT_CHANGED => ClientError::RingKeyRegistryRootChanged,
            RING_KEY_REGISTRY_MEMBER_UNREGISTERED => ClientError::RingKeyRegistryMemberUnregistered,
            RING_KEY_REGISTRY_MEMBER_ALREADY_REGISTERED => {
                ClientError::RingKeyRegistryMemberAlreadyRegistered
            }
            JSON_RPC_INTERNAL_ERROR => ClientError::IndexerUnavailable(message),
            _ => ClientError::Indexer(message),
        },
        _ => ClientError::Indexer(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_ring_projection_error_codes() {
        let cases = [
            (RING_HEAD_MAP_OUT_OF_SYNC, ClientError::RingHeadMapOutOfSync),
            (RING_HEAD_ROOT_CHANGED, ClientError::RingHeadRootChanged),
            (
                RING_HEAD_MEMBER_UNREGISTERED,
                ClientError::RingHeadMemberUnregistered,
            ),
            (
                RING_HEAD_MEMBER_ALREADY_REGISTERED,
                ClientError::RingHeadMemberAlreadyRegistered,
            ),
            (
                RING_KEY_REGISTRY_OUT_OF_SYNC,
                ClientError::RingKeyRegistryOutOfSync,
            ),
            (
                RING_KEY_REGISTRY_ROOT_CHANGED,
                ClientError::RingKeyRegistryRootChanged,
            ),
            (
                RING_KEY_REGISTRY_MEMBER_UNREGISTERED,
                ClientError::RingKeyRegistryMemberUnregistered,
            ),
            (
                RING_KEY_REGISTRY_MEMBER_ALREADY_REGISTERED,
                ClientError::RingKeyRegistryMemberAlreadyRegistered,
            ),
        ];
        for (code, expected) in cases {
            let actual = indexer_error(zolana_api::ApiError::JsonRpc {
                method: "ringMethod",
                code: Some(code),
                message: Some("projection error".into()),
            });
            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(&expected),
                "code {code}"
            );
        }
    }
}
