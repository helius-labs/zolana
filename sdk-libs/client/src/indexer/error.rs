use crate::error::ClientError;
use zolana_indexer_api::error_code::{
    RING_KEY_REGISTRY_MEMBER_ALREADY_REGISTERED, RING_KEY_REGISTRY_MEMBER_UNREGISTERED,
    RING_KEY_REGISTRY_OUT_OF_SYNC, RING_KEY_REGISTRY_ROOT_CHANGED, RING_SPEND_RECORD_OUT_OF_SYNC,
};

const JSON_RPC_METHOD_NOT_FOUND: i64 = -32601;
const JSON_RPC_INTERNAL_ERROR: i64 = -32603;

/// Split indexer failures into the ones worth polling through and the ones that
/// will never succeed. Photon reports both a transient database failure and a
/// permanent internal bug as `-32603` with the body scrubbed, so `-32603` is
/// retried and the caller is handed the last one it saw rather than a bare
/// timeout.
///
/// Every indexer call is a read, so a request that got no usable response is
/// retried whatever the transport: a `reqwest` timeout, connection failure or
/// request the connection dropped (such as a pooled keep-alive connection the
/// server closed), a custom HTTP client that failed without a response, and a
/// response lost while reading its body.
///
/// The message comes from `ApiError`'s display, which masks the `api-key`.
pub(super) fn indexer_error(error: zolana_api::ApiError) -> ClientError {
    let message = error.to_string();
    match error {
        #[cfg(feature = "reqwest")]
        zolana_api::ApiError::Request(error)
            if error.is_timeout() || error.is_connect() || error.is_request() =>
        {
            ClientError::IndexerUnavailable(message)
        }
        zolana_api::ApiError::HttpClient(_) | zolana_api::ApiError::ResponseLost(_) => {
            ClientError::IndexerUnavailable(message)
        }
        zolana_api::ApiError::Response { status, .. }
            if status == http::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() =>
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
            RING_KEY_REGISTRY_OUT_OF_SYNC => ClientError::RingKeyRegistryOutOfSync,
            RING_KEY_REGISTRY_ROOT_CHANGED => ClientError::RingKeyRegistryRootChanged,
            RING_KEY_REGISTRY_MEMBER_UNREGISTERED => ClientError::RingKeyRegistryMemberUnregistered,
            RING_KEY_REGISTRY_MEMBER_ALREADY_REGISTERED => {
                ClientError::RingKeyRegistryMemberAlreadyRegistered
            }
            RING_SPEND_RECORD_OUT_OF_SYNC => ClientError::RingSpendRecordOutOfSync,
            JSON_RPC_INTERNAL_ERROR => ClientError::IndexerUnavailable(message),
            _ => ClientError::Indexer(message),
        },
        _ => ClientError::Indexer(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connection the server drops before it answers, the way a pooled
    /// keep-alive connection it closed while idle fails, is a request error
    /// that is neither a timeout nor a connection failure, and is retried.
    #[cfg(feature = "reqwest")]
    #[tokio::test]
    async fn retries_a_request_the_connection_dropped() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            drop(stream);
        });
        let error = reqwest::Client::new().get(url).send().await.unwrap_err();
        assert!(error.is_request() && !error.is_timeout() && !error.is_connect());
        assert!(matches!(
            indexer_error(zolana_api::ApiError::Request(error)),
            ClientError::IndexerUnavailable(_)
        ));
    }

    #[test]
    fn preserves_ring_projection_error_codes() {
        let cases = [
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
            (
                RING_SPEND_RECORD_OUT_OF_SYNC,
                ClientError::RingSpendRecordOutOfSync,
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

    #[test]
    fn retries_a_custom_client_that_got_no_response() {
        let error = indexer_error(zolana_api::ApiError::HttpClient("offline".into()));
        assert!(
            matches!(&error, ClientError::IndexerUnavailable(message) if message.contains("offline")),
            "{error:?}"
        );
        let error = indexer_error(zolana_api::ApiError::ResponseLost("reset".into()));
        assert!(
            matches!(&error, ClientError::IndexerUnavailable(message) if message.contains("reset")),
            "{error:?}"
        );
    }

    #[test]
    fn a_custom_client_failure_keeps_the_api_key_out() {
        let error = indexer_error(zolana_api::ApiError::HttpClient(
            "connect error for https://gw/v1?api-key=SECRET".into(),
        ));
        let message = error.to_string();
        assert!(!message.contains("SECRET"), "{message}");
        assert!(
            message.contains("https://gw/v1?api-key=redacted"),
            "{message}"
        );
    }
}
