use std::net::SocketAddr;

use hyper::Method;
use jsonrpsee::{
    core::TEN_MB_SIZE_BYTES,
    server::{middleware::http::ProxyGetRequestLayer, ServerBuilder, ServerConfig, ServerHandle},
    types::ErrorObjectOwned,
    RpcModule,
};
use log::debug;
use tower_http::cors::{Any, CorsLayer};
use zolana_indexer_api::{
    method::{
        GetEncryptedUtxosByTags, GetMerkleProofs, GetNonInclusionProofs, GetNullifierQueueElements,
        GetShieldedTransactionsByNullifiers, GetShieldedTransactionsBySignature,
        GetShieldedTransactionsByTags, GetUserRecords,
    },
    RpcMethod,
};
use zolana_rpc_http::MethodPathLayer;

use super::service::PhotonApi;

pub async fn run_server(
    api: PhotonApi,
    port: u16,
    max_connections: u32,
) -> Result<ServerHandle, anyhow::Error> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    Ok(start_server(api, addr, max_connections).await?.1)
}

async fn start_server(
    api: PhotonApi,
    addr: SocketAddr,
    max_connections: u32,
) -> Result<(SocketAddr, ServerHandle), anyhow::Error> {
    let cors = CorsLayer::new()
        .allow_methods([Method::POST, Method::GET])
        .allow_origin(Any)
        .allow_headers([hyper::header::CONTENT_TYPE]);
    let middleware = tower::ServiceBuilder::new()
        .layer(cors)
        .layer(ProxyGetRequestLayer::new([
            ("/liveness", "liveness"),
            ("/readiness", "readiness"),
        ])?)
        .layer(MethodPathLayer {
            max_body_size: TEN_MB_SIZE_BYTES as usize,
        });
    let server = ServerBuilder::default()
        .set_config(
            ServerConfig::builder()
                .max_connections(max_connections)
                .max_request_body_size(TEN_MB_SIZE_BYTES)
                .build(),
        )
        .set_http_middleware(middleware)
        .build(addr)
        .await?;
    let rpc_module = build_rpc_module(api)?;
    Ok((server.local_addr()?, server.start(rpc_module)))
}

fn build_rpc_module(api_and_indexer: PhotonApi) -> Result<RpcModule<PhotonApi>, anyhow::Error> {
    let mut module = RpcModule::new(api_and_indexer);

    module.register_async_method(
        "liveness",
        |_rpc_params, rpc_context, _extensions| async move {
            debug!("Checking Liveness");
            let api = rpc_context.as_ref();
            api.liveness().await.map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        "readiness",
        |_rpc_params, rpc_context, _extensions| async move {
            debug!("Checking Readiness");
            let api = rpc_context.as_ref();
            api.readiness().await.map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        "getIndexerHealth",
        |_rpc_params, rpc_context, _extensions| async move {
            rpc_context
                .as_ref()
                .get_indexer_health()
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        "getIndexerSlot",
        |_rpc_params, rpc_context, _extensions| async move {
            let api = rpc_context.as_ref();
            api.get_indexer_slot().await.map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        GetEncryptedUtxosByTags::NAME,
        |rpc_params, rpc_context, _extensions| async move {
            let api = rpc_context.as_ref();
            let payload = rpc_params.parse()?;
            api.get_encrypted_utxos_by_tags(payload)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        GetShieldedTransactionsBySignature::NAME,
        |rpc_params, rpc_context, _extensions| async move {
            let api = rpc_context.as_ref();
            let payload = rpc_params.parse()?;
            api.get_shielded_transactions_by_signature(payload)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        GetShieldedTransactionsByTags::NAME,
        |rpc_params, rpc_context, _extensions| async move {
            let api = rpc_context.as_ref();
            let payload = rpc_params.parse()?;
            api.get_shielded_transactions_by_tags(payload)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        GetShieldedTransactionsByNullifiers::NAME,
        |rpc_params, rpc_context, _extensions| async move {
            let api = rpc_context.as_ref();
            let payload = rpc_params.parse()?;
            api.get_shielded_transactions_by_nullifiers(payload)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        GetMerkleProofs::NAME,
        |rpc_params, rpc_context, _extensions| async move {
            let api = rpc_context.as_ref();
            let payload = rpc_params.parse()?;
            api.get_merkle_proofs(payload)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        GetNonInclusionProofs::NAME,
        |rpc_params, rpc_context, _extensions| async move {
            let api = rpc_context.as_ref();
            let payload = rpc_params.parse()?;
            api.get_non_inclusion_proofs(payload)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        GetNullifierQueueElements::NAME,
        |rpc_params, rpc_context, _extensions| async move {
            let api = rpc_context.as_ref();
            let payload = rpc_params.parse()?;
            api.get_nullifier_queue_elements(payload)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        GetUserRecords::NAME,
        |rpc_params, rpc_context, _extensions| async move {
            let api = rpc_context.as_ref();
            let payload = rpc_params.parse()?;
            api.get_user_records(payload)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    Ok(module)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::RpcClient;
    use sea_orm::Database;
    use std::sync::Arc;

    #[tokio::test]
    async fn method_paths_reject_other_methods_and_batches_but_preserve_root_rpc_and_health() {
        let (addr, server) = start_server(test_api().await, "127.0.0.1:0".parse().unwrap(), 10)
            .await
            .unwrap();
        let client = reqwest::Client::new();
        let url = format!("http://{addr}");
        for body in [
            r#"{"jsonrpc":"2.0","method":"getNullifierQueueElements","id":7}"#,
            r#"[{"jsonrpc":"2.0","method":"getUserRecords","id":7}]"#,
            r#"{"method":"getUserRecords","method":"getMerkleProofs","id":7}"#,
            r#"{"method":"getMerkleProofs","method":"getUserRecords","id":7}"#,
        ] {
            let response = client
                .post(format!("{url}/v1/zolana/getUserRecords/"))
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                reqwest::StatusCode::BAD_REQUEST,
                "{body}"
            );
            let answer: serde_json::Value = response.json().await.unwrap();
            assert_eq!(answer["error"]["code"], -32601, "{body}");
        }
        for method in [
            GetEncryptedUtxosByTags::NAME,
            GetShieldedTransactionsBySignature::NAME,
            GetShieldedTransactionsByTags::NAME,
            GetShieldedTransactionsByNullifiers::NAME,
            GetMerkleProofs::NAME,
            GetNonInclusionProofs::NAME,
            GetNullifierQueueElements::NAME,
            GetUserRecords::NAME,
        ] {
            let response = client
                .post(format!("{url}/v1/zolana/{method}?q=%61"))
                .json(&serde_json::json!({"jsonrpc":"2.0", "method":method, "id":7}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK, "{method}");
            let answer: serde_json::Value = response.json().await.unwrap();
            // Missing parameters reach the named RPC handler, which rejects them.
            assert_eq!(answer["error"]["code"], -32602, "{method}: {answer}");
        }
        let response = client
            .post(format!("{url}/"))
            .json(&serde_json::json!([
                {"jsonrpc":"2.0", "method":"liveness", "id":1},
                {"jsonrpc":"2.0", "method":"readiness", "id":2},
            ]))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let answers: Vec<serde_json::Value> = response.json().await.unwrap();
        assert_eq!(answers.len(), 2);
        assert!(answers.iter().all(|answer| answer.get("error").is_none()));
        for path in ["liveness", "readiness"] {
            let response = client.get(format!("{url}/{path}")).send().await.unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK);
        }
        server.stop().unwrap();
        server.stopped().await;
    }

    #[tokio::test]
    async fn registers_the_rings_product_methods() {
        let module = build_rpc_module(test_api().await).unwrap();
        let methods = module.method_names().collect::<Vec<_>>();

        assert!(methods.contains(&"liveness"));
        assert!(methods.contains(&"readiness"));
        assert!(methods.contains(&"getIndexerHealth"));
        assert!(methods.contains(&"getIndexerSlot"));
        assert!(methods.contains(&"getEncryptedUtxosByTags"));
        assert!(methods.contains(&"getShieldedTransactionsBySignature"));
        assert!(methods.contains(&"getShieldedTransactionsByTags"));
        assert!(methods.contains(&"getMerkleProofs"));
        assert!(methods.contains(&"getNonInclusionProofs"));
        assert!(methods.contains(&"getNullifierQueueElements"));
        assert!(methods.contains(&"getUserRecords"));
    }

    async fn test_api() -> PhotonApi {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        PhotonApi::new(
            Arc::new(db),
            Arc::new(RpcClient::new("http://127.0.0.1:8899".to_string())),
        )
    }
}
