use std::net::SocketAddr;

use hyper::Method;
use jsonrpsee::{
    server::{middleware::http::ProxyGetRequestLayer, ServerBuilder, ServerConfig, ServerHandle},
    types::ErrorObjectOwned,
    RpcModule,
};
use log::debug;
use tower_http::cors::{Any, CorsLayer};

use super::api::PhotonApi;

pub async fn run_server(
    api: PhotonApi,
    port: u16,
    max_connections: u32,
) -> Result<ServerHandle, anyhow::Error> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let cors = CorsLayer::new()
        .allow_methods([Method::POST, Method::GET])
        .allow_origin(Any)
        .allow_headers([hyper::header::CONTENT_TYPE]);
    let middleware = tower::ServiceBuilder::new()
        .layer(cors)
        .layer(ProxyGetRequestLayer::new([
            ("/liveness", "liveness"),
            ("/readiness", "readiness"),
        ])?);
    let server = ServerBuilder::default()
        .set_config(
            ServerConfig::builder()
                .max_connections(max_connections)
                .build(),
        )
        .set_http_middleware(middleware)
        .build(addr)
        .await?;
    let rpc_module = build_rpc_module(api)?;
    Ok(server.start(rpc_module))
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
        "get_encrypted_utxos_by_tags",
        |rpc_params, rpc_context, _extensions| async move {
            let api = rpc_context.as_ref();
            let payload = rpc_params.parse()?;
            api.get_encrypted_utxos_by_tags(payload)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        "get_shielded_transactions_by_tags",
        |rpc_params, rpc_context, _extensions| async move {
            let api = rpc_context.as_ref();
            let payload = rpc_params.parse()?;
            api.get_shielded_transactions_by_tags(payload)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        "get_merkle_proofs",
        |rpc_params, rpc_context, _extensions| async move {
            let api = rpc_context.as_ref();
            let payload = rpc_params.parse()?;
            api.get_merkle_proofs(payload)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        "get_non_inclusion_proofs",
        |rpc_params, rpc_context, _extensions| async move {
            let api = rpc_context.as_ref();
            let payload = rpc_params.parse()?;
            api.get_non_inclusion_proofs(payload)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        "get_nullifier_queue_elements",
        |rpc_params, rpc_context, _extensions| async move {
            let api = rpc_context.as_ref();
            let payload = rpc_params.parse()?;
            api.get_nullifier_queue_elements(payload)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    Ok(module)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;
    use solana_client::nonblocking::rpc_client::RpcClient;
    use std::sync::Arc;

    #[tokio::test]
    async fn registers_only_rings_product_methods() {
        let module = build_rpc_module(test_api().await).unwrap();
        let methods = module.method_names().collect::<Vec<_>>();

        assert!(methods.contains(&"liveness"));
        assert!(methods.contains(&"readiness"));
        assert!(methods.contains(&"getIndexerHealth"));
        assert!(methods.contains(&"getIndexerSlot"));
        assert!(methods.contains(&"get_encrypted_utxos_by_tags"));
        assert!(methods.contains(&"get_shielded_transactions_by_tags"));
        assert!(methods.contains(&"get_merkle_proofs"));
        assert!(methods.contains(&"get_non_inclusion_proofs"));
        assert!(methods.contains(&"get_nullifier_queue_elements"));
    }

    async fn test_api() -> PhotonApi {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        PhotonApi::new(
            Arc::new(db),
            Arc::new(RpcClient::new("http://127.0.0.1:8899".to_string())),
        )
    }
}
