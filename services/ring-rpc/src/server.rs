//! JSON-RPC surface. Same server shape as Photon so one client stack reads both.

use std::{net::SocketAddr, sync::Arc};

use hyper::Method;
use jsonrpsee::{
    server::{middleware::http::ProxyGetRequestLayer, ServerBuilder, ServerHandle},
    types::ErrorObjectOwned,
    RpcModule,
};
use tower_http::cors::{Any, CorsLayer};

use crate::{
    api::{GetDecryptedTransactionsRequest, HealthResponse, GET_DECRYPTED_TRANSACTIONS, HEALTH},
    audit::{AuditService, TransactionSource},
};

pub async fn run_server<S: TransactionSource + 'static>(
    service: Arc<AuditService<S>>,
    port: u16,
) -> Result<ServerHandle, anyhow::Error> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let cors = CorsLayer::new()
        .allow_methods([Method::POST, Method::GET])
        .allow_origin(Any)
        .allow_headers([hyper::header::CONTENT_TYPE]);
    let middleware = tower::ServiceBuilder::new()
        .layer(cors)
        .layer(ProxyGetRequestLayer::new([("/health", HEALTH)])?);
    let server = ServerBuilder::default()
        .set_http_middleware(middleware)
        .build(addr)
        .await?;
    Ok(server.start(rpc_module(service)?))
}

pub fn rpc_module<S: TransactionSource + 'static>(
    service: Arc<AuditService<S>>,
) -> Result<RpcModule<Arc<AuditService<S>>>, anyhow::Error> {
    let mut module = RpcModule::new(service);

    module.register_async_method(HEALTH, |_params, service, _extensions| async move {
        Ok::<_, ErrorObjectOwned>(HealthResponse {
            auditor_view_tag: service.auditor_view_tag().into(),
        })
    })?;

    module.register_async_method(
        GET_DECRYPTED_TRANSACTIONS,
        |params, service, _extensions| async move {
            let request = params.parse::<GetDecryptedTransactionsRequest>()?;
            service
                .decrypted_transactions(request.cursor.map(Into::into), request.limit)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    Ok(module)
}
