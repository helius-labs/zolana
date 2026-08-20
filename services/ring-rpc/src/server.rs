//! HTTP surface: the JSON-RPC methods, `GET /health` and `GET /ready`.

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use hyper::{header::CONTENT_TYPE, Method, StatusCode};
use jsonrpsee::{
    core::BoxError,
    server::{
        middleware::http::ProxyGetRequestLayer, HttpBody, HttpRequest, HttpResponse, ServerBuilder,
        ServerConfig, ServerHandle,
    },
    types::{ErrorCode, ErrorObjectOwned},
    RpcModule,
};
use log::error;
use tower::{Layer, Service};
use tower_http::cors::{AllowOrigin, CorsLayer};

use solana_address::Address;
use solana_signer::Signer;
use zeroize::Zeroizing;
use zolana_indexer_api::Base64String;

use crate::{
    api::{
        auditor_key_attestation, CreateAuditorKeyRequest, CreateAuditorKeyResponse,
        GetDecryptedTransactionsRequest, HealthResponse, ProveAuditorKeyEncryptionRequest,
        ProveAuditorKeyEncryptionResponse, CREATE_AUDITOR_KEY, GET_DECRYPTED_TRANSACTIONS, HEALTH,
        PROVE_AUDITOR_KEY_ENCRYPTION,
    },
    audit::{Hub, TransactionSource},
    prove::{prove_auditor_key_encryption, AuditProveError, AuditWitness},
};

pub struct ServerOptions {
    pub bind: IpAddr,
    pub port: u16,
    pub allow_origins: Vec<String>,
    pub max_connections: u32,
    pub request_timeout: Duration,
}

pub async fn run_server<S: TransactionSource + 'static>(
    hub: Arc<Hub<S>>,
    options: ServerOptions,
) -> Result<ServerHandle, anyhow::Error> {
    let addr = SocketAddr::from((options.bind, options.port));
    let middleware = tower::ServiceBuilder::new()
        .layer(cors(&options.allow_origins)?)
        .layer(tower::timeout::TimeoutLayer::new(options.request_timeout))
        .layer(ReadyLayer { hub: hub.clone() })
        .layer(ProxyGetRequestLayer::new([("/health", HEALTH)])?);
    let server = ServerBuilder::default()
        .set_config(
            ServerConfig::builder()
                .max_connections(options.max_connections)
                .build(),
        )
        .set_http_middleware(middleware)
        .build(addr)
        .await?;
    Ok(server.start(rpc_module(hub)?))
}

/// Cross-origin calls are opt-in per origin.
fn cors(origins: &[String]) -> Result<CorsLayer, anyhow::Error> {
    if origins.is_empty() {
        return Ok(CorsLayer::new());
    }
    let parsed = origins
        .iter()
        .map(|origin| origin.parse())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(parsed))
        .allow_methods([Method::POST, Method::GET])
        .allow_headers([CONTENT_TYPE]))
}

pub fn rpc_module<S: TransactionSource + 'static>(
    hub: Arc<Hub<S>>,
) -> Result<RpcModule<Arc<Hub<S>>>, anyhow::Error> {
    let mut module = RpcModule::new(hub);

    module.register_async_method(HEALTH, |_params, hub, _extensions| async move {
        Ok::<_, ErrorObjectOwned>(HealthResponse {
            mode: if hub.is_derived() { "derived" } else { "local" }.to_owned(),
            service_pubkey: hub.signer().pubkey().into(),
            auditor_view_tag: hub
                .local_service()
                .map(|service| service.auditor_view_tag().into()),
        })
    })?;

    module.register_async_method(CREATE_AUDITOR_KEY, |params, hub, _extensions| async move {
        let request = params.parse::<CreateAuditorKeyRequest>()?;
        let ring = request.ring_program_id.0;
        let service = hub.ring(Some(ring)).map_err(ErrorObjectOwned::from)?;
        let auditor_pubkey = service.auditor_pubkey().as_bytes().to_vec();
        let signature = hub
            .signer()
            .sign_message(&auditor_key_attestation(&ring, &auditor_pubkey));
        Ok::<_, ErrorObjectOwned>(CreateAuditorKeyResponse {
            ring_program_id: ring.into(),
            auditor_pubkey: auditor_pubkey.into(),
            auditor_view_tag: service.auditor_view_tag().into(),
            service_pubkey: hub.signer().pubkey().into(),
            signature: signature.into(),
        })
    })?;

    module.register_async_method(
        GET_DECRYPTED_TRANSACTIONS,
        |params, hub, _extensions| async move {
            let request = params.parse::<GetDecryptedTransactionsRequest>()?;
            let service = hub
                .ring(request.ring_program_id.map(|ring| ring.0))
                .map_err(ErrorObjectOwned::from)?;
            let cursor: Option<Vec<u8>> = request.cursor.map(Into::into);
            let filter = service
                .authorize_read(&request.auth, cursor.as_deref(), request.limit.clone())
                .await
                .map_err(ErrorObjectOwned::from)?;
            service
                .decrypted_transactions(cursor, request.limit, &filter)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    module.register_async_method(
        PROVE_AUDITOR_KEY_ENCRYPTION,
        |params, hub, _extensions| async move {
            let request = params.parse::<ProveAuditorKeyEncryptionRequest>()?;
            let service = hub
                .ring(request.ring_program_id.map(|ring| ring.0))
                .map_err(ErrorObjectOwned::from)?;
            let witness = AuditWitness {
                private_tx_hash: scalar(request.private_tx_hash, "private_tx_hash")?,
                tx_viewing_sk: Zeroizing::new(scalar(request.tx_viewing_sk, "tx_viewing_sk")?),
                eph_sk: Zeroizing::new(scalar(request.eph_sk, "eph_sk")?),
            };
            let auditor_pk = service.auditor_pubkey();
            // Proving blocks for seconds.
            let proof = tokio::task::spawn_blocking(move || {
                prove_auditor_key_encryption(&witness, &auditor_pk)
            })
            .await
            .map_err(|_| internal_error("audit prover task failed"))?
            .map_err(|error| match error {
                AuditProveError::Scalar(_) | AuditProveError::Encryption(_) => {
                    invalid_params(error.to_string())
                }
                other => {
                    error!("audit proof failed: {other}");
                    internal_error("audit proof failed")
                }
            })?;
            let bytes = wincode::serialize(&proof)
                .map_err(|_| internal_error("audit proof serialization failed"))?;
            Ok::<_, ErrorObjectOwned>(ProveAuditorKeyEncryptionResponse {
                proof: bytes.into(),
            })
        },
    )?;

    Ok(module)
}

fn scalar(value: Base64String, name: &str) -> Result<[u8; 32], ErrorObjectOwned> {
    <[u8; 32]>::try_from(value.0).map_err(|_| invalid_params(format!("{name} must be 32 bytes")))
}

fn invalid_params(message: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InvalidParams.code(), message, None::<()>)
}

fn internal_error(message: &str) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InternalError.code(), message, None::<()>)
}

/// Answers readiness on `GET /ready` and hands every other request to the
/// JSON-RPC server. Readiness stays outside the JSON-RPC proxy because a failing
/// probe must answer with a non-200 status.
struct ReadyLayer<S> {
    hub: Arc<Hub<S>>,
}

impl<S, Inner> Layer<Inner> for ReadyLayer<S> {
    type Service = ReadyService<S, Inner>;

    fn layer(&self, inner: Inner) -> Self::Service {
        ReadyService {
            inner,
            hub: self.hub.clone(),
        }
    }
}

struct ReadyService<S, Inner> {
    inner: Inner,
    hub: Arc<Hub<S>>,
}

impl<S, Inner: Clone> Clone for ReadyService<S, Inner> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            hub: self.hub.clone(),
        }
    }
}

impl<S, Inner, B> Service<HttpRequest<B>> for ReadyService<S, Inner>
where
    S: TransactionSource + 'static,
    Inner: Service<HttpRequest<B>, Response = HttpResponse>,
    Inner::Error: Into<BoxError> + 'static,
    Inner::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = HttpResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: HttpRequest<B>) -> Self::Future {
        if request.method() == Method::GET && request.uri().path() == "/ready" {
            let hub = self.hub.clone();
            return Box::pin(async move { Ok(readiness(&hub).await) });
        }
        let future = self.inner.call(request);
        Box::pin(async move { future.await.map_err(Into::into) })
    }
}

async fn readiness<S: TransactionSource>(hub: &Hub<S>) -> HttpResponse {
    // Any ring probes the same indexer; the local key or an arbitrary ring.
    let service = match hub.local_service() {
        Some(service) => Ok(service),
        None => hub.ring(Some(Address::default())),
    };
    let probe = match service {
        Ok(service) => service.probe_indexer().await,
        Err(error) => Err(error),
    };
    match probe {
        Ok(slot) => text_response(StatusCode::OK, format!("ready, indexer slot {slot}")),
        Err(error) => text_response(StatusCode::SERVICE_UNAVAILABLE, error.to_string()),
    }
}

fn text_response(status: StatusCode, body: String) -> HttpResponse {
    hyper::Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(HttpBody::from(body))
        .expect("static response parts are valid")
}
