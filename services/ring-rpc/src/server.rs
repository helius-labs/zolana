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
    core::{BoxError, RegisterMethodError},
    server::{
        middleware::http::{ProxyGetRequestError, ProxyGetRequestLayer},
        BatchRequestConfig, HttpBody, HttpRequest, HttpResponse, ServerBuilder, ServerConfig,
        ServerHandle,
    },
    types::ErrorObjectOwned,
    RpcModule,
};
use thiserror::Error;
use tower::{Layer, Service};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::{
    api::{
        auditor_key_attestation, CreateAuditorKeyRequest, CreateAuditorKeyResponse,
        GetDecryptedTransactionsRequest, HealthResponse, RingDepositsRequest, RingDepositsResponse,
        RingState, RingStatusRequest, RingStatusResponse, CREATE_AUDITOR_KEY,
        GET_DECRYPTED_TRANSACTIONS, HEALTH, RING_DEPOSITS, RING_STATUS,
    },
    audit::{AuditRead, PageOptions},
    hub::{Hub, ReadinessStatus},
    limits::PublicRequest,
    origins::{OriginError, Origins},
    upstream::{DepositPage, TransactionSource},
};

const MAX_REQUEST_BODY_SIZE: u32 = 64 * 1024;
const MAX_RESPONSE_BODY_SIZE: u32 = 16 * 1024 * 1024;

/// Only a loopback bind keeps the decrypted audit data behind a TLS proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindPolicy {
    LoopbackOnly,
    InsecurePublic,
}

pub struct ServerOptions {
    pub bind: IpAddr,
    pub bind_policy: BindPolicy,
    pub port: u16,
    pub max_connections: u32,
    pub request_timeout: Duration,
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("ring RPC must bind to a loopback address")]
    PublicBind,
    #[error(transparent)]
    Origin(#[from] OriginError),
    #[error("health proxy setup failed")]
    Proxy(#[from] ProxyGetRequestError),
    #[error("RPC listener setup failed")]
    Listener(#[from] std::io::Error),
    #[error("RPC method setup failed")]
    Method(#[from] RegisterMethodError),
}

pub async fn run_server<S: TransactionSource + 'static>(
    hub: Arc<Hub<S>>,
    options: ServerOptions,
) -> Result<ServerHandle, ServerError> {
    if options.bind_policy == BindPolicy::LoopbackOnly && !options.bind.is_loopback() {
        return Err(ServerError::PublicBind);
    }
    let addr = SocketAddr::from((options.bind, options.port));
    let middleware = tower::ServiceBuilder::new()
        .layer(cors(hub.origins())?)
        .layer(tower::timeout::TimeoutLayer::new(options.request_timeout))
        .layer(ReadyLayer { hub: hub.clone() })
        .layer(ProxyGetRequestLayer::new([("/health", HEALTH)])?);
    let server = ServerBuilder::default()
        .set_config(
            ServerConfig::builder()
                .max_connections(options.max_connections)
                .max_request_body_size(MAX_REQUEST_BODY_SIZE)
                .max_response_body_size(MAX_RESPONSE_BODY_SIZE)
                .set_batch_request_config(BatchRequestConfig::Disabled)
                .build(),
        )
        .set_http_middleware(middleware)
        .build(addr)
        .await?;
    Ok(server.start(rpc_module(hub)?))
}

fn cors(origins: &Origins) -> Result<CorsLayer, OriginError> {
    if origins.is_empty() {
        return Ok(CorsLayer::new());
    }
    let allow = if origins.allows_any() {
        AllowOrigin::any()
    } else {
        AllowOrigin::list(origins.header_values()?)
    };
    Ok(CorsLayer::new()
        .allow_origin(allow)
        .allow_methods([Method::POST, Method::GET])
        .allow_headers([CONTENT_TYPE]))
}

pub fn rpc_module<S: TransactionSource + 'static>(
    hub: Arc<Hub<S>>,
) -> Result<RpcModule<Arc<Hub<S>>>, RegisterMethodError> {
    let mut module = RpcModule::new(hub);

    module.register_async_method(HEALTH, |_params, hub, _extensions| async move {
        Ok::<_, ErrorObjectOwned>(HealthResponse {
            mode: hub.mode(),
            service_pubkey: hub.service_pubkey().into(),
        })
    })?;

    module.register_async_method(CREATE_AUDITOR_KEY, |params, hub, _extensions| async move {
        let request = params.parse::<CreateAuditorKeyRequest>()?;
        hub.accept_authentication()
            .map_err(ErrorObjectOwned::from)?;
        let _authentication = hub.authentication_slot().map_err(ErrorObjectOwned::from)?;
        let ring = request.ring_program_id.0;
        let service = hub.service_for(ring).map_err(ErrorObjectOwned::from)?;
        service
            .authorize_auditor_key(&request.auth)
            .await
            .map_err(ErrorObjectOwned::from)?;
        let ring = service.ring();
        let auditor_pubkey = service.auditor_pubkey();
        let signature = hub.sign_attestation(&auditor_key_attestation(&ring, &auditor_pubkey));
        Ok::<_, ErrorObjectOwned>(CreateAuditorKeyResponse {
            ring_program_id: ring.into(),
            auditor_pubkey: auditor_pubkey.into(),
            auditor_view_tag: service.auditor_view_tag().into(),
            service_pubkey: hub.service_pubkey().into(),
            signature: signature.into(),
        })
    })?;

    module.register_async_method(RING_DEPOSITS, |params, hub, _extensions| async move {
        let request = params.parse::<RingDepositsRequest>()?;
        let limit = request.page_limit();
        let before = request.before().map_err(ErrorObjectOwned::from)?;
        hub.validate_ring(request.ring_program_id.0)
            .map_err(ErrorObjectOwned::from)?;
        hub.accept_public(PublicRequest::DepositScan { signatures: limit })
            .map_err(ErrorObjectOwned::from)?;
        let _scan = hub.deposit_slot().map_err(ErrorObjectOwned::from)?;
        let service = hub
            .service_for(request.ring_program_id.0)
            .map_err(ErrorObjectOwned::from)?;
        let history = hub
            .ring_deposits(DepositPage {
                ring: service.ring(),
                limit,
                before,
            })
            .await
            .map_err(ErrorObjectOwned::from)?;
        Ok::<_, ErrorObjectOwned>(RingDepositsResponse::from(history))
    })?;

    module.register_async_method(RING_STATUS, |params, hub, _extensions| async move {
        let request = params.parse::<RingStatusRequest>()?;
        hub.accept_public(PublicRequest::Standard)
            .map_err(ErrorObjectOwned::from)?;
        let ring = request.ring_program_id.0;
        let service = hub.service_for(ring).map_err(ErrorObjectOwned::from)?;
        let auditor_pubkey = service.auditor_pubkey();
        let configured = service
            .configured_auditor()
            .await
            .map_err(ErrorObjectOwned::from)?;
        let state = match configured {
            None => RingState::Uninitialized,
            Some(key) if key == auditor_pubkey => RingState::Served,
            Some(_) => RingState::ForeignAuditor,
        };
        Ok::<_, ErrorObjectOwned>(RingStatusResponse {
            ring_program_id: service.ring().into(),
            state,
            config_auditor_pubkey: configured.map(Into::into),
            service_pubkey: hub.service_pubkey().into(),
        })
    })?;

    module.register_async_method(
        GET_DECRYPTED_TRANSACTIONS,
        |params, hub, _extensions| async move {
            let request = params.parse::<GetDecryptedTransactionsRequest>()?;
            hub.accept_authentication()
                .map_err(ErrorObjectOwned::from)?;
            let authentication = hub.authentication_slot().map_err(ErrorObjectOwned::from)?;
            let service = match request.ring_program_id {
                Some(ring) => hub.service_for(ring.0),
                None => hub.service(),
            }
            .map_err(ErrorObjectOwned::from)?;
            let mut page = PageOptions::default();
            if let Some(since) = &request.since {
                page = page.with_since(since);
            }
            if let Some(limit) = request.limit {
                page = page.with_limit(limit).map_err(ErrorObjectOwned::from)?;
            }
            let page = page.build().map_err(ErrorObjectOwned::from)?;
            let read = service
                .authorize(AuditRead {
                    auth: &request.auth,
                    page: &page,
                })
                .await
                .map_err(ErrorObjectOwned::from)?;
            drop(authentication);
            hub.accept_audit().map_err(ErrorObjectOwned::from)?;
            let _slot = hub.read_slot().map_err(ErrorObjectOwned::from)?;
            read.execute().await.map_err(ErrorObjectOwned::from)
        },
    )?;

    Ok(module)
}

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

async fn readiness<S: TransactionSource + 'static>(hub: &Arc<Hub<S>>) -> HttpResponse {
    match hub.readiness().await {
        ReadinessStatus::Ready => text_response(StatusCode::OK, "ready"),
        ReadinessStatus::Unavailable(check) => {
            text_response(StatusCode::SERVICE_UNAVAILABLE, check)
        }
    }
}

fn text_response(status: StatusCode, body: &'static str) -> HttpResponse {
    let mut response = hyper::Response::new(HttpBody::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        net::Ipv4Addr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use solana_address::Address;
    use solana_signature::Signature;
    use zolana_client::{ClientError, GetShieldedTransactionsByTagsResponse};
    use zolana_keypair::ViewingKey;
    use zolana_ring_client::{OriginError, RingOrigin};
    use zolana_transaction::AssetRegistry;

    use crate::{
        api::DEPOSITS_PAGE_LIMIT,
        config::RootSecret,
        error::RingRpcError,
        keys::KeyMode,
        limits::{
            MAX_CONCURRENT_AUTHENTICATIONS, MAX_CONCURRENT_DEPOSIT_SCANS, MAX_CONCURRENT_READS,
            MAX_REQUEST_UNITS_PER_SECOND,
        },
        origins::OriginPolicy,
        upstream::{DepositHistory, ReaderGrant, RingConfiguration, TransactionPage},
    };

    use super::*;

    const SERVED_RING: Address = Address::new_from_array([8; 32]);
    const TEST_GENESIS: [u8; 32] = [3; 32];

    struct TestSource {
        healthy: bool,
        delay: Duration,
        config: Option<RingConfiguration>,
        health_calls: Arc<AtomicUsize>,
    }

    impl TransactionSource for TestSource {
        async fn transactions_by_tag(
            &self,
            _request: TransactionPage,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            Err(ClientError::Rpc("unused source".to_owned()))
        }

        async fn transaction_origin(
            &self,
            _signature: Signature,
            _ring: Address,
        ) -> Result<RingOrigin, OriginError> {
            Ok(RingOrigin {
                ring_invoked: false,
                signers: Vec::new(),
                withdrawals: Vec::new(),
            })
        }

        async fn ring_deposits(&self, _page: DepositPage) -> Result<DepositHistory, ClientError> {
            Ok(DepositHistory {
                deposits: Vec::new(),
                cursor: None,
                oldest_slot: None,
            })
        }

        async fn ring_config(
            &self,
            _ring: Address,
        ) -> Result<Option<RingConfiguration>, ClientError> {
            Ok(self.config)
        }

        async fn reader_granted(&self, _request: ReaderGrant) -> Result<bool, ClientError> {
            Ok(false)
        }

        async fn upgrade_authority(
            &self,
            _program: Address,
        ) -> Result<Option<Address>, ClientError> {
            Ok(None)
        }

        fn health(&self) -> impl Future<Output = Result<(), ClientError>> + Send {
            let healthy = self.healthy;
            let delay = self.delay;
            let calls = self.health_calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(delay).await;
                healthy
                    .then_some(())
                    .ok_or_else(|| ClientError::Rpc("unavailable".to_owned()))
            }
        }

        async fn genesis_hash(&self) -> Result<[u8; 32], ClientError> {
            Ok(TEST_GENESIS)
        }

        async fn asset_registry(&self) -> Result<AssetRegistry, ClientError> {
            Ok(AssetRegistry::default())
        }
    }

    fn port() -> u16 {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
        listener.local_addr().expect("address").port()
    }

    fn hub(mut source: TestSource, origins: Origins) -> Arc<Hub<TestSource>> {
        let auditor = ViewingKey::new();
        source.config = Some(RingConfiguration {
            auditor_pubkey: auditor.pubkey(),
            authority: Address::new_from_array([2; 32]),
        });
        Arc::new(
            Hub::builder(source, TEST_GENESIS)
                .with_origins(origins)
                .local(SERVED_RING, auditor)
                .expect("hub"),
        )
    }

    fn derived_hub(source: TestSource, genesis: [u8; 32]) -> Arc<Hub<TestSource>> {
        Arc::new(
            Hub::builder(source, genesis)
                .derived(RootSecret::from_bytes([5; 32]).expect("root"))
                .expect("hub"),
        )
    }

    fn source() -> TestSource {
        TestSource {
            healthy: true,
            delay: Duration::ZERO,
            config: None,
            health_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn params<T: serde::Serialize>(value: T) -> serde_json::Map<String, serde_json::Value> {
        let serde_json::Value::Object(map) = serde_json::to_value(value).expect("JSON object")
        else {
            panic!("expected JSON object");
        };
        map
    }

    fn deposits(ring: Address) -> RingDepositsRequest {
        RingDepositsRequest {
            ring_program_id: ring.to_bytes().into(),
            limit: None,
            cursor: None,
        }
    }

    fn options(port: u16, timeout: Duration) -> ServerOptions {
        ServerOptions {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_policy: BindPolicy::LoopbackOnly,
            port,
            max_connections: 8,
            request_timeout: timeout,
        }
    }

    #[tokio::test]
    async fn server_enforces_transport_boundaries() {
        let origins = OriginPolicy::new(vec!["http://localhost:3000".to_owned()])
            .with_relying_party_id("localhost".to_owned())
            .build()
            .expect("origins");
        let server_port = port();
        let handle = run_server(
            hub(source(), origins),
            options(server_port, Duration::from_secs(1)),
        )
        .await
        .expect("server");
        let url = format!("http://127.0.0.1:{server_port}");
        let client = reqwest::Client::new();

        let allowed = client
            .post(&url)
            .header("origin", "http://localhost:3000")
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": HEALTH,
            }))
            .send()
            .await
            .expect("allowed request");
        assert_eq!(
            allowed
                .headers()
                .get("access-control-allow-origin")
                .expect("CORS"),
            "http://localhost:3000"
        );

        let denied = client
            .post(&url)
            .header("origin", "https://evil.example")
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": HEALTH,
            }))
            .send()
            .await
            .expect("denied request");
        assert!(denied
            .headers()
            .get("access-control-allow-origin")
            .is_none());

        let batch = client
            .post(&url)
            .json(&serde_json::json!([{
                "jsonrpc": "2.0",
                "id": 1,
                "method": HEALTH,
            }]))
            .send()
            .await
            .expect("batch");
        let batch_body: serde_json::Value = batch.json().await.expect("batch body");
        assert_eq!(batch_body["error"]["code"], -32005);

        let oversized = client
            .post(&url)
            .body("a".repeat(MAX_REQUEST_BODY_SIZE as usize + 1))
            .send()
            .await
            .expect("oversized request");
        assert!(!oversized.status().is_success());

        let ready = client
            .get(format!("{url}/ready"))
            .send()
            .await
            .expect("ready");
        assert_eq!(ready.status(), StatusCode::OK);
        handle.stop().expect("stop");
        handle.stopped().await;
    }

    #[tokio::test]
    async fn server_rejects_public_bind_and_failed_readiness() {
        let public = run_server(
            hub(source(), Origins::default()),
            ServerOptions {
                bind: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                bind_policy: BindPolicy::LoopbackOnly,
                port: 0,
                max_connections: 1,
                request_timeout: Duration::from_secs(1),
            },
        )
        .await;
        assert!(matches!(public, Err(ServerError::PublicBind)));
        let insecure = run_server(
            hub(source(), Origins::default()),
            ServerOptions {
                bind: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                bind_policy: BindPolicy::InsecurePublic,
                port: 0,
                max_connections: 1,
                request_timeout: Duration::from_secs(1),
            },
        )
        .await
        .expect("public bind under the insecure policy");
        insecure.stop().expect("stop");

        let failed_port = port();
        let handle = run_server(
            hub(
                TestSource {
                    healthy: false,
                    ..source()
                },
                Origins::default(),
            ),
            options(failed_port, Duration::from_secs(1)),
        )
        .await
        .expect("server");
        let response = reqwest::get(format!("http://127.0.0.1:{failed_port}/ready"))
            .await
            .expect("ready response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        handle.stop().expect("stop");
        handle.stopped().await;

        let timeout_port = port();
        let handle = run_server(
            hub(
                TestSource {
                    delay: Duration::from_millis(50),
                    ..source()
                },
                Origins::default(),
            ),
            options(timeout_port, Duration::from_millis(5)),
        )
        .await
        .expect("server");
        assert!(
            reqwest::get(format!("http://127.0.0.1:{timeout_port}/ready"))
                .await
                .is_err()
        );
        handle.stop().expect("stop");
        handle.stopped().await;
    }

    #[tokio::test]
    async fn deposit_pages_are_metered_and_serve_one_ring() {
        let module = rpc_module(hub(source(), Origins::default())).expect("module");

        let foreign = module
            .call::<_, RingDepositsResponse>(
                RING_DEPOSITS,
                params(deposits(Address::new_from_array([1; 32]))),
            )
            .await
            .expect_err("another ring");
        assert!(foreign.to_string().contains("not served"), "{foreign}");

        for _ in 0..MAX_REQUEST_UNITS_PER_SECOND / DEPOSITS_PAGE_LIMIT as usize {
            module
                .call::<_, RingDepositsResponse>(RING_DEPOSITS, params(deposits(SERVED_RING)))
                .await
                .expect("page");
        }
        let busy = module
            .call::<_, RingDepositsResponse>(RING_DEPOSITS, params(deposits(SERVED_RING)))
            .await
            .expect_err("exhausted window");
        assert!(busy.to_string().contains("busy"), "{busy}");

        let health: HealthResponse = module.call(HEALTH, [(); 0]).await.expect("health");
        assert_eq!(health.mode, KeyMode::Local);
        let status: RingStatusResponse = module
            .call(
                RING_STATUS,
                params(RingStatusRequest {
                    ring_program_id: SERVED_RING.to_bytes().into(),
                }),
            )
            .await
            .expect("status");
        assert_eq!(status.state, RingState::Served);
    }

    #[tokio::test]
    async fn readiness_probes_share_a_cached_result() {
        let source = source();
        let calls = source.health_calls.clone();
        let hub = hub(source, Origins::default());

        assert_eq!(hub.readiness().await, ReadinessStatus::Ready);
        assert_eq!(hub.readiness().await, ReadinessStatus::Ready);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cancelled_readiness_waiters_leave_one_probe() {
        let source = TestSource {
            delay: Duration::from_millis(10),
            ..source()
        };
        let calls = source.health_calls.clone();
        let hub = hub(source, Origins::default());
        let waiter = tokio::spawn({
            let hub = hub.clone();
            async move { hub.readiness().await }
        });
        while calls.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
        waiter.abort();

        assert_eq!(hub.readiness().await, ReadinessStatus::Ready);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    /// A decrypting page holds its slot for the whole page, and the gate
    /// refuses the next reader rather than queueing it behind them.
    #[test]
    fn concurrent_reads_are_capped_and_refused_rather_than_queued() {
        let hub = hub(source(), Origins::default());
        let held = (0..MAX_CONCURRENT_READS)
            .map(|_| hub.read_slot().expect("read slot"))
            .collect::<Vec<_>>();

        assert!(matches!(hub.read_slot(), Err(RingRpcError::Busy)));
        drop(held);
        let _reopened = hub.read_slot().expect("released slot");
    }

    #[test]
    fn concurrent_deposit_scans_are_capped() {
        let hub = hub(source(), Origins::default());
        let held = (0..MAX_CONCURRENT_DEPOSIT_SCANS)
            .map(|_| hub.deposit_slot().expect("deposit slot"))
            .collect::<Vec<_>>();

        assert!(matches!(hub.deposit_slot(), Err(RingRpcError::Busy)));
        drop(held);
        let _reopened = hub.deposit_slot().expect("released slot");
    }

    #[test]
    fn authentication_attempts_do_not_consume_audit_capacity() {
        let hub = hub(source(), Origins::default());
        for _ in 0..MAX_REQUEST_UNITS_PER_SECOND {
            hub.accept_authentication().expect("authentication");
        }
        assert!(matches!(
            hub.accept_authentication(),
            Err(RingRpcError::Busy)
        ));
        hub.accept_audit().expect("audit capacity");
    }

    #[test]
    fn concurrent_authentication_attempts_are_capped() {
        let hub = hub(source(), Origins::default());
        let held = (0..MAX_CONCURRENT_AUTHENTICATIONS)
            .map(|_| hub.authentication_slot().expect("authentication slot"))
            .collect::<Vec<_>>();

        assert!(matches!(hub.authentication_slot(), Err(RingRpcError::Busy)));
        drop(held);
        let _reopened = hub.authentication_slot().expect("released slot");
    }

    /// Every derived key is bound to the genesis hash captured at boot, so
    /// another cluster orphans every ring already registered.
    #[tokio::test]
    async fn derived_readiness_checks_the_cluster() {
        let matching = port();
        let handle = run_server(
            derived_hub(source(), TEST_GENESIS),
            options(matching, Duration::from_secs(1)),
        )
        .await
        .expect("server");
        let ready = reqwest::get(format!("http://127.0.0.1:{matching}/ready"))
            .await
            .expect("ready");
        assert_eq!(ready.status(), StatusCode::OK);
        handle.stop().expect("stop");
        handle.stopped().await;

        let repointed = port();
        let handle = run_server(
            derived_hub(source(), [1; 32]),
            options(repointed, Duration::from_secs(1)),
        )
        .await
        .expect("server");
        let response = reqwest::get(format!("http://127.0.0.1:{repointed}/ready"))
            .await
            .expect("ready");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.text().await.expect("body"), "unavailable cluster");
        handle.stop().expect("stop");
        handle.stopped().await;
    }
}
