//! HTTP surface: the JSON-RPC methods and, on `GET /`, the auditor page.

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use hyper::{
    header::{CONTENT_TYPE, LOCATION},
    Method, StatusCode,
};
use jsonrpsee::{
    core::BoxError,
    server::{
        middleware::http::ProxyGetRequestLayer, HttpBody, HttpRequest, HttpResponse, ServerBuilder,
        ServerConfig, ServerHandle,
    },
    types::ErrorObjectOwned,
    RpcModule,
};
use tower::{Layer, Service};
use tower_http::cors::{AllowOrigin, CorsLayer};

use solana_address::Address;
use zolana_indexer_api::Limit;

use crate::{
    api::{
        CreateAuditorKeyRequest, CreateAuditorKeyResponse, GetDecryptedTransactionsRequest,
        HealthResponse, CREATE_AUDITOR_KEY, GET_DECRYPTED_TRANSACTIONS, HEALTH,
    },
    audit::{Hub, RingRpcError, TransactionSource},
    page::{cursor_from_query, AuditorPage},
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
        .layer(PageLayer { hub: hub.clone() })
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

/// The page is same-origin, so cross-origin calls are opt-in per origin.
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
            auditor_view_tag: hub
                .local_service()
                .map(|service| service.auditor_view_tag().into()),
        })
    })?;

    module.register_async_method(CREATE_AUDITOR_KEY, |params, hub, _extensions| async move {
        let request = params.parse::<CreateAuditorKeyRequest>()?;
        let ring = request.ring_program_id.0;
        let service = hub.ring(Some(ring)).map_err(ErrorObjectOwned::from)?;
        Ok::<_, ErrorObjectOwned>(CreateAuditorKeyResponse {
            ring_program_id: ring.into(),
            auditor_pubkey: service.auditor_pubkey().as_bytes().to_vec().into(),
            auditor_view_tag: service.auditor_view_tag().into(),
            key_version: 1,
        })
    })?;

    module.register_async_method(
        GET_DECRYPTED_TRANSACTIONS,
        |params, hub, _extensions| async move {
            let request = params.parse::<GetDecryptedTransactionsRequest>()?;
            let service = hub
                .ring(request.ring_program_id.map(|ring| ring.0))
                .map_err(ErrorObjectOwned::from)?;
            service
                .decrypted_transactions(request.cursor.map(Into::into), request.limit)
                .await
                .map_err(ErrorObjectOwned::from)
        },
    )?;

    Ok(module)
}

/// Serves the auditor page on `GET /` and `GET /ui` (`?ring=<program id>`
/// selects the ring when keys are derived), and readiness on `GET /ready`;
/// every other request goes to the JSON-RPC server. Readiness stays outside the
/// JSON-RPC proxy because a failing probe must answer with a non-200 status.
struct PageLayer<S> {
    hub: Arc<Hub<S>>,
}

impl<S, Inner> Layer<Inner> for PageLayer<S> {
    type Service = PageService<S, Inner>;

    fn layer(&self, inner: Inner) -> Self::Service {
        PageService {
            inner,
            hub: self.hub.clone(),
        }
    }
}

struct PageService<S, Inner> {
    inner: Inner,
    hub: Arc<Hub<S>>,
}

impl<S, Inner: Clone> Clone for PageService<S, Inner> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            hub: self.hub.clone(),
        }
    }
}

impl<S, Inner, B> Service<HttpRequest<B>> for PageService<S, Inner>
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
        if request.method() != Method::GET {
            let future = self.inner.call(request);
            return Box::pin(async move { future.await.map_err(Into::into) });
        }
        let hub = self.hub.clone();
        match request.uri().path() {
            "/" | "/ui" => {
                let query = request.uri().query();
                let cursor = query_param(query, "cursor").map(str::to_owned);
                let ring = query_param(query, "ring").map(str::to_owned);
                Box::pin(async move { Ok(render_page(&hub, ring, cursor).await) })
            }
            "/ready" => Box::pin(async move { Ok(readiness(&hub).await) }),
            _ => {
                let future = self.inner.call(request);
                Box::pin(async move { future.await.map_err(Into::into) })
            }
        }
    }
}

async fn render_page<S: TransactionSource>(
    hub: &Hub<S>,
    ring: Option<String>,
    cursor: Option<String>,
) -> HttpResponse {
    let ring = match ring.as_deref().map(str::parse::<Address>) {
        None => None,
        Some(Ok(ring)) => Some(ring),
        Some(Err(_)) => return redirect_home(),
    };
    let service = match hub.ring(ring) {
        Ok(service) => service,
        Err(error @ RingRpcError::RingRequired) => {
            return html_response(
                StatusCode::BAD_REQUEST,
                maud::html! { p { (error) ". Open " code { "/?ring=<program id>" } "." } }
                    .into_string(),
            )
        }
        Err(error) => {
            return html_response(
                StatusCode::BAD_REQUEST,
                maud::html! { p { (error) } }.into_string(),
            )
        }
    };
    let cursor_bytes = match cursor.as_deref() {
        None => None,
        Some(text) => match cursor_from_query(text) {
            Some(bytes) => Some(bytes),
            None => return redirect_home(),
        },
    };
    match service
        .decrypted_transactions(cursor_bytes, Some(Limit::default()))
        .await
    {
        Ok(page) => {
            let markup = AuditorPage {
                auditor_view_tag: service.auditor_view_tag().into(),
                ring,
                page: &page,
                cursor: cursor.as_deref(),
            }
            .render();
            html_response(StatusCode::OK, markup.into_string())
        }
        Err(error) => html_response(
            StatusCode::BAD_GATEWAY,
            maud::html! {
                p { "The ring RPC is up, its indexer is not: " (error) }
            }
            .into_string(),
        ),
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

fn query_param<'a>(query: Option<&'a str>, name: &str) -> Option<&'a str> {
    query?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

fn html_response(status: StatusCode, body: String) -> HttpResponse {
    response(status, "text/html; charset=utf-8", body)
}

fn text_response(status: StatusCode, body: String) -> HttpResponse {
    response(status, "text/plain; charset=utf-8", body)
}

fn response(status: StatusCode, content_type: &str, body: String) -> HttpResponse {
    hyper::Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .body(HttpBody::from(body))
        .expect("static response parts are valid")
}

fn redirect_home() -> HttpResponse {
    hyper::Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(LOCATION, "/")
        .body(HttpBody::empty())
        .expect("static response parts are valid")
}
