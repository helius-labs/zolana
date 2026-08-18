//! HTTP surface: the JSON-RPC methods and, on `GET /`, the auditor page. Same
//! server shape as Photon so one client stack reads both.

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

use crate::{
    api::{
        GetDecryptedTransactionsRequest, HealthResponse, GET_DECRYPTED_TRANSACTIONS, HEALTH,
        PAGE_LIMIT,
    },
    audit::{AuditService, TransactionSource},
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
    service: Arc<AuditService<S>>,
    options: ServerOptions,
) -> Result<ServerHandle, anyhow::Error> {
    let addr = SocketAddr::from((options.bind, options.port));
    let middleware = tower::ServiceBuilder::new()
        .layer(cors(&options.allow_origins)?)
        .layer(tower::timeout::TimeoutLayer::new(options.request_timeout))
        .layer(PageLayer {
            service: service.clone(),
        })
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
    Ok(server.start(rpc_module(service)?))
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

/// Serves the auditor page on `GET /` and `GET /ui`, and readiness on
/// `GET /ready`; every other request goes to the JSON-RPC server.
struct PageLayer<S> {
    service: Arc<AuditService<S>>,
}

impl<S, Inner> Layer<Inner> for PageLayer<S> {
    type Service = PageService<S, Inner>;

    fn layer(&self, inner: Inner) -> Self::Service {
        PageService {
            inner,
            service: self.service.clone(),
        }
    }
}

struct PageService<S, Inner> {
    inner: Inner,
    service: Arc<AuditService<S>>,
}

// Derived `Clone` would demand `S: Clone`; the service is shared through `Arc`.
impl<S, Inner: Clone> Clone for PageService<S, Inner> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            service: self.service.clone(),
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
        let service = self.service.clone();
        match request.uri().path() {
            "/" | "/ui" => {
                let cursor = query_param(request.uri().query(), "cursor").map(str::to_owned);
                Box::pin(async move { Ok(render_page(&service, cursor).await) })
            }
            "/ready" => Box::pin(async move { Ok(readiness(&service).await) }),
            _ => {
                let future = self.inner.call(request);
                Box::pin(async move { future.await.map_err(Into::into) })
            }
        }
    }
}

async fn render_page<S: TransactionSource>(
    service: &AuditService<S>,
    cursor: Option<String>,
) -> HttpResponse {
    let cursor_bytes = match cursor.as_deref() {
        None => None,
        Some(text) => match cursor_from_query(text) {
            Some(bytes) => Some(bytes),
            None => return redirect_home(),
        },
    };
    let limit = u32::try_from(PAGE_LIMIT).ok();
    match service.decrypted_transactions(cursor_bytes, limit).await {
        Ok(page) => {
            let markup = AuditorPage {
                auditor_view_tag: service.auditor_view_tag().into(),
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

async fn readiness<S: TransactionSource>(service: &AuditService<S>) -> HttpResponse {
    match service.probe_indexer().await {
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
    hyper::Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(HttpBody::from(body))
        .expect("static response parts are valid")
}

fn text_response(status: StatusCode, body: String) -> HttpResponse {
    hyper::Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
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
