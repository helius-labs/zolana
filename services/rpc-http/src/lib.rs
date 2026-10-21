//! A call on any path but `/` runs only when its JSON-RPC body names the
//! path's last segment. A gateway routes and prices RPC calls by path, so the
//! method that runs must be the one the path names; `/` serves every method
//! to a self-hosted client.

use std::{
    borrow::Cow,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{HeaderValue, CONTENT_TYPE};
use jsonrpsee::{
    core::BoxError,
    server::{HttpBody, HttpRequest, HttpResponse},
    types::{error::ErrorCode, Id},
};
use serde::Deserialize;
use tower::{Layer, Service};

const MISMATCH: &str = "the method does not match the request path";

#[derive(Clone, Copy)]
pub struct MethodPathLayer {
    pub max_body_size: usize,
}

impl<Inner> Layer<Inner> for MethodPathLayer {
    type Service = MethodPath<Inner>;

    fn layer(&self, inner: Inner) -> Self::Service {
        MethodPath {
            inner,
            max_body_size: self.max_body_size,
        }
    }
}

#[derive(Clone)]
pub struct MethodPath<Inner> {
    inner: Inner,
    max_body_size: usize,
}

/// The fields of one call that decide whether it may run on a path. Anything
/// that does not parse as one call is refused on a method path, so this and
/// jsonrpsee never disagree about which method a body names.
#[derive(Deserialize)]
struct Call<'a> {
    #[serde(borrow)]
    method: Cow<'a, str>,
    #[serde(borrow, default)]
    id: Option<Id<'a>>,
}

impl<Inner> Service<HttpRequest> for MethodPath<Inner>
where
    Inner: Service<HttpRequest, Response = HttpResponse> + Clone + Send + 'static,
    Inner::Error: Into<BoxError> + 'static,
    Inner::Future: Send + 'static,
{
    type Response = HttpResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: HttpRequest) -> Self::Future {
        let Some(named) = path_method(request.uri().path()).map(str::to_owned) else {
            let future = self.inner.call(request);
            return Box::pin(async move { future.await.map_err(Into::into) });
        };
        // The service polled ready serves this call; its clone serves the next.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        let max_body_size = self.max_body_size;
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let Ok(collected) = Limited::new(body, max_body_size).collect().await else {
                return Ok(refusal(
                    None,
                    ErrorCode::InvalidRequest,
                    "unreadable request body",
                ));
            };
            let bytes = collected.to_bytes();
            match serde_json::from_slice::<Call<'_>>(&bytes) {
                Ok(call) if call.method == named => {}
                Ok(call) => return Ok(refusal(call.id, ErrorCode::MethodNotFound, MISMATCH)),
                Err(_) => return Ok(refusal(None, ErrorCode::MethodNotFound, MISMATCH)),
            }
            let request = HttpRequest::from_parts(parts, HttpBody::new(Full::new(bytes)));
            inner.call(request).await.map_err(Into::into)
        })
    }
}

/// The method a path names: its last segment, none for `/`.
fn path_method(path: &str) -> Option<&str> {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
}

fn refusal(id: Option<Id<'_>>, code: ErrorCode, message: &str) -> HttpResponse {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "error": { "code": code.code(), "message": message },
        "id": id,
    });
    let mut response = hyper::Response::new(HttpBody::from(body.to_string()));
    // This request never reached RPC execution. An opaque HTTP proxy must
    // recognize the refusal without parsing the JSON-RPC error to bill it.
    *response.status_mut() = hyper::StatusCode::BAD_REQUEST;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tower::{service_fn, ServiceExt};

    use super::*;

    /// This is the execution barrier for path-based billing: a rejected call
    /// must not reach the RPC handler, consume an auth nonce, or report units.
    #[tokio::test]
    async fn rejects_ambiguous_calls_before_rpc_execution() {
        let calls = Arc::new(AtomicUsize::new(0));
        let executed = calls.clone();
        let service = MethodPathLayer { max_body_size: 128 }.layer(service_fn(
            move |request: HttpRequest| {
                executed.fetch_add(1, Ordering::SeqCst);
                async move { Ok::<_, BoxError>(HttpResponse::new(request.into_body())) }
            },
        ));
        for (body, code) in [
            (
                r#"{"method":"getDecryptedTransactions","id":7}"#.to_owned(),
                -32601,
            ),
            (r#"[{"method":"health"}]"#.to_owned(), -32601),
            (
                r#"{"method":"health","method":"ringDeposits"}"#.to_owned(),
                -32601,
            ),
            (
                r#"{"method":"ringDeposits","method":"health"}"#.to_owned(),
                -32601,
            ),
            (r#"{"id":7}"#.to_owned(), -32601),
            ("not json".to_owned(), -32601),
            (" ".repeat(129), -32600),
        ] {
            let response = service
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .method("POST")
                        .uri("/v1/zolana/ring/health/")
                        .body(HttpBody::from(body.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), hyper::StatusCode::BAD_REQUEST);
            assert!(!response.headers().contains_key("x-helius-metering-units"));
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let answer: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(answer["error"]["code"], code, "{body}");
            assert_eq!(calls.load(Ordering::SeqCst), 0, "{body}");
        }

        // JSON escaping is legal; forward the original bytes after checking
        // the decoded method so jsonrpsee sees exactly the client's call.
        let body = r#"{ "jsonrpc":"2.0", "method":"he\u0061lth", "id":7 }"#;
        let response = service
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/v1/zolana/ring/health/?q=%61")
                    .body(HttpBody::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            body
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn matching_calls_preserve_the_body_for_every_method() {
        let inner = tower::service_fn(|request: HttpRequest| async move {
            Ok::<_, BoxError>(HttpResponse::new(request.into_body()))
        });
        let service = MethodPathLayer { max_body_size: 256 }.layer(inner);
        for method in [
            "health",
            "ringStatus",
            "ringDeposits",
            "createAuditorKey",
            "getDecryptedTransactions",
        ] {
            let body = format!(
                r#"{{ "jsonrpc": "2.0", "id": "request", "method": "{method}", "params": {{}} }}"#
            );
            for path in [
                "/".to_owned(),
                format!("/{method}"),
                format!("/v1/zolana/ring/{method}/?api-key=test"),
            ] {
                let response = service
                    .clone()
                    .oneshot(
                        HttpRequest::post(&path)
                            .body(HttpBody::from(body.clone()))
                            .expect("request"),
                    )
                    .await
                    .expect("response");
                let bytes = response
                    .into_body()
                    .collect()
                    .await
                    .expect("body")
                    .to_bytes();
                assert_eq!(bytes.as_ref(), body.as_bytes(), "{path}");
            }
        }
    }

    #[tokio::test]
    async fn rejected_calls_never_reach_the_handler() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = tower::service_fn({
            let calls = calls.clone();
            move |_request: HttpRequest| {
                calls.fetch_add(1, Ordering::Relaxed);
                async { Ok::<_, BoxError>(HttpResponse::new(HttpBody::from("dispatched"))) }
            }
        });
        let service = MethodPathLayer { max_body_size: 256 }.layer(inner);
        for body in [
            r#"{"jsonrpc":"2.0","id":7,"method":"ringStatus"}"#,
            r#"{"jsonrpc":"2.0","id":"request","method":"getDecryptedTransactions"}"#,
            r#"[{"jsonrpc":"2.0","id":7,"method":"health"}]"#,
            r#"{"method":"health","method":"getDecryptedTransactions"}"#,
            r#"{"method":"getDecryptedTransactions","method":"health"}"#,
            r#"{"method":"health","id":1,"id":2}"#,
            r#"{"method":"health","id":{"secret":"not-an-id"}}"#,
            r#"{"method":"health"} {"method":"getDecryptedTransactions"}"#,
            "not JSON",
        ] {
            let response = service
                .clone()
                .oneshot(
                    HttpRequest::post("/v1/zolana/ring/health?api-key=ignored")
                        .body(HttpBody::from(body))
                        .expect("request"),
                )
                .await
                .expect("response");
            let bytes = response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            let response: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
            assert_eq!(response["error"]["code"], -32601, "{body}");
            assert!(!String::from_utf8_lossy(&bytes).contains("secret"));
        }
        let response = service
            .oneshot(
                HttpRequest::post("/health")
                    .body(HttpBody::from(" ".repeat(257)))
                    .expect("request"),
            )
            .await
            .expect("response");
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let response: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(response["error"]["code"], -32600);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_path_names_its_last_segment_and_the_root_names_none() {
        for (path, method) in [
            ("/", None),
            ("", None),
            ("//", None),
            ("/health", Some("health")),
            ("/health/", Some("health")),
            ("/v1/zolana/ring/ringStatus", Some("ringStatus")),
            (
                "/v1/zolana/ring/getDecryptedTransactions/",
                Some("getDecryptedTransactions"),
            ),
        ] {
            assert_eq!(path_method(path), method, "{path}");
        }
    }
}
