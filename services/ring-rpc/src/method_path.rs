//! A call on any path but `/` runs only when its JSON-RPC body names the
//! path's last segment. A gateway routes and prices ring RPC by path, so the
//! method that runs must be the one the path names; `/` serves every method
//! to a self-hosted client.

use std::{
    borrow::Cow,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http_body_util::{BodyExt, Limited};
use hyper::header::{HeaderValue, CONTENT_TYPE};
use jsonrpsee::{
    core::BoxError,
    server::{HttpBody, HttpRequest, HttpResponse},
    types::error::ErrorCode,
};
use serde::Deserialize;
use serde_json::value::RawValue;
use tower::{Layer, Service};

const MISMATCH: &str = "the method does not match the request path";

#[derive(Clone, Copy)]
pub(crate) struct MethodPathLayer {
    pub(crate) max_body_size: usize,
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
pub(crate) struct MethodPath<Inner> {
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
    id: Option<&'a RawValue>,
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
            let request = HttpRequest::from_parts(parts, HttpBody::from(bytes.to_vec()));
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

fn refusal(id: Option<&RawValue>, code: ErrorCode, message: &str) -> HttpResponse {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "error": { "code": code.code(), "message": message },
        "id": id.map_or(serde_json::Value::Null, |id| {
            serde_json::from_str(id.get()).unwrap_or(serde_json::Value::Null)
        }),
    });
    let mut response = hyper::Response::new(HttpBody::from(body.to_string()));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

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
