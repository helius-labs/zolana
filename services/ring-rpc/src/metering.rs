//! The units a gateway bills a call at, reported in `x-helius-metering-units`.
//! A gateway prices a call at its method's price times these units, and reads
//! them only from a successful answer.
//!
//! `ringDeposits` bills one unit per `DEPOSITS_PAGE_LIMIT` signatures it asks
//! to examine, rounded up. Every other method answers a bounded page or a
//! single lookup and reports none, which a gateway bills as one.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use hyper::header::HeaderValue;
use jsonrpsee::{
    core::{
        middleware::{Batch, Notification, RpcServiceT},
        BoxError,
    },
    server::{HttpRequest, HttpResponse, MethodResponse},
    types::Request,
};
use tower::{Layer, Service};

use crate::api::{RingDepositsRequest, DEPOSITS_PAGE_LIMIT, RING_DEPOSITS};

const METERING_UNITS_HEADER: &str = "x-helius-metering-units";

/// The units one successful call bills, carried from the RPC layer to the
/// HTTP answer in the response's extensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MeteringUnits(pub(crate) u32);

/// RPC middleware recording a successful call's units on its response.
#[derive(Clone)]
pub(crate) struct Metering<S>(pub(crate) S);

impl<S> RpcServiceT for Metering<S>
where
    S: RpcServiceT<MethodResponse = MethodResponse> + Send + Sync + Clone + 'static,
{
    type MethodResponse = S::MethodResponse;
    type NotificationResponse = S::NotificationResponse;
    type BatchResponse = S::BatchResponse;

    fn call<'a>(
        &self,
        request: Request<'a>,
    ) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        let units = call_units(&request);
        let service = self.0.clone();
        async move {
            let mut response = service.call(request).await;
            if let (Some(units), true) = (units, response.is_success()) {
                response.extensions_mut().insert(MeteringUnits(units));
            }
            response
        }
    }

    fn batch<'a>(
        &self,
        requests: Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        self.0.batch(requests)
    }

    fn notification<'a>(
        &self,
        notification: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        self.0.notification(notification)
    }
}

fn call_units(request: &Request<'_>) -> Option<u32> {
    match request.method_name() {
        RING_DEPOSITS => request
            .params()
            .parse::<RingDepositsRequest>()
            .ok()
            .map(|deposits| deposit_page_units(deposits.page_limit())),
        _ => None,
    }
}

fn deposit_page_units(signatures: usize) -> u32 {
    u32::try_from(signatures.div_ceil(DEPOSITS_PAGE_LIMIT as usize)).unwrap_or(u32::MAX)
}

/// Writes the units the RPC layer recorded as the answer's header.
#[derive(Clone, Copy)]
pub(crate) struct MeteringHeaderLayer;

impl<Inner> Layer<Inner> for MeteringHeaderLayer {
    type Service = MeteringHeader<Inner>;

    fn layer(&self, inner: Inner) -> Self::Service {
        MeteringHeader(inner)
    }
}

#[derive(Clone)]
pub(crate) struct MeteringHeader<Inner>(Inner);

impl<Inner, B> Service<HttpRequest<B>> for MeteringHeader<Inner>
where
    Inner: Service<HttpRequest<B>, Response = HttpResponse>,
    Inner::Error: Into<BoxError> + 'static,
    Inner::Future: Send + 'static,
{
    type Response = HttpResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: HttpRequest<B>) -> Self::Future {
        let future = self.0.call(request);
        Box::pin(async move {
            let mut response = future.await.map_err(Into::into)?;
            if let Some(MeteringUnits(units)) =
                response.extensions().get::<MeteringUnits>().copied()
            {
                response
                    .headers_mut()
                    .insert(METERING_UNITS_HEADER, HeaderValue::from(units));
            }
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deposits_page_bills_one_unit_per_default_page_it_spans() {
        for (signatures, units) in [(1, 1), (50, 1), (51, 2), (100, 2), (200, 4)] {
            assert_eq!(deposit_page_units(signatures), units, "{signatures}");
        }
    }
}
