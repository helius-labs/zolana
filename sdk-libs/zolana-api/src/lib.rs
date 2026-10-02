//! Async and blocking transports for the Zolana indexer JSON-RPC contract.
//!
//! Both send their requests through an [`HttpClient`] or a
//! [`BlockingHttpClient`]: a `reqwest` client by default, or the
//! application's own networking stack. The `zolana-client` prover clients
//! send through the same traits.

use std::{
    borrow::Cow, error::Error as StdError, fmt, future::Future, pin::Pin, sync::Arc, time::Duration,
};

use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE},
    Method,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::Zeroizing;
use zolana_indexer_api::{
    method::{
        GetEncryptedUtxosByTags, GetMerkleProofs, GetNonInclusionProofs, GetNullifierQueueElements,
        GetRingKeyRegistryEntry, GetRingKeyRegistryRegisterProof, GetRingSpendRecord,
        GetShieldedTransactionsByNullifiers, GetShieldedTransactionsBySignature,
        GetShieldedTransactionsByTags,
    },
    RpcMethod,
};

pub use zolana_indexer_api::{
    Base64String, Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse,
    GetMerkleProofsRequest, GetMerkleProofsResponse, GetNonInclusionProofsRequest,
    GetNonInclusionProofsResponse, GetNullifierQueueElementsRequest,
    GetNullifierQueueElementsResponse, GetRingKeyRegistryEntryResponse,
    GetRingKeyRegistryRegisterProofResponse, GetRingSpendRecordResponse,
    GetRingsByNullifiersRequest, GetRingsByTagsRequest,
    GetShieldedTransactionsByNullifiersResponse, GetShieldedTransactionsBySignatureRequest,
    GetShieldedTransactionsBySignatureResponse, GetShieldedTransactionsByTagsResponse, Hash,
    IndexedShieldedTransaction, Limit, MerkleContext, MerkleProof, NonInclusionProof,
    NullifierQueueElement, RingMemberProofRequest, RingSpendRecord, RingSpendRecordRequest,
    RingsOutputContext, RingsOutputSlot, SerializablePubkey, SerializableSignature,
    ShieldedTransaction, PAGE_LIMIT,
};

const JSON_RPC_VERSION: &str = "2.0";
const REQUEST_ID: &str = "test-account";

#[derive(Clone, Debug)]
pub struct ZolanaApi {
    base_path: String,
    api_key: Option<String>,
    client: Arc<dyn HttpClient>,
    trace_http: bool,
}

#[derive(Clone, Debug)]
pub struct BlockingZolanaApi {
    base_path: String,
    api_key: Option<String>,
    client: Arc<dyn BlockingHttpClient>,
    trace_http: bool,
}

/// Sends the requests of a [`ZolanaApi`] and of the `zolana-client` async
/// prover client.
pub trait HttpClient: fmt::Debug + Send + Sync {
    /// Send `request` and answer with the server's response, whatever its
    /// status: the caller acts on the status. Fail only without a response:
    /// with [`ApiError::HttpClient`] when no response arrived, and with
    /// [`ApiError::ResponseLost`] when its status arrived and its body could
    /// not be read.
    fn send<'a>(&'a self, request: HttpRequest) -> HttpFuture<'a>;
}

/// Sends the requests of a [`BlockingZolanaApi`] and of the `zolana-client`
/// blocking prover client.
pub trait BlockingHttpClient: fmt::Debug + Send + Sync {
    /// As [`HttpClient::send`].
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, ApiError>;
}

pub type HttpFuture<'a> = Pin<Box<dyn Future<Output = Result<HttpResponse, ApiError>> + Send + 'a>>;

/// One request of an [`HttpClient`] or a [`BlockingHttpClient`].
///
/// Its `Debug` shows the header names and the body length only, with the
/// URL's `api-key` masked: a header can carry a credential and a proof
/// request's body carries the witness.
pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub headers: HeaderMap,
    /// Empty for a `GET`. Wiped on drop: a proof request's body carries the
    /// witness.
    pub body: Zeroizing<Vec<u8>>,
    /// The caller's bound on the whole request, for a client that can keep
    /// one; the `reqwest` clients do. Without it the client's own bound
    /// applies.
    pub timeout: Option<Duration>,
}

impl HttpRequest {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: Method::GET,
            url: url.into(),
            headers: HeaderMap::new(),
            body: Zeroizing::new(Vec::new()),
            timeout: None,
        }
    }

    /// A `POST` of `body`, a JSON document, to `url`.
    pub fn post_json(url: impl Into<String>, body: Vec<u8>) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Self {
            method: Method::POST,
            url: url.into(),
            headers,
            body: Zeroizing::new(body),
            timeout: None,
        }
    }

    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &redact_api_key(&self.url))
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("body_len", &self.body.len())
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: reqwest::StatusCode,
    pub body: String,
}

impl HttpClient for reqwest::Client {
    fn send<'a>(&'a self, request: HttpRequest) -> HttpFuture<'a> {
        Box::pin(async move {
            let HttpRequest {
                method,
                url,
                headers,
                mut body,
                timeout,
            } = request;
            let mut builder = self
                .request(method, url)
                .headers(headers)
                .body(std::mem::take(&mut *body));
            if let Some(timeout) = timeout {
                builder = builder.timeout(timeout);
            }
            let response = builder.send().await?;
            let status = response.status();
            let body = response.text().await.map_err(response_lost)?;
            Ok(HttpResponse { status, body })
        })
    }
}

impl BlockingHttpClient for reqwest::blocking::Client {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, ApiError> {
        let HttpRequest {
            method,
            url,
            headers,
            mut body,
            timeout,
        } = request;
        let mut builder = self
            .request(method, url)
            .headers(headers)
            .body(std::mem::take(&mut *body));
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        let response = builder.send()?;
        let status = response.status();
        let body = response.text().map_err(response_lost)?;
        Ok(HttpResponse { status, body })
    }
}

fn response_lost(error: reqwest::Error) -> ApiError {
    ApiError::ResponseLost(Box::new(error))
}

#[derive(Debug)]
pub enum ApiError {
    Request(reqwest::Error),
    /// A custom [`HttpClient`] or [`BlockingHttpClient`] failed before it had
    /// a response.
    HttpClient(Box<dyn StdError + Send + Sync>),
    /// The response's status arrived and its body could not be read. The
    /// server got the request and may have acted on it, so a request that is
    /// not safe to repeat, such as a proof, is not sent again.
    ResponseLost(Box<dyn StdError + Send + Sync>),
    Response {
        status: reqwest::StatusCode,
        body: String,
    },
    JsonRpc {
        method: &'static str,
        code: Option<i64>,
        message: Option<String>,
    },
    InvalidRequest {
        field: &'static str,
        message: &'static str,
    },
    MissingResult(&'static str),
}

/// Every `api-key` value is masked: a `reqwest` error and a custom client's
/// failure both tend to name the URL, and the URL carries the key.
impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Request(error) => format!("request error: {error}"),
            Self::HttpClient(error) => format!("HTTP client error: {error}"),
            Self::ResponseLost(error) => format!("failed to read response body: {error}"),
            Self::Response { status, body } => format!("HTTP response error {status}: {body}"),
            Self::JsonRpc {
                method,
                code,
                message,
            } => format!("JSON-RPC error from {method}: code={code:?} message={message:?}"),
            Self::InvalidRequest { field, message } => format!("invalid {field}: {message}"),
            Self::MissingResult(method) => {
                format!("JSON-RPC response from {method} omitted result")
            }
        };
        formatter.write_str(&redact_api_key(&text))
    }
}

impl StdError for ApiError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::HttpClient(error) | Self::ResponseLost(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<reqwest::Error> for ApiError {
    fn from(error: reqwest::Error) -> Self {
        Self::Request(error)
    }
}

#[derive(Serialize)]
struct JsonRpcRequest<'a, P> {
    id: &'static str,
    jsonrpc: &'static str,
    method: &'static str,
    params: &'a P,
}

impl<'a, P> JsonRpcRequest<'a, P> {
    fn new(method: &'static str, params: &'a P) -> Self {
        Self {
            id: REQUEST_ID,
            jsonrpc: JSON_RPC_VERSION,
            method,
            params,
        }
    }
}

#[derive(Deserialize)]
struct JsonRpcResponse<R> {
    error: Option<JsonRpcError>,
    result: Option<R>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: Option<i64>,
    message: Option<String>,
}

impl ZolanaApi {
    pub fn new(url: impl AsRef<str>) -> Self {
        Self::with_client(url, reqwest::Client::new())
    }

    pub fn with_client(url: impl AsRef<str>, client: impl HttpClient + 'static) -> Self {
        let (base_path, api_key) = parse_url(url.as_ref());
        Self {
            base_path,
            api_key,
            client: Arc::new(client),
            trace_http: false,
        }
    }

    pub fn base_path(&self) -> &str {
        &self.base_path
    }

    pub fn api_key(&self) -> Option<&str> {
        self.api_key.as_deref()
    }

    pub fn with_http_trace(mut self) -> Self {
        self.trace_http = true;
        self
    }

    pub async fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<Hash>,
        cursor: Option<Base64String>,
        limit: Option<u64>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ApiError> {
        self.call::<GetEncryptedUtxosByTags>(GetRingsByTagsRequest {
            tags,
            cursor,
            limit: optional_limit(limit)?,
            ring_program_id: None,
        })
        .await
    }

    pub async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<Hash>,
        cursor: Option<Base64String>,
        limit: Option<u64>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ApiError> {
        self.call::<GetShieldedTransactionsByTags>(GetRingsByTagsRequest {
            tags,
            cursor,
            limit: optional_limit(limit)?,
            ring_program_id: None,
        })
        .await
    }

    pub async fn get_shielded_transactions_by_signature(
        &self,
        tx_signature: SerializableSignature,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ApiError> {
        self.call::<GetShieldedTransactionsBySignature>(GetShieldedTransactionsBySignatureRequest {
            tx_signature,
        })
        .await
    }

    pub async fn get_shielded_transactions(
        &self,
        request: GetRingsByTagsRequest,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ApiError> {
        self.call::<GetShieldedTransactionsByTags>(request).await
    }

    pub async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<Hash>,
        cursor: Option<Base64String>,
        limit: Option<u64>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ApiError> {
        self.call::<GetShieldedTransactionsByNullifiers>(GetRingsByNullifiersRequest {
            nullifiers,
            cursor,
            limit: optional_limit(limit)?,
        })
        .await
    }

    pub async fn get_merkle_proofs(
        &self,
        tree_account: SerializablePubkey,
        leaves: Vec<Hash>,
    ) -> Result<GetMerkleProofsResponse, ApiError> {
        self.call::<GetMerkleProofs>(GetMerkleProofsRequest {
            tree_account,
            leaves,
        })
        .await
    }

    pub async fn get_ring_spend_record(
        &self,
        request: RingSpendRecordRequest,
    ) -> Result<GetRingSpendRecordResponse, ApiError> {
        self.call::<GetRingSpendRecord>(request).await
    }

    pub async fn get_ring_key_registry_entry(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryEntryResponse, ApiError> {
        self.call::<GetRingKeyRegistryEntry>(request).await
    }

    pub async fn get_ring_key_registry_register_proof(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryRegisterProofResponse, ApiError> {
        self.call::<GetRingKeyRegistryRegisterProof>(request).await
    }

    pub async fn get_non_inclusion_proofs(
        &self,
        tree_account: SerializablePubkey,
        leaves: Vec<Hash>,
    ) -> Result<GetNonInclusionProofsResponse, ApiError> {
        self.call::<GetNonInclusionProofs>(GetNonInclusionProofsRequest {
            tree_account,
            leaves,
        })
        .await
    }

    pub async fn get_nullifier_queue_elements(
        &self,
        tree_account: SerializablePubkey,
        start_seq: Option<u64>,
        limit: u64,
    ) -> Result<GetNullifierQueueElementsResponse, ApiError> {
        self.call::<GetNullifierQueueElements>(GetNullifierQueueElementsRequest {
            tree_account,
            start_seq: start_seq.unwrap_or_default(),
            limit: required_limit(limit)?,
        })
        .await
    }

    async fn call<M>(&self, params: M::Request) -> Result<M::Response, ApiError>
    where
        M: RpcMethod,
    {
        let body = JsonRpcRequest::new(M::NAME, &params);
        let response: JsonRpcResponse<M::Response> = self.post(M::NAME, &body).await?;
        unwrap_response::<M>(response)
    }

    async fn post<B, R>(&self, method: &'static str, body: &B) -> Result<R, ApiError>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let url = self.url(method);
        let body = encode_body(body)?;
        if self.trace_http {
            print_api_request(&url, &body);
        }
        let response = self.client.send(HttpRequest::post_json(url, body)).await?;
        handle_response(method, response, self.trace_http)
    }

    fn url(&self, method: &str) -> String {
        api_url(&self.base_path, self.api_key.as_deref(), method)
    }
}

impl BlockingZolanaApi {
    pub fn new(url: impl AsRef<str>) -> Self {
        Self::with_client(url, reqwest::blocking::Client::new())
    }

    pub fn with_client(url: impl AsRef<str>, client: impl BlockingHttpClient + 'static) -> Self {
        let (base_path, api_key) = parse_url(url.as_ref());
        Self {
            base_path,
            api_key,
            client: Arc::new(client),
            trace_http: false,
        }
    }

    pub fn base_path(&self) -> &str {
        &self.base_path
    }

    pub fn api_key(&self) -> Option<&str> {
        self.api_key.as_deref()
    }

    pub fn with_http_trace(mut self) -> Self {
        self.trace_http = true;
        self
    }

    pub fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<Hash>,
        cursor: Option<Base64String>,
        limit: Option<u64>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ApiError> {
        self.call::<GetEncryptedUtxosByTags>(GetRingsByTagsRequest {
            tags,
            cursor,
            limit: optional_limit(limit)?,
            ring_program_id: None,
        })
    }

    pub fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<Hash>,
        cursor: Option<Base64String>,
        limit: Option<u64>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ApiError> {
        self.call::<GetShieldedTransactionsByTags>(GetRingsByTagsRequest {
            tags,
            cursor,
            limit: optional_limit(limit)?,
            ring_program_id: None,
        })
    }

    pub fn get_shielded_transactions_by_signature(
        &self,
        tx_signature: SerializableSignature,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ApiError> {
        self.call::<GetShieldedTransactionsBySignature>(GetShieldedTransactionsBySignatureRequest {
            tx_signature,
        })
    }

    pub fn get_shielded_transactions(
        &self,
        request: GetRingsByTagsRequest,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ApiError> {
        self.call::<GetShieldedTransactionsByTags>(request)
    }

    pub fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<Hash>,
        cursor: Option<Base64String>,
        limit: Option<u64>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ApiError> {
        self.call::<GetShieldedTransactionsByNullifiers>(GetRingsByNullifiersRequest {
            nullifiers,
            cursor,
            limit: optional_limit(limit)?,
        })
    }

    pub fn get_merkle_proofs(
        &self,
        tree_account: SerializablePubkey,
        leaves: Vec<Hash>,
    ) -> Result<GetMerkleProofsResponse, ApiError> {
        self.call::<GetMerkleProofs>(GetMerkleProofsRequest {
            tree_account,
            leaves,
        })
    }

    pub fn get_ring_spend_record(
        &self,
        request: RingSpendRecordRequest,
    ) -> Result<GetRingSpendRecordResponse, ApiError> {
        self.call::<GetRingSpendRecord>(request)
    }

    pub fn get_ring_key_registry_entry(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryEntryResponse, ApiError> {
        self.call::<GetRingKeyRegistryEntry>(request)
    }

    pub fn get_ring_key_registry_register_proof(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryRegisterProofResponse, ApiError> {
        self.call::<GetRingKeyRegistryRegisterProof>(request)
    }

    pub fn get_non_inclusion_proofs(
        &self,
        tree_account: SerializablePubkey,
        leaves: Vec<Hash>,
    ) -> Result<GetNonInclusionProofsResponse, ApiError> {
        self.call::<GetNonInclusionProofs>(GetNonInclusionProofsRequest {
            tree_account,
            leaves,
        })
    }

    pub fn get_nullifier_queue_elements(
        &self,
        tree_account: SerializablePubkey,
        start_seq: Option<u64>,
        limit: u64,
    ) -> Result<GetNullifierQueueElementsResponse, ApiError> {
        self.call::<GetNullifierQueueElements>(GetNullifierQueueElementsRequest {
            tree_account,
            start_seq: start_seq.unwrap_or_default(),
            limit: required_limit(limit)?,
        })
    }

    fn call<M>(&self, params: M::Request) -> Result<M::Response, ApiError>
    where
        M: RpcMethod,
    {
        let body = JsonRpcRequest::new(M::NAME, &params);
        let response: JsonRpcResponse<M::Response> = self.post(M::NAME, &body)?;
        unwrap_response::<M>(response)
    }

    fn post<B, R>(&self, method: &'static str, body: &B) -> Result<R, ApiError>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let url = self.url(method);
        let body = encode_body(body)?;
        if self.trace_http {
            print_api_request(&url, &body);
        }
        let response = self.client.send(HttpRequest::post_json(url, body))?;
        handle_response(method, response, self.trace_http)
    }

    fn url(&self, method: &str) -> String {
        api_url(&self.base_path, self.api_key.as_deref(), method)
    }
}

const API_KEY_PARAMETER: &str = "api-key=";

/// `text` with the value after every `api-key=` replaced by `redacted`. The
/// value ends at the first character a query value does not use unencoded.
fn redact_api_key(text: &str) -> Cow<'_, str> {
    let lowercase = text.to_ascii_lowercase();
    if !lowercase.contains(API_KEY_PARAMETER) {
        return Cow::Borrowed(text);
    }
    let mut redacted = String::with_capacity(text.len());
    let mut start = 0;
    while let Some(found) = lowercase
        .get(start..)
        .and_then(|rest| rest.find(API_KEY_PARAMETER))
    {
        let value_start = start + found + API_KEY_PARAMETER.len();
        let rest = text.get(value_start..).unwrap_or_default();
        let value_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || "-._~%+/=".contains(c)))
            .unwrap_or(rest.len());
        redacted.push_str(text.get(start..value_start).unwrap_or_default());
        redacted.push_str("redacted");
        start = value_start + value_len;
    }
    redacted.push_str(text.get(start..).unwrap_or_default());
    Cow::Owned(redacted)
}

fn optional_limit(value: Option<u64>) -> Result<Option<Limit>, ApiError> {
    value
        .map(|value| {
            Limit::new(value).map_err(|message| ApiError::InvalidRequest {
                field: "limit",
                message,
            })
        })
        .transpose()
}

fn required_limit(value: u64) -> Result<Limit, ApiError> {
    Limit::new(value).map_err(|message| ApiError::InvalidRequest {
        field: "limit",
        message,
    })
}

fn unwrap_response<M>(response: JsonRpcResponse<M::Response>) -> Result<M::Response, ApiError>
where
    M: RpcMethod,
{
    if let Some(error) = response.error {
        return Err(ApiError::JsonRpc {
            method: M::NAME,
            code: error.code,
            message: error.message,
        });
    }
    response.result.ok_or(ApiError::MissingResult(M::NAME))
}

fn parse_url(url: &str) -> (String, Option<String>) {
    let Some(query_start) = url.find('?') else {
        return (url.to_string(), None);
    };
    let base = &url[..query_start];
    let query = &url[query_start + 1..];
    for parameter in query.split('&') {
        if let Some(value) = parameter.strip_prefix("api-key=") {
            return (base.to_string(), Some(value.to_string()));
        }
    }
    (url.to_string(), None)
}

fn api_url(base_path: &str, api_key: Option<&str>, method: &str) -> String {
    let mut url = format!("{}/{}", base_path.trim_end_matches('/'), method);
    if let Some(api_key) = api_key {
        url.push_str("?api-key=");
        url.push_str(api_key);
    }
    url
}

fn encode_body<B>(body: &B) -> Result<Vec<u8>, ApiError>
where
    B: Serialize + ?Sized,
{
    serde_json::to_vec(body).map_err(|_| ApiError::InvalidRequest {
        field: "params",
        message: "cannot be encoded as JSON",
    })
}

fn handle_response<R>(method: &str, response: HttpResponse, trace_http: bool) -> Result<R, ApiError>
where
    R: DeserializeOwned,
{
    let HttpResponse { status, body } = response;
    if trace_http {
        print_api_response(method, status, &body);
    }
    if !status.is_success() {
        return Err(ApiError::Response { status, body });
    }
    parse_json_response(status, body)
}

fn print_api_request(url: &str, body: &[u8]) {
    println!(
        "Photon API request:\n{}",
        curl_command(url, &String::from_utf8_lossy(body))
    );
}

fn print_api_response(method: &str, status: reqwest::StatusCode, body: &str) {
    println!(
        "Photon API response {method} {status}:\n{}",
        pretty_json(body)
    );
}

fn curl_command(url: &str, body_json: &str) -> String {
    format!(
        "curl -sS -X POST {} -H 'content-type: application/json' -d {}",
        shell_quote(url),
        shell_quote(body_json)
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'\''"#))
}

fn pretty_json(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .and_then(|value| serde_json::to_string_pretty(&value))
        .unwrap_or_else(|_| body.to_string())
}

fn parse_json_response<R>(status: reqwest::StatusCode, body: String) -> Result<R, ApiError>
where
    R: DeserializeOwned,
{
    let mut deserializer = serde_json::Deserializer::from_str(&body);
    serde_path_to_error::deserialize(&mut deserializer).map_err(|error| ApiError::Response {
        status,
        body: format!(
            "failed to decode JSON response at {}: {}; body: {body}",
            error.path(),
            error.inner()
        ),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use zolana_indexer_api::{GET_ENCRYPTED_UTXOS_BY_TAGS, GET_MERKLE_PROOFS};

    const NO_TRANSACTIONS: &str = r#"{"jsonrpc":"2.0","id":"test-account","result":{"context":{"blockTime":0,"slot":7},"transactions":[]}}"#;

    /// Answers every request with one status and body, or fails before a
    /// response when `status` is 0, and records the requests it was sent.
    #[derive(Debug)]
    struct FakeClient {
        status: u16,
        body: &'static str,
        requests: Arc<Mutex<Vec<HttpRequest>>>,
    }

    impl FakeClient {
        fn answering(status: u16, body: &'static str) -> Self {
            Self {
                status,
                body,
                requests: Arc::default(),
            }
        }

        fn answer(&self, request: HttpRequest) -> Result<HttpResponse, ApiError> {
            self.requests.lock().unwrap().push(request);
            match reqwest::StatusCode::from_u16(self.status) {
                Ok(status) => Ok(HttpResponse {
                    status,
                    body: self.body.to_string(),
                }),
                Err(_) => Err(ApiError::HttpClient("offline".into())),
            }
        }
    }

    impl BlockingHttpClient for FakeClient {
        fn send(&self, request: HttpRequest) -> Result<HttpResponse, ApiError> {
            self.answer(request)
        }
    }

    impl HttpClient for FakeClient {
        fn send<'a>(&'a self, request: HttpRequest) -> HttpFuture<'a> {
            Box::pin(async move { self.answer(request) })
        }
    }

    fn assert_signature_request(requests: &Mutex<Vec<HttpRequest>>) {
        let request = requests.lock().unwrap().pop().expect("one request");
        assert_eq!(request.method, Method::POST);
        assert_eq!(
            request.url,
            "https://rpc.example.test/v1/getShieldedTransactionsBySignature?api-key=secret"
        );
        assert_eq!(
            request.headers.get(CONTENT_TYPE).map(HeaderValue::as_bytes),
            Some(b"application/json".as_slice())
        );
        assert_eq!(request.timeout, None);
        let body: serde_json::Value =
            serde_json::from_slice(request.body.as_slice()).expect("the API sends JSON");
        assert_eq!(body["jsonrpc"], JSON_RPC_VERSION);
        assert_eq!(body["method"], "getShieldedTransactionsBySignature");
        assert!(body["params"]["txSignature"].is_string(), "{body}");
    }

    #[test]
    fn blocking_api_sends_through_its_client() {
        let client = FakeClient::answering(200, NO_TRANSACTIONS);
        let requests = client.requests.clone();
        let api =
            BlockingZolanaApi::with_client("https://rpc.example.test/v1?api-key=secret", client);
        let response = api
            .get_shielded_transactions_by_signature(SerializableSignature::default())
            .unwrap();
        assert_eq!(response.context.slot, 7);
        assert_signature_request(&requests);
    }

    #[tokio::test]
    async fn async_api_sends_through_its_client() {
        let client = FakeClient::answering(200, NO_TRANSACTIONS);
        let requests = client.requests.clone();
        let api = ZolanaApi::with_client("https://rpc.example.test/v1?api-key=secret", client);
        let response = api
            .get_shielded_transactions_by_signature(SerializableSignature::default())
            .await
            .unwrap();
        assert_eq!(response.context.slot, 7);
        assert_signature_request(&requests);
    }

    #[test]
    fn client_answers_keep_their_errors() {
        let call = |status, body| {
            BlockingZolanaApi::with_client(
                "https://rpc.example.test",
                FakeClient::answering(status, body),
            )
            .get_shielded_transactions_by_signature(SerializableSignature::default())
        };
        assert!(matches!(
            call(429, "slow down"),
            Err(ApiError::Response { status, body })
                if status == reqwest::StatusCode::TOO_MANY_REQUESTS && body == "slow down"
        ));
        assert!(matches!(
            call(
                200,
                r#"{"jsonrpc":"2.0","id":"test-account","error":{"code":-32603,"message":"Internal error"}}"#
            ),
            Err(ApiError::JsonRpc {
                code: Some(-32603),
                ..
            })
        ));
        assert!(matches!(
            call(200, "not json"),
            Err(ApiError::Response { .. })
        ));
        let error = call(0, "").unwrap_err();
        assert!(matches!(error, ApiError::HttpClient(_)));
        assert_eq!(error.to_string(), "HTTP client error: offline");
    }

    #[test]
    fn errors_mask_the_api_key() {
        let error = ApiError::HttpClient(
            "connect error for https://gw.test/v1?API-KEY=SECRET-1&page=2 and https://gw.test/v1?api-key=SECRET-2"
                .into(),
        );
        assert_eq!(
            error.to_string(),
            "HTTP client error: connect error for https://gw.test/v1?API-KEY=redacted&page=2 and https://gw.test/v1?api-key=redacted"
        );
        let error =
            ApiError::ResponseLost("reset reading https://gw.test/v1?api-key=SECRET".into());
        assert_eq!(
            error.to_string(),
            "failed to read response body: reset reading https://gw.test/v1?api-key=redacted"
        );
        assert_eq!(
            ApiError::HttpClient("offline".into()).to_string(),
            "HTTP client error: offline"
        );
    }

    #[test]
    fn a_request_prints_no_secret() {
        let request = HttpRequest::post_json(
            "https://gw.test/v1/prove?api-key=SECRET",
            br#"{"nullifierSecret":"WITNESS"}"#.to_vec(),
        )
        .with_header(
            HeaderName::from_static("x-token"),
            HeaderValue::from_static("TOKEN"),
        );
        let printed = format!("{request:?}");
        assert!(printed.contains("api-key=redacted"), "{printed}");
        assert!(printed.contains("x-token"), "{printed}");
        assert!(printed.contains("body_len: 29"), "{printed}");
        for secret in ["SECRET", "WITNESS", "TOKEN"] {
            assert!(!printed.contains(secret), "{printed}");
        }
    }

    #[test]
    fn extracts_api_key_from_url() {
        let api = ZolanaApi::new("https://rpc.example.test?api-key=secret");
        assert_eq!(api.base_path(), "https://rpc.example.test");
        assert_eq!(api.api_key(), Some("secret"));
        assert_eq!(
            api.url(GET_MERKLE_PROOFS),
            "https://rpc.example.test/getMerkleProofs?api-key=secret"
        );
    }

    #[test]
    fn leaves_plain_urls_unchanged() {
        let api = ZolanaApi::new("http://127.0.0.1:8784");
        assert_eq!(api.base_path(), "http://127.0.0.1:8784");
        assert_eq!(api.api_key(), None);
        assert_eq!(
            api.url(GET_ENCRYPTED_UTXOS_BY_TAGS),
            "http://127.0.0.1:8784/getEncryptedUtxosByTags"
        );
    }

    #[test]
    fn blocking_client_uses_same_url_shape() {
        let api = BlockingZolanaApi::new("https://rpc.example.test?api-key=secret");
        assert_eq!(api.base_path(), "https://rpc.example.test");
        assert_eq!(api.api_key(), Some("secret"));
        assert_eq!(
            api.url(GetNonInclusionProofs::NAME),
            "https://rpc.example.test/getNonInclusionProofs?api-key=secret"
        );
    }

    #[test]
    fn rejects_out_of_range_page_limit_before_transport() {
        assert!(matches!(
            optional_limit(Some(0)),
            Err(ApiError::InvalidRequest { field: "limit", .. })
        ));
        assert!(optional_limit(Some(1)).is_ok());
        assert!(matches!(
            required_limit(zolana_indexer_api::PAGE_LIMIT + 1),
            Err(ApiError::InvalidRequest { field: "limit", .. })
        ));
        assert!(required_limit(zolana_indexer_api::PAGE_LIMIT).is_ok());
    }
}
