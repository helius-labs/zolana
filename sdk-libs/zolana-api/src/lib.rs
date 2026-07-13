//! Async and blocking transports for the Zolana indexer JSON-RPC contract.

use std::{error::Error as StdError, fmt};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zolana_indexer_api::{
    method::{
        GetEncryptedUtxosByTags, GetMerkleProofs, GetNonInclusionProofs, GetNullifierQueueElements,
        GetShieldedTransactionsByTags,
    },
    RpcMethod,
};

pub use zolana_indexer_api::{
    Base64String, Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse,
    GetMerkleProofsRequest, GetMerkleProofsResponse, GetNonInclusionProofsRequest,
    GetNonInclusionProofsResponse, GetNullifierQueueElementsRequest,
    GetNullifierQueueElementsResponse, GetRingsByTagsRequest,
    GetShieldedTransactionsByTagsResponse, Hash, Limit, MerkleContext, MerkleProof,
    NonInclusionProof, NullifierQueueElement, RingsOutputContext, RingsOutputSlot,
    SerializablePubkey, SerializableSignature, ShieldedTransaction,
};

const JSON_RPC_VERSION: &str = "2.0";
const REQUEST_ID: &str = "test-account";

#[derive(Clone, Debug)]
pub struct ZolanaApi {
    base_path: String,
    api_key: Option<String>,
    client: reqwest::Client,
    trace_http: bool,
}

#[derive(Clone, Debug)]
pub struct BlockingZolanaApi {
    base_path: String,
    api_key: Option<String>,
    client: reqwest::blocking::Client,
    trace_http: bool,
}

#[derive(Debug)]
pub enum ApiError {
    Request(reqwest::Error),
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

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => write!(formatter, "request error: {error}"),
            Self::Response { status, body } => {
                write!(formatter, "HTTP response error {status}: {body}")
            }
            Self::JsonRpc {
                method,
                code,
                message,
            } => write!(
                formatter,
                "JSON-RPC error from {method}: code={code:?} message={message:?}"
            ),
            Self::InvalidRequest { field, message } => {
                write!(formatter, "invalid {field}: {message}")
            }
            Self::MissingResult(method) => {
                write!(formatter, "JSON-RPC response from {method} omitted result")
            }
        }
    }
}

impl StdError for ApiError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Request(error) => Some(error),
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
        let (base_path, api_key) = parse_url(url.as_ref());
        Self {
            base_path,
            api_key,
            client: reqwest::Client::new(),
            trace_http: false,
        }
    }

    pub fn with_client(url: impl AsRef<str>, client: reqwest::Client) -> Self {
        let (base_path, api_key) = parse_url(url.as_ref());
        Self {
            base_path,
            api_key,
            client,
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
        if self.trace_http {
            print_api_request(&url, body);
        }
        let response = self.client.post(&url).json(body).send().await?;
        let status = response.status();
        let response_body = response.text().await?;
        if self.trace_http {
            print_api_response(method, status, &response_body);
        }
        if !status.is_success() {
            return Err(ApiError::Response {
                status,
                body: response_body,
            });
        }
        parse_json_response(status, response_body)
    }

    fn url(&self, method: &str) -> String {
        api_url(&self.base_path, self.api_key.as_deref(), method)
    }
}

impl BlockingZolanaApi {
    pub fn new(url: impl AsRef<str>) -> Self {
        let (base_path, api_key) = parse_url(url.as_ref());
        Self {
            base_path,
            api_key,
            client: reqwest::blocking::Client::new(),
            trace_http: false,
        }
    }

    pub fn with_client(url: impl AsRef<str>, client: reqwest::blocking::Client) -> Self {
        let (base_path, api_key) = parse_url(url.as_ref());
        Self {
            base_path,
            api_key,
            client,
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
        if self.trace_http {
            print_api_request(&url, body);
        }
        let response = self.client.post(&url).json(body).send()?;
        let status = response.status();
        let response_body = response.text()?;
        if self.trace_http {
            print_api_response(method, status, &response_body);
        }
        if !status.is_success() {
            return Err(ApiError::Response {
                status,
                body: response_body,
            });
        }
        parse_json_response(status, response_body)
    }

    fn url(&self, method: &str) -> String {
        api_url(&self.base_path, self.api_key.as_deref(), method)
    }
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

fn print_api_request<B>(url: &str, body: &B)
where
    B: Serialize + ?Sized,
{
    let body_json = serde_json::to_string(body)
        .unwrap_or_else(|error| format!(r#"{{"serialization_error":"{error}"}}"#));
    println!("Photon API request:\n{}", curl_command(url, &body_json));
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
    use super::*;
    use zolana_indexer_api::{GET_ENCRYPTED_UTXOS_BY_TAGS, GET_MERKLE_PROOFS};

    #[test]
    fn extracts_api_key_from_url() {
        let api = ZolanaApi::new("https://rpc.example.test?api-key=secret");
        assert_eq!(api.base_path(), "https://rpc.example.test");
        assert_eq!(api.api_key(), Some("secret"));
        assert_eq!(
            api.url(GET_MERKLE_PROOFS),
            "https://rpc.example.test/get_merkle_proofs?api-key=secret"
        );
    }

    #[test]
    fn leaves_plain_urls_unchanged() {
        let api = ZolanaApi::new("http://127.0.0.1:8784");
        assert_eq!(api.base_path(), "http://127.0.0.1:8784");
        assert_eq!(api.api_key(), None);
        assert_eq!(
            api.url(GET_ENCRYPTED_UTXOS_BY_TAGS),
            "http://127.0.0.1:8784/get_encrypted_utxos_by_tags"
        );
    }

    #[test]
    fn blocking_client_uses_same_url_shape() {
        let api = BlockingZolanaApi::new("https://rpc.example.test?api-key=secret");
        assert_eq!(api.base_path(), "https://rpc.example.test");
        assert_eq!(api.api_key(), Some("secret"));
        assert_eq!(
            api.url(GetNonInclusionProofs::NAME),
            "https://rpc.example.test/get_non_inclusion_proofs?api-key=secret"
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
