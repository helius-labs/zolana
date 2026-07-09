//! Typed client for Photon's Rings-only indexer API.
//!
//! Types are generated from `src/openapi/specs/zolana.yaml` in the Photon
//! checkout and checked in as `src/codegen.rs`.

#![allow(clippy::large_enum_variant)]

use std::{error::Error as StdError, fmt, sync::Once};

use serde::{de::DeserializeOwned, Serialize};

pub mod generated {
    #![allow(unused_imports, clippy::all, dead_code)]
    #![allow(mismatched_lifetime_syntaxes)]

    include!("codegen.rs");
}

pub use generated::types;

pub type Base64String = types::Base64String;
pub type Context = types::Context;
pub type EncryptedUtxoMatch = types::EncryptedUtxoMatch;
pub type GetEncryptedUtxosByTagsResponse = types::PostGetEncryptedUtxosByTagsResponseResult;
pub type GetMerkleProofsResponse = types::PostGetMerkleProofsResponseResult;
pub type GetNonInclusionProofsResponse = types::PostGetNonInclusionProofsResponseResult;
pub type GetShieldedTransactionsByTagsResponse =
    types::PostGetShieldedTransactionsByTagsResponseResult;
pub type Hash = types::Hash;
pub type Limit = types::Limit;
pub type MerkleContext = types::MerkleContext;
pub type MerkleProof = types::MerkleProof;
pub type NonInclusionProof = types::NonInclusionProof;
pub type NullifierQueueElement = types::NullifierQueueElement;
pub type GetNullifierQueueElementsResponse = types::PostGetNullifierQueueElementsResponseResult;
pub type SerializablePubkey = types::SerializablePubkey;
pub type SerializableSignature = types::SerializableSignature;
pub type ShieldedTransaction = types::ShieldedTransaction;
pub type RingsOutputContext = types::RingsOutputContext;
pub type RingsOutputSlot = types::RingsOutputSlot;

#[derive(Clone, Debug)]
pub struct RingsApi {
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
    MissingResult(&'static str),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(err) => write!(f, "request error: {err}"),
            Self::Response { status, body } => {
                write!(f, "HTTP response error {status}: {body}")
            }
            Self::JsonRpc {
                method,
                code,
                message,
            } => write!(
                f,
                "JSON-RPC error from {method}: code={code:?} message={message:?}"
            ),
            Self::MissingResult(method) => {
                write!(f, "JSON-RPC response from {method} omitted result")
            }
        }
    }
}

impl StdError for ApiError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Request(err) => Some(err),
            _ => None,
        }
    }
}

impl From<reqwest::Error> for ApiError {
    fn from(err: reqwest::Error) -> Self {
        Self::Request(err)
    }
}

impl RingsApi {
    pub fn new(url: impl AsRef<str>) -> Self {
        ensure_ring_provider();
        let (base_path, api_key) = parse_url(url.as_ref());
        Self {
            base_path,
            api_key,
            client: reqwest::Client::new(),
            trace_http: false,
        }
    }

    pub fn with_client(url: impl AsRef<str>, client: reqwest::Client) -> Self {
        ensure_ring_provider();
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
        let method = "get_encrypted_utxos_by_tags";
        let body = types::PostGetEncryptedUtxosByTagsBody {
            id: types::PostGetEncryptedUtxosByTagsBodyId::TestAccount,
            jsonrpc: types::PostGetEncryptedUtxosByTagsBodyJsonrpc::X20,
            method: types::PostGetEncryptedUtxosByTagsBodyMethod::GetEncryptedUtxosByTags,
            params: types::PostGetEncryptedUtxosByTagsBodyParams {
                cursor,
                limit: limit.and_then(|value| ::std::num::NonZeroU64::new(value).map(types::Limit)),
                tags,
            },
        };
        let response: types::PostGetEncryptedUtxosByTagsResponse = self.post(method, &body).await?;
        if let Some(error) = response.error {
            return Err(ApiError::JsonRpc {
                method,
                code: error.code,
                message: error.message,
            });
        }
        response.result.ok_or(ApiError::MissingResult(method))
    }

    pub async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<Hash>,
        cursor: Option<Base64String>,
        limit: Option<u64>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ApiError> {
        let method = "get_shielded_transactions_by_tags";
        let body = types::PostGetShieldedTransactionsByTagsBody {
            id: types::PostGetShieldedTransactionsByTagsBodyId::TestAccount,
            jsonrpc: types::PostGetShieldedTransactionsByTagsBodyJsonrpc::X20,
            method:
                types::PostGetShieldedTransactionsByTagsBodyMethod::GetShieldedTransactionsByTags,
            params: types::PostGetShieldedTransactionsByTagsBodyParams {
                cursor,
                limit: limit.and_then(|value| ::std::num::NonZeroU64::new(value).map(types::Limit)),
                tags,
            },
        };
        let response: types::PostGetShieldedTransactionsByTagsResponse =
            self.post(method, &body).await?;
        if let Some(error) = response.error {
            return Err(ApiError::JsonRpc {
                method,
                code: error.code,
                message: error.message,
            });
        }
        response.result.ok_or(ApiError::MissingResult(method))
    }

    pub async fn get_merkle_proofs(
        &self,
        tree_account: SerializablePubkey,
        leaves: Vec<Hash>,
    ) -> Result<GetMerkleProofsResponse, ApiError> {
        let method = "get_merkle_proofs";
        let body = types::PostGetMerkleProofsBody {
            id: types::PostGetMerkleProofsBodyId::TestAccount,
            jsonrpc: types::PostGetMerkleProofsBodyJsonrpc::X20,
            method: types::PostGetMerkleProofsBodyMethod::GetMerkleProofs,
            params: types::PostGetMerkleProofsBodyParams {
                leaves,
                tree_account,
            },
        };
        let response: types::PostGetMerkleProofsResponse = self.post(method, &body).await?;
        if let Some(error) = response.error {
            return Err(ApiError::JsonRpc {
                method,
                code: error.code,
                message: error.message,
            });
        }
        response.result.ok_or(ApiError::MissingResult(method))
    }

    pub async fn get_non_inclusion_proofs(
        &self,
        tree_account: SerializablePubkey,
        leaves: Vec<Hash>,
    ) -> Result<GetNonInclusionProofsResponse, ApiError> {
        let method = "get_non_inclusion_proofs";
        let body = types::PostGetNonInclusionProofsBody {
            id: types::PostGetNonInclusionProofsBodyId::TestAccount,
            jsonrpc: types::PostGetNonInclusionProofsBodyJsonrpc::X20,
            method: types::PostGetNonInclusionProofsBodyMethod::GetNonInclusionProofs,
            params: types::PostGetNonInclusionProofsBodyParams {
                leaves,
                tree_account,
            },
        };
        let response: types::PostGetNonInclusionProofsResponse = self.post(method, &body).await?;
        if let Some(error) = response.error {
            return Err(ApiError::JsonRpc {
                method,
                code: error.code,
                message: error.message,
            });
        }
        response.result.ok_or(ApiError::MissingResult(method))
    }

    pub async fn get_nullifier_queue_elements(
        &self,
        tree_account: SerializablePubkey,
        start_seq: Option<u64>,
        limit: u64,
    ) -> Result<GetNullifierQueueElementsResponse, ApiError> {
        let method = "get_nullifier_queue_elements";
        let body = types::PostGetNullifierQueueElementsBody {
            id: types::PostGetNullifierQueueElementsBodyId::TestAccount,
            jsonrpc: types::PostGetNullifierQueueElementsBodyJsonrpc::X20,
            method: types::PostGetNullifierQueueElementsBodyMethod::GetNullifierQueueElements,
            params: types::PostGetNullifierQueueElementsBodyParams {
                limit,
                start_seq,
                tree_account,
            },
        };
        let response: types::PostGetNullifierQueueElementsResponse =
            self.post(method, &body).await?;
        if let Some(error) = response.error {
            return Err(ApiError::JsonRpc {
                method,
                code: error.code,
                message: error.message,
            });
        }
        response.result.ok_or(ApiError::MissingResult(method))
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
        ensure_ring_provider();
        let (base_path, api_key) = parse_url(url.as_ref());
        Self {
            base_path,
            api_key,
            client: reqwest::blocking::Client::new(),
            trace_http: false,
        }
    }

    pub fn with_client(url: impl AsRef<str>, client: reqwest::blocking::Client) -> Self {
        ensure_ring_provider();
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
        let method = "get_encrypted_utxos_by_tags";
        let body = types::PostGetEncryptedUtxosByTagsBody {
            id: types::PostGetEncryptedUtxosByTagsBodyId::TestAccount,
            jsonrpc: types::PostGetEncryptedUtxosByTagsBodyJsonrpc::X20,
            method: types::PostGetEncryptedUtxosByTagsBodyMethod::GetEncryptedUtxosByTags,
            params: types::PostGetEncryptedUtxosByTagsBodyParams {
                cursor,
                limit: limit.and_then(|value| ::std::num::NonZeroU64::new(value).map(types::Limit)),
                tags,
            },
        };
        let response: types::PostGetEncryptedUtxosByTagsResponse = self.post(method, &body)?;
        if let Some(error) = response.error {
            return Err(ApiError::JsonRpc {
                method,
                code: error.code,
                message: error.message,
            });
        }
        response.result.ok_or(ApiError::MissingResult(method))
    }

    pub fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<Hash>,
        cursor: Option<Base64String>,
        limit: Option<u64>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ApiError> {
        let method = "get_shielded_transactions_by_tags";
        let body = types::PostGetShieldedTransactionsByTagsBody {
            id: types::PostGetShieldedTransactionsByTagsBodyId::TestAccount,
            jsonrpc: types::PostGetShieldedTransactionsByTagsBodyJsonrpc::X20,
            method:
                types::PostGetShieldedTransactionsByTagsBodyMethod::GetShieldedTransactionsByTags,
            params: types::PostGetShieldedTransactionsByTagsBodyParams {
                cursor,
                limit: limit.and_then(|value| ::std::num::NonZeroU64::new(value).map(types::Limit)),
                tags,
            },
        };
        let response: types::PostGetShieldedTransactionsByTagsResponse =
            self.post(method, &body)?;
        if let Some(error) = response.error {
            return Err(ApiError::JsonRpc {
                method,
                code: error.code,
                message: error.message,
            });
        }
        response.result.ok_or(ApiError::MissingResult(method))
    }

    pub fn get_merkle_proofs(
        &self,
        tree_account: SerializablePubkey,
        leaves: Vec<Hash>,
    ) -> Result<GetMerkleProofsResponse, ApiError> {
        let method = "get_merkle_proofs";
        let body = types::PostGetMerkleProofsBody {
            id: types::PostGetMerkleProofsBodyId::TestAccount,
            jsonrpc: types::PostGetMerkleProofsBodyJsonrpc::X20,
            method: types::PostGetMerkleProofsBodyMethod::GetMerkleProofs,
            params: types::PostGetMerkleProofsBodyParams {
                leaves,
                tree_account,
            },
        };
        let response: types::PostGetMerkleProofsResponse = self.post(method, &body)?;
        if let Some(error) = response.error {
            return Err(ApiError::JsonRpc {
                method,
                code: error.code,
                message: error.message,
            });
        }
        response.result.ok_or(ApiError::MissingResult(method))
    }

    pub fn get_non_inclusion_proofs(
        &self,
        tree_account: SerializablePubkey,
        leaves: Vec<Hash>,
    ) -> Result<GetNonInclusionProofsResponse, ApiError> {
        let method = "get_non_inclusion_proofs";
        let body = types::PostGetNonInclusionProofsBody {
            id: types::PostGetNonInclusionProofsBodyId::TestAccount,
            jsonrpc: types::PostGetNonInclusionProofsBodyJsonrpc::X20,
            method: types::PostGetNonInclusionProofsBodyMethod::GetNonInclusionProofs,
            params: types::PostGetNonInclusionProofsBodyParams {
                leaves,
                tree_account,
            },
        };
        let response: types::PostGetNonInclusionProofsResponse = self.post(method, &body)?;
        if let Some(error) = response.error {
            return Err(ApiError::JsonRpc {
                method,
                code: error.code,
                message: error.message,
            });
        }
        response.result.ok_or(ApiError::MissingResult(method))
    }

    pub fn get_nullifier_queue_elements(
        &self,
        tree_account: SerializablePubkey,
        start_seq: Option<u64>,
        limit: u64,
    ) -> Result<GetNullifierQueueElementsResponse, ApiError> {
        let method = "get_nullifier_queue_elements";
        let body = types::PostGetNullifierQueueElementsBody {
            id: types::PostGetNullifierQueueElementsBodyId::TestAccount,
            jsonrpc: types::PostGetNullifierQueueElementsBodyJsonrpc::X20,
            method: types::PostGetNullifierQueueElementsBodyMethod::GetNullifierQueueElements,
            params: types::PostGetNullifierQueueElementsBodyParams {
                limit,
                start_seq,
                tree_account,
            },
        };
        let response: types::PostGetNullifierQueueElementsResponse = self.post(method, &body)?;
        if let Some(error) = response.error {
            return Err(ApiError::JsonRpc {
                method,
                code: error.code,
                message: error.message,
            });
        }
        response.result.ok_or(ApiError::MissingResult(method))
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

fn parse_url(url: &str) -> (String, Option<String>) {
    let Some(query_start) = url.find('?') else {
        return (url.to_string(), None);
    };
    let base = &url[..query_start];
    let query = &url[query_start + 1..];
    for param in query.split('&') {
        if let Some(value) = param.strip_prefix("api-key=") {
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
    serde_json::from_str(&body).map_err(|error| ApiError::Response {
        status,
        body: format!("failed to decode JSON response: {error}; body: {body}"),
    })
}

fn ensure_ring_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_api_key_from_url() {
        let api = RingsApi::new("https://rpc.example.test?api-key=secret");
        assert_eq!(api.base_path(), "https://rpc.example.test");
        assert_eq!(api.api_key(), Some("secret"));
        assert_eq!(
            api.url("get_merkle_proofs"),
            "https://rpc.example.test/get_merkle_proofs?api-key=secret"
        );
    }

    #[test]
    fn leaves_plain_urls_unchanged() {
        let api = RingsApi::new("http://127.0.0.1:8784");
        assert_eq!(api.base_path(), "http://127.0.0.1:8784");
        assert_eq!(api.api_key(), None);
        assert_eq!(
            api.url("get_encrypted_utxos_by_tags"),
            "http://127.0.0.1:8784/get_encrypted_utxos_by_tags"
        );
    }

    #[test]
    fn blocking_client_uses_same_url_shape() {
        let api = BlockingZolanaApi::new("https://rpc.example.test?api-key=secret");
        assert_eq!(api.base_path(), "https://rpc.example.test");
        assert_eq!(api.api_key(), Some("secret"));
        assert_eq!(
            api.url("get_non_inclusion_proofs"),
            "https://rpc.example.test/get_non_inclusion_proofs?api-key=secret"
        );
    }
}
