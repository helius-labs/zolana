use std::{
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_transaction_status_client_types::{TransactionDetails, UiConfirmedBlock};
use thiserror::Error;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Clone, Debug)]
pub struct RpcClient {
    http: Client,
    url: String,
    fixture: Result<bool, String>,
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("RPC transport failed: {0}")]
    Transport(reqwest::Error),
    #[error("RPC method {method} failed with code {code}: {message}")]
    Response {
        method: &'static str,
        code: i64,
        message: String,
    },
    #[error("RPC method {0} returned no result")]
    MissingResult(&'static str),
    #[error("invalid account returned by RPC: {0}")]
    InvalidAccount(String),
    #[error("invalid Surfpool fixture configuration {0}")]
    FixtureConfiguration(String),
}

impl RpcError {
    fn transport(error: reqwest::Error) -> Self {
        Self::Transport(error.without_url())
    }

    pub fn response_code(&self) -> Option<i64> {
        match self {
            Self::Response { code, .. } => Some(*code),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ContextValue<T> {
    value: T,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncodedAccount {
    lamports: u64,
    data: (String, String),
    owner: String,
    executable: bool,
    rent_epoch: u64,
}

#[derive(Debug, Deserialize)]
struct ProgramAccount {
    pubkey: String,
    account: EncodedAccount,
}

impl RpcClient {
    pub fn new(url: String) -> Self {
        let fixture = fixture_mode(
            &url,
            std::env::var_os("ZOLANA_RING_SURFPOOL_FIXTURE").as_deref(),
            std::env::var_os("ZOLANA_PROCESS_SCOPE_DIR").as_deref(),
        );
        Self {
            http: Client::new(),
            url,
            fixture,
        }
    }

    pub async fn get_slot(&self) -> Result<u64, RpcError> {
        self.call("getSlot", json!([{ "commitment": "confirmed" }]))
            .await
    }

    pub async fn get_genesis_hash(&self) -> Result<String, RpcError> {
        self.call("getGenesisHash", json!([])).await
    }

    pub async fn get_block(
        &self,
        slot: u64,
        transaction_details: TransactionDetails,
    ) -> Result<UiConfirmedBlock, RpcError> {
        let fixture = *self
            .fixture
            .as_ref()
            .map_err(|error| RpcError::FixtureConfiguration(error.clone()))?;
        let mut block: UiConfirmedBlock = self
            .call("getBlock", block_params(slot, transaction_details))
            .await?;
        if fixture {
            let parent: UiConfirmedBlock = self
                .call(
                    "getBlock",
                    block_params(block.parent_slot, TransactionDetails::None),
                )
                .await?;
            normalize_fixture_header(&mut block, &parent)?;
        }
        Ok(block)
    }

    pub async fn get_blocks(
        &self,
        slots: std::ops::RangeInclusive<u64>,
    ) -> Result<Vec<u64>, RpcError> {
        self.call(
            "getBlocks",
            json!([slots.start(), slots.end(), { "commitment": "confirmed" }]),
        )
        .await
    }

    pub async fn get_account(&self, pubkey: &Pubkey) -> Result<Account, RpcError> {
        let response: ContextValue<Option<EncodedAccount>> = self
            .call(
                "getAccountInfo",
                json!([pubkey.to_string(), account_config()]),
            )
            .await?;
        response
            .value
            .ok_or_else(|| RpcError::InvalidAccount(format!("account {pubkey} does not exist")))?
            .decode()
    }

    pub async fn get_multiple_accounts(
        &self,
        pubkeys: &[Pubkey],
    ) -> Result<Vec<Option<Account>>, RpcError> {
        let addresses = pubkeys.iter().map(ToString::to_string).collect::<Vec<_>>();
        let response: ContextValue<Vec<Option<EncodedAccount>>> = self
            .call("getMultipleAccounts", json!([addresses, account_config()]))
            .await?;
        response
            .value
            .into_iter()
            .map(|account| account.map(EncodedAccount::decode).transpose())
            .collect()
    }

    pub async fn get_program_accounts(
        &self,
        program_id: &Pubkey,
    ) -> Result<Vec<(Pubkey, Account)>, RpcError> {
        let accounts: Vec<ProgramAccount> = self
            .call(
                "getProgramAccounts",
                json!([program_id.to_string(), account_config()]),
            )
            .await?;
        accounts
            .into_iter()
            .map(|item| {
                let pubkey = Pubkey::from_str(&item.pubkey).map_err(|error| {
                    RpcError::InvalidAccount(format!("invalid pubkey {}: {error}", item.pubkey))
                })?;
                Ok((pubkey, item.account.decode()?))
            })
            .collect()
    }

    async fn call<T>(&self, method: &'static str, params: Value) -> Result<T, RpcError>
    where
        T: DeserializeOwned,
    {
        static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

        let response = self
            .http
            .post(&self.url)
            .timeout(DEFAULT_TIMEOUT)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": REQUEST_ID.fetch_add(1, Ordering::Relaxed),
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .map_err(RpcError::transport)?;
        let status_error = response.error_for_status_ref().err();
        let response = match response.json::<JsonRpcResponse<T>>().await {
            Ok(response) => response,
            Err(error) => {
                return Err(RpcError::transport(status_error.unwrap_or(error)));
            }
        };
        if let Some(error) = response.error {
            return Err(RpcError::Response {
                method,
                code: error.code,
                message: error.message,
            });
        }
        response.result.ok_or(RpcError::MissingResult(method))
    }
}

fn fixture_mode(
    url: &str,
    opt_in: Option<&std::ffi::OsStr>,
    scope: Option<&std::ffi::OsStr>,
) -> Result<bool, String> {
    let Some(opt_in) = opt_in else {
        return Ok(false);
    };
    if !cfg!(feature = "surfpool-fixture") {
        return Err("binary lacks surfpool-fixture support".into());
    }
    if opt_in != "1" {
        return Err("ZOLANA_RING_SURFPOOL_FIXTURE must equal 1".into());
    }
    let loopback = reqwest::Url::parse(url).ok().is_some_and(|url| {
        url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
    });
    let scope = scope
        .map(std::path::Path::new)
        .ok_or("task scope is required")?;
    let metadata = std::fs::symlink_metadata(scope).map_err(|_| "task scope is missing")?;
    let canonical = std::fs::canonicalize(scope).map_err(|_| "task scope is invalid")?;
    if !loopback
        || !scope.is_absolute()
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || canonical.parent().is_none()
        || std::env::var_os("HOME").is_some_and(|home| canonical == home)
    {
        return Err("fixture needs loopback RPC and a dedicated absolute task directory".into());
    }
    Ok(true)
}

fn normalize_fixture_header(
    block: &mut UiConfirmedBlock,
    parent: &UiConfirmedBlock,
) -> Result<(), RpcError> {
    if [
        &block.blockhash,
        &block.previous_blockhash,
        &parent.blockhash,
    ]
    .into_iter()
    .any(|hash| !hash.starts_with("SURFNETxSAFEHASH"))
    {
        return Err(RpcError::FixtureConfiguration(
            "only Surfpool synthetic block headers are supported".into(),
        ));
    }
    block.previous_blockhash = parent.blockhash.clone();
    Ok(())
}

impl EncodedAccount {
    fn decode(self) -> Result<Account, RpcError> {
        if self.data.1 != "base64" {
            return Err(RpcError::InvalidAccount(format!(
                "unsupported account encoding {}",
                self.data.1
            )));
        }
        let data = BASE64
            .decode(self.data.0)
            .map_err(|error| RpcError::InvalidAccount(format!("invalid base64 data: {error}")))?;
        let owner = Pubkey::from_str(&self.owner).map_err(|error| {
            RpcError::InvalidAccount(format!("invalid owner {}: {error}", self.owner))
        })?;
        Ok(Account {
            lamports: self.lamports,
            data,
            owner,
            executable: self.executable,
            rent_epoch: self.rent_epoch,
        })
    }
}

fn account_config() -> Value {
    json!({
        "commitment": "confirmed",
        "encoding": "base64",
    })
}

fn block_params(slot: u64, transaction_details: TransactionDetails) -> Value {
    json!([slot, {
        "commitment": "confirmed",
        "encoding": "base64",
        // A block holding a newer version is refused whole, not skipped.
        "maxSupportedTransactionVersion": 1,
        "rewards": false,
        "transactionDetails": transaction_details,
    }])
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread::JoinHandle,
    };

    use super::*;

    fn serve_once(status: &str, body: &str) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        });
        (format!("http://{address}"), handle)
    }

    #[test]
    fn fixture_only_normalizes_surfpool_parent_links() {
        let mut block:UiConfirmedBlock=serde_json::from_value(json!({"blockhash":"SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxxxxxxxx28","previousBlockhash":"SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxxxxxxxxxx","parentSlot":39,"blockTime":1,"blockHeight":40})).unwrap();
        let mut parent = block.clone();
        parent.blockhash = "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxxxxxxxx27".into();
        let original = block.blockhash.clone();
        normalize_fixture_header(&mut block, &parent).unwrap();
        assert_eq!(block.previous_blockhash, parent.blockhash);
        assert_eq!(block.blockhash, original);
        parent.blockhash = "11111111111111111111111111111111".into();
        assert!(matches!(
            normalize_fixture_header(&mut block, &parent),
            Err(RpcError::FixtureConfiguration(_))
        ));
        assert_eq!(fixture_mode("http://127.0.0.1:8899", None, None), Ok(false));
        assert!(fixture_mode(
            "https://api.mainnet-beta.solana.com",
            Some(std::ffi::OsStr::new("1")),
            None
        )
        .is_err());
    }

    #[test]
    fn decodes_base64_accounts_without_account_decoder_crate() {
        let owner = Pubkey::from([7; 32]);
        let account = EncodedAccount {
            lamports: 42,
            data: (BASE64.encode([1, 2, 3]), "base64".to_string()),
            owner: owner.to_string(),
            executable: true,
            rent_epoch: 9,
        }
        .decode()
        .unwrap();
        assert_eq!(account.lamports, 42);
        assert_eq!(account.data, [1, 2, 3]);
        assert_eq!(account.owner, owner);
        assert!(account.executable);
        assert_eq!(account.rent_epoch, 9);
    }

    #[test]
    fn preserves_rpc_response_codes() {
        let error = RpcError::Response {
            method: "getBlock",
            code: -32007,
            message: "skipped".to_string(),
        };
        assert_eq!(error.response_code(), Some(-32007));
    }

    #[tokio::test]
    async fn preserves_json_rpc_error_from_non_success_http_response() {
        let (url, server) = serve_once(
            "503 Service Unavailable",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32007,"message":"skipped"}}"#,
        );
        let error = RpcClient::new(url)
            .get_block(42, TransactionDetails::Full)
            .await
            .unwrap_err();
        server.join().unwrap();

        assert_eq!(error.response_code(), Some(-32007));
    }

    #[tokio::test]
    async fn transport_errors_do_not_expose_rpc_url_query() {
        let (url, server) = serve_once("502 Bad Gateway", "not JSON");
        let error = RpcClient::new(format!("{url}?api-key=super-secret"))
            .get_slot()
            .await
            .unwrap_err();
        server.join().unwrap();

        let message = error.to_string();
        assert!(!message.contains("api-key"));
        assert!(!message.contains("super-secret"));
    }

    #[tokio::test]
    async fn preserves_null_result_from_non_success_http_response() {
        let (url, server) = serve_once(
            "503 Service Unavailable",
            r#"{"jsonrpc":"2.0","id":1,"result":null}"#,
        );
        let error = RpcClient::new(url).get_slot().await.unwrap_err();
        server.join().unwrap();

        assert!(matches!(error, RpcError::MissingResult("getSlot")));
    }

    #[test]
    fn block_request_matches_solana_rpc_wire_format() {
        assert_eq!(
            block_params(42, TransactionDetails::Full),
            json!([42, {
                "commitment": "confirmed",
                "encoding": "base64",
                "maxSupportedTransactionVersion": 1,
                "rewards": false,
                "transactionDetails": "full",
            }])
        );
    }
}
