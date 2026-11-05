use base64::{engine::general_purpose::STANDARD, Engine as _};
use solana_account::Account;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_pubkey::Pubkey;
use solana_rpc_client::api::{
    config::{RpcAccountInfoConfig, RpcProgramAccountsConfig, UiAccountEncoding},
    filter::{Memcmp, MemcmpEncodedBytes, RpcFilterType},
    response::UiAccount,
};

use crate::error::ClientError;
pub use crate::rpc::ProgramAccountsFilter;

impl ProgramAccountsFilter {
    /// The `getProgramAccounts` config the filtered query sends.
    pub fn rpc_config(&self) -> RpcProgramAccountsConfig {
        let memcmp = self.memcmp_filters().map(|(offset, bytes)| {
            let bytes = MemcmpEncodedBytes::Base64(STANDARD.encode(bytes));
            RpcFilterType::Memcmp(Memcmp::new(offset, bytes))
        });
        RpcProgramAccountsConfig {
            filters: Some(
                std::iter::once(RpcFilterType::DataSize(self.data_size() as u64))
                    .chain(memcmp)
                    .collect(),
            ),
            account_config: RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64),
                commitment: Some(CommitmentConfig::confirmed()),
                min_context_slot: self.min_context_slot(),
                ..RpcAccountInfoConfig::default()
            },
            ..RpcProgramAccountsConfig::default()
        }
    }
}

pub(super) fn retryable_account_read(error: &ClientError) -> bool {
    use solana_rpc_client_api::{
        client_error::{reqwest::StatusCode, ErrorKind},
        custom_error::JSON_RPC_SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED,
        request::RpcError,
    };
    use std::io::ErrorKind as IoErrorKind;

    let ClientError::SolanaRpcRead(source) = error else {
        return false;
    };
    match source.kind() {
        ErrorKind::Reqwest(error) => {
            error.is_timeout()
                || error.is_connect()
                || matches!(
                    error.status(),
                    Some(
                        StatusCode::TOO_MANY_REQUESTS
                            | StatusCode::BAD_GATEWAY
                            | StatusCode::SERVICE_UNAVAILABLE
                            | StatusCode::GATEWAY_TIMEOUT
                    )
                )
        }
        ErrorKind::RpcError(RpcError::RpcResponseError { code, .. }) => {
            *code == JSON_RPC_SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED
        }
        ErrorKind::Io(error) => matches!(
            error.kind(),
            IoErrorKind::TimedOut
                | IoErrorKind::ConnectionRefused
                | IoErrorKind::ConnectionReset
                | IoErrorKind::ConnectionAborted
                | IoErrorKind::NotConnected
                | IoErrorKind::BrokenPipe
                | IoErrorKind::Interrupted
        ),
        _ => false,
    }
}

pub(super) fn filtered_program_accounts(
    program: &Address,
    filter: &ProgramAccountsFilter,
    accounts: Vec<(Address, UiAccount)>,
) -> Result<Vec<(Address, Account)>, ClientError> {
    accounts
        .into_iter()
        .map(|(address, ui_account)| {
            let account = ui_account.to_account().ok_or_else(|| {
                ClientError::Rpc(format!(
                    "get_program_accounts {program} returned account {address} in an unsupported encoding"
                ))
            })?;
            if !filter.matches(&account.data) {
                return Err(ClientError::Rpc(format!(
                    "get_program_accounts {program} returned account {address} outside the filter"
                )));
            }
            Ok((address, account))
        })
        .collect()
}

pub(super) fn pubkey_from_address(address: &Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

#[cfg(test)]
mod tests {
    use std::io;

    use solana_rpc_client_api::{
        client_error::{Error as RpcClientError, ErrorKind},
        request::{RpcError, RpcResponseErrorData},
    };

    use super::*;

    #[test]
    fn account_read_conversion_preserves_retryable_transport_kinds() {
        for kind in [io::ErrorKind::TimedOut, io::ErrorKind::ConnectionReset] {
            let source = RpcClientError::from(ErrorKind::Io(io::Error::from(kind)));
            let converted = Result::<(), _>::Err(source)
                .map_err(ClientError::SolanaRpcRead)
                .unwrap_err();
            assert!(retryable_account_read(&converted));
            let rpc = super::super::SolanaRpc::new("http://127.0.0.1:0");
            assert!(crate::rpc::Rpc::should_retry(&rpc, &converted));
            assert!(
                matches!(converted, ClientError::SolanaRpcRead(source) if matches!(source.kind(), ErrorKind::Io(error) if error.kind() == kind))
            );
        }
        for (code, retryable) in [
            (solana_rpc_client_api::custom_error::JSON_RPC_SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED, true),
            (-32601, false),
            (-32602, false),
        ] {
            let source = RpcClientError::from(ErrorKind::RpcError(RpcError::RpcResponseError {
                code,
                message: "request refused".into(),
                data: RpcResponseErrorData::Empty,
            }));
            let converted = Result::<(), _>::Err(source)
                .map_err(ClientError::SolanaRpcRead)
                .unwrap_err();
            assert_eq!(retryable_account_read(&converted), retryable);
        }
        let malformed = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let converted = ClientError::SolanaRpcRead(ErrorKind::SerdeJson(malformed).into());
        assert!(!retryable_account_read(&converted));
        assert!(!retryable_account_read(&ClientError::UnsupportedRpcMethod(
            "get_program_accounts_filtered"
        )));
    }

    #[test]
    fn account_read_conversion_retries_only_named_http_statuses() {
        for (status, retryable) in [
            (429, true),
            (502, true),
            (503, true),
            (504, true),
            (400, false),
            (401, false),
            (403, false),
            (500, false),
        ] {
            let response = http::Response::builder().status(status).body("").unwrap();
            let source = solana_rpc_client_api::client_error::reqwest::Response::from(response)
                .error_for_status()
                .unwrap_err();
            let converted = Result::<(), RpcClientError>::Err(ErrorKind::Reqwest(source).into())
                .map_err(ClientError::SolanaRpcRead)
                .unwrap_err();
            assert_eq!(retryable_account_read(&converted), retryable);
        }
    }

    #[tokio::test]
    async fn account_read_conversion_preserves_http_connect_failures() {
        let client = solana_rpc_client_api::client_error::reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        let sender = solana_rpc_client::http_sender::HttpSender::new_with_client(
            "http://127.0.0.1:0",
            client.clone(),
        );
        let rpc = super::super::AsyncSolanaRpc::with_client(
            solana_rpc_client::nonblocking::rpc_client::RpcClient::new_sender(
                sender,
                solana_rpc_client::rpc_client::RpcClientConfig::default(),
            ),
        );
        let converted = rpc
            .get_program_accounts_filtered(Address::default(), &ProgramAccountsFilter::new(1))
            .await
            .unwrap_err();
        assert!(
            matches!(&converted, ClientError::SolanaRpcRead(source) if matches!(source.kind(), ErrorKind::Reqwest(error) if error.is_connect()))
        );
        assert!(crate::rpc::AsyncRpc::should_retry(&rpc, &converted));
        let malformed = client.get("invalid address").build().unwrap_err();
        let converted = ClientError::SolanaRpcRead(ErrorKind::Reqwest(malformed).into());
        assert!(!retryable_account_read(&converted));
    }
}
