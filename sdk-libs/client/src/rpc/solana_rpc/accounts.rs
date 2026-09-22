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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramAccountsFilter {
    data_size: usize,
    memcmp: Vec<MemcmpFilter>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MemcmpFilter {
    offset: usize,
    bytes: Vec<u8>,
}

impl ProgramAccountsFilter {
    pub fn new(data_size: usize) -> Self {
        Self {
            data_size,
            memcmp: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_memcmp(mut self, offset: usize, bytes: impl Into<Vec<u8>>) -> Self {
        self.memcmp.push(MemcmpFilter {
            offset,
            bytes: bytes.into(),
        });
        self
    }

    /// The `getProgramAccounts` config the filtered query sends.
    pub fn rpc_config(&self) -> RpcProgramAccountsConfig {
        let memcmp = self.memcmp.iter().map(|memcmp| {
            let bytes = MemcmpEncodedBytes::Base64(STANDARD.encode(&memcmp.bytes));
            RpcFilterType::Memcmp(Memcmp::new(memcmp.offset, bytes))
        });
        RpcProgramAccountsConfig {
            filters: Some(
                std::iter::once(RpcFilterType::DataSize(self.data_size as u64))
                    .chain(memcmp)
                    .collect(),
            ),
            account_config: RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64),
                commitment: Some(CommitmentConfig::confirmed()),
                ..RpcAccountInfoConfig::default()
            },
            ..RpcProgramAccountsConfig::default()
        }
    }

    pub fn matches(&self, data: &[u8]) -> bool {
        data.len() == self.data_size
            && self.memcmp.iter().all(|memcmp| {
                data.get(memcmp.offset..)
                    .is_some_and(|window| window.starts_with(&memcmp.bytes))
            })
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
