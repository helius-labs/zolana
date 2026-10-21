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
                ..RpcAccountInfoConfig::default()
            },
            ..RpcProgramAccountsConfig::default()
        }
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
