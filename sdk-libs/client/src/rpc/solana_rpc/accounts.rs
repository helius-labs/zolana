use std::{mem::offset_of, ops::Range};

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

use zolana_interface::{
    pda,
    state::{
        discriminator::{SPL_ASSET_COUNTER, SPL_ASSET_REGISTRY},
        SplAssetCounter, SplAssetRegistry,
    },
    PROGRAM_ID_PUBKEY,
};
use zolana_transaction::AssetRegistry;

use crate::{error::ClientError, scan::registry_entry};

/// Ids one registry page reads, every id of a page shares the bytes past its lowest.
const ASSET_REGISTRY_PAGE_IDS: u64 = 256;

/// The counter allocates ids `FIRST_ASSET_ID..next_id` in order, a page of them per query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AssetRegistryPages {
    next_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AssetRegistryPage {
    ids: Range<u64>,
}

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

impl AssetRegistryPages {
    pub(super) fn counter() -> Address {
        Address::new_from_array(pda::spl_asset_counter().to_bytes())
    }

    /// No counter account means no mint was ever registered.
    pub(super) fn of(counter: Option<Account>) -> Result<Self, ClientError> {
        let Some(counter) = counter else {
            return Ok(Self {
                next_id: SplAssetCounter::FIRST_ASSET_ID,
            });
        };
        let start = offset_of!(SplAssetCounter, next_id);
        let next_id = (counter.owner == PROGRAM_ID_PUBKEY
            && counter.data.len() == SplAssetCounter::SIZE
            && counter.data.first() == Some(&SPL_ASSET_COUNTER))
        .then(|| counter.data.get(start..start + 8)?.try_into().ok())
        .flatten()
        .map(u64::from_le_bytes)
        .filter(|next_id| *next_id >= SplAssetCounter::FIRST_ASSET_ID)
        .ok_or(ClientError::InvalidAssetCounter)?;
        Ok(Self { next_id })
    }

    pub(super) fn pages(self) -> impl Iterator<Item = AssetRegistryPage> {
        let first = SplAssetCounter::FIRST_ASSET_ID;
        let pages = first / ASSET_REGISTRY_PAGE_IDS..self.next_id.div_ceil(ASSET_REGISTRY_PAGE_IDS);
        pages
            .map(move |page| AssetRegistryPage {
                ids: (page * ASSET_REGISTRY_PAGE_IDS).max(first)
                    ..((page + 1) * ASSET_REGISTRY_PAGE_IDS).min(self.next_id),
            })
            .filter(|page| !page.ids.is_empty())
    }
}

impl AssetRegistryPage {
    pub(super) fn query(&self) -> (Address, ProgramAccountsFilter) {
        let page = self.ids.start / ASSET_REGISTRY_PAGE_IDS;
        let filter = ProgramAccountsFilter::new(SplAssetRegistry::SIZE)
            .with_memcmp(0, [SPL_ASSET_REGISTRY])
            .with_memcmp(
                offset_of!(SplAssetRegistry, asset_id) + 1,
                page.to_le_bytes()[..7].to_vec(),
            );
        (PROGRAM_ID_PUBKEY, filter)
    }

    /// Every id of the page answers once, one invalid, foreign or missing entry fails the read.
    pub(super) fn read(
        &self,
        accounts: Vec<(Address, Account)>,
        registry: &mut AssetRegistry,
    ) -> Result<(), ClientError> {
        let found = accounts.len();
        for (address, account) in accounts {
            let (asset_id, mint) = registry_entry(&address, &account)
                .filter(|(asset_id, _)| self.ids.contains(asset_id))
                .ok_or(ClientError::InvalidAssetRegistryAccount { address })?;
            registry.insert(asset_id, mint)?;
        }
        if found as u64 != self.ids.end - self.ids.start {
            return Err(ClientError::AssetRegistryPageIncomplete {
                first: self.ids.start,
                end: self.ids.end,
                found,
            });
        }
        Ok(())
    }
}
