use std::{future::Future, marker::PhantomData, time::Duration};

use bytemuck::Pod;
use custom_ring_interface::{
    ReadAccessRecord, RingProgramConfig, CONFIG_PDA_SEED, READ_ACCESS_RECORD, RING_PROGRAM_CONFIG,
};
use solana_account_decoder_client_types::UiAccountEncoding;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_loader_v3_interface::{get_program_data_address, state::UpgradeableLoaderState};
use solana_rpc_client::{
    nonblocking::rpc_client::RpcClient as NonblockingRpcClient,
    rpc_client::GetConfirmedSignaturesForAddress2Config,
};
use solana_rpc_client_api::{
    config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
    filter::RpcFilterType,
};
use solana_signature::Signature;
use zolana_api::ZolanaApi;
use zolana_client::{
    AsyncRpc, AsyncSolanaRpc, AsyncZolanaIndexer, ClientError,
    GetShieldedTransactionsByTagsResponse,
};
use zolana_interface::{
    is_reserved_p256_derivation_point, state::SplAssetRegistry, BPF_LOADER_UPGRADEABLE_ID,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::P256Pubkey;
use zolana_ring_client::{
    ring_deposits_in, ConfirmedTransaction, OriginError, ReaderKey, RingOrigin,
    ORIGIN_TRANSACTION_CONFIG,
};
use zolana_transaction::AssetRegistry;

use crate::{
    api::DepositRecord,
    audit::{Page, MAX_ASSET_REGISTRY_ACCOUNTS},
};

pub trait TransactionSource: Send + Sync {
    fn transactions_by_tag(
        &self,
        request: TransactionPage<'_>,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send;

    fn transaction_origin(
        &self,
        signature: Signature,
        ring: Address,
    ) -> impl Future<Output = Result<RingOrigin, OriginError>> + Send;

    fn ring_deposits(
        &self,
        page: DepositPage,
    ) -> impl Future<Output = Result<DepositHistory, ClientError>> + Send;

    fn ring_config(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<Option<RingConfiguration>, ClientError>> + Send;

    fn reader_granted(
        &self,
        request: ReaderGrant,
    ) -> impl Future<Output = Result<bool, ClientError>> + Send;

    /// `None` for a program that is immutable or not deployed.
    fn upgrade_authority(
        &self,
        program: Address,
    ) -> impl Future<Output = Result<Option<Address>, ClientError>> + Send;

    fn health(&self) -> impl Future<Output = Result<(), ClientError>> + Send;

    /// Binds every derived auditor key to one cluster.
    fn genesis_hash(&self) -> impl Future<Output = Result<[u8; 32], ClientError>> + Send;

    fn asset_registry(&self) -> impl Future<Output = Result<AssetRegistry, ClientError>> + Send;
}

#[must_use]
pub struct TransactionPage<'a> {
    pub tag: [u8; 32],
    pub page: &'a Page,
}

#[derive(Clone, Copy)]
#[must_use]
pub struct DepositPage {
    pub ring: Address,
    /// Signatures examined, which is not the number of deposits found.
    pub limit: usize,
    /// Resume bound, the oldest signature the previous page examined.
    pub before: Option<Signature>,
}

pub struct DepositHistory {
    pub deposits: Vec<DepositRecord>,
    /// Absent once the ring has no older history.
    pub cursor: Option<Signature>,
    /// Slot of the oldest signature examined, absent when the page examined
    /// nothing.
    pub oldest_slot: Option<u64>,
}

#[derive(Clone, Copy)]
#[must_use]
pub struct ReaderGrant {
    pub ring: Address,
    pub reader: ReaderKey,
}

#[derive(Clone, Copy)]
pub struct RingConfiguration {
    pub auditor_pubkey: P256Pubkey,
    pub authority: Address,
}

#[must_use]
pub struct Upstreams<'a> {
    pub indexer_url: &'a str,
    pub rpc_url: &'a str,
    pub timeout: Duration,
}

pub struct ChainSource {
    indexer: AsyncZolanaIndexer,
    rpc: AsyncSolanaRpc,
}

impl ChainSource {
    pub fn connect(upstreams: Upstreams<'_>) -> Result<Self, ClientError> {
        let http = reqwest::Client::builder()
            .timeout(upstreams.timeout)
            .build()
            .map_err(|error| ClientError::Rpc(format!("http client: {error}")))?;
        Ok(Self {
            indexer: AsyncZolanaIndexer::with_api(ZolanaApi::with_client(
                upstreams.indexer_url,
                http,
            )),
            rpc: AsyncSolanaRpc::with_client(
                NonblockingRpcClient::new_with_timeout_and_commitment(
                    upstreams.rpc_url.to_owned(),
                    upstreams.timeout,
                    CommitmentConfig::confirmed(),
                ),
            ),
        })
    }

    pub fn rpc(&self) -> &AsyncSolanaRpc {
        &self.rpc
    }

    /// A foreign owner means the account does not exist for its program, not
    /// that it is broken.
    async fn owned_account(
        &self,
        address: Address,
        owner: Address,
    ) -> Result<Option<solana_account::Account>, ClientError> {
        Ok(self
            .rpc
            .get_account(address)
            .await?
            .filter(|account| account.owner == owner))
    }
}

impl TransactionSource for ChainSource {
    fn transactions_by_tag(
        &self,
        request: TransactionPage<'_>,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send
    {
        self.indexer.get_shielded_transactions_by_tags(
            vec![request.tag],
            request.page.cursor().map(ToOwned::to_owned),
            Some(request.page.limit().get()),
            None,
        )
    }

    /// The ring's own signatures name the candidates, and every deposit field
    /// this reports is public.
    async fn ring_deposits(&self, page: DepositPage) -> Result<DepositHistory, ClientError> {
        let ring = page.ring;
        let signatures = self
            .rpc
            .client()
            .get_signatures_for_address_with_config(
                &ring,
                GetConfirmedSignaturesForAddress2Config {
                    before: page.before,
                    until: None,
                    limit: Some(page.limit),
                    commitment: Some(CommitmentConfig::confirmed()),
                },
            )
            .await
            .map_err(|error| ClientError::Rpc(format!("signatures for {ring}: {error}")))?;
        // A short page means the ring has no older history.
        let more = signatures.len() == page.limit;
        let mut deposits = Vec::new();
        let mut oldest = None;
        for entry in signatures {
            let Ok(signature) = entry.signature.parse::<Signature>() else {
                continue;
            };
            oldest = Some((signature, entry.slot));
            let response = self
                .indexer
                .get_shielded_transactions_by_signature(signature, None)
                .await?;
            for indexed in response.transactions {
                let slots = indexed
                    .transaction
                    .output_slots
                    .iter()
                    .map(|slot| (slot.view_tag, slot.payload.clone()));
                for found in ring_deposits_in(slots, ring) {
                    deposits.push(DepositRecord {
                        signature: signature.into(),
                        slot: indexed.transaction.slot,
                        depositor: found.depositor.into(),
                        asset: found.asset.to_bytes().into(),
                        amount: found.amount,
                    });
                }
            }
        }
        Ok(DepositHistory {
            deposits,
            cursor: oldest.map(|(signature, _)| signature).filter(|_| more),
            oldest_slot: oldest.map(|(_, slot)| slot),
        })
    }

    async fn transaction_origin(
        &self,
        signature: Signature,
        ring: Address,
    ) -> Result<RingOrigin, OriginError> {
        let transaction = self
            .rpc
            .client()
            .get_transaction_with_config(&signature, ORIGIN_TRANSACTION_CONFIG)
            .await
            .map_err(|error| OriginError::Unavailable {
                signature,
                message: error.to_string(),
            })?;
        ConfirmedTransaction {
            signature,
            transaction,
        }
        .origin(ring)
    }

    async fn ring_config(&self, ring: Address) -> Result<Option<RingConfiguration>, ClientError> {
        let (address, bump) = Address::find_program_address(&[CONFIG_PDA_SEED], &ring);
        let Some(account) = self.owned_account(address, ring).await? else {
            return Ok(None);
        };
        Ok(Some(
            ConfigAccount {
                account: &account,
                ring,
                bump,
            }
            .decode()?,
        ))
    }

    async fn upgrade_authority(&self, program: Address) -> Result<Option<Address>, ClientError> {
        let address = get_program_data_address(&program);
        let Some(account) = self
            .owned_account(address, Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID))
            .await?
        else {
            return Ok(None);
        };
        ProgramDataAccount { account: &account }.upgrade_authority()
    }

    async fn reader_granted(&self, request: ReaderGrant) -> Result<bool, ClientError> {
        let address = request.reader.entry_address(&request.ring);
        let Some(account) = self.rpc.get_account(address).await? else {
            return Ok(false);
        };
        ReaderAccount {
            account: &account,
            grant: request,
        }
        .validate()?;
        Ok(true)
    }

    async fn health(&self) -> Result<(), ClientError> {
        self.indexer
            .get_shielded_transactions_by_tags(vec![[0; 32]], None, Some(1), None)
            .await?;
        self.rpc.health().await
    }

    async fn genesis_hash(&self) -> Result<[u8; 32], ClientError> {
        self.rpc.genesis_hash().await
    }

    async fn asset_registry(&self) -> Result<AssetRegistry, ClientError> {
        let program = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let accounts = self
            .rpc
            .client()
            .get_program_ui_accounts_with_config(
                &program,
                RpcProgramAccountsConfig {
                    filters: Some(vec![RpcFilterType::DataSize(SplAssetRegistry::SIZE as u64)]),
                    account_config: RpcAccountInfoConfig {
                        encoding: Some(UiAccountEncoding::Base64),
                        commitment: Some(CommitmentConfig::confirmed()),
                        ..RpcAccountInfoConfig::default()
                    },
                    ..RpcProgramAccountsConfig::default()
                },
            )
            .await
            .map_err(|_| ClientError::Rpc("asset registry request failed".to_owned()))?;
        if accounts.len() > MAX_ASSET_REGISTRY_ACCOUNTS {
            return Err(ClientError::Rpc(
                "asset registry response is too large".to_owned(),
            ));
        }
        let entries = accounts.into_iter().filter_map(|(_, account)| {
            let account = account.to_account()?;
            SplAssetRegistry::from_account_bytes(&account.data)
                .ok()
                .map(|registry| (registry.asset_id, registry.mint))
        });
        AssetRegistry::new(entries).map_err(ClientError::from)
    }
}

struct ConfigAccount<'a> {
    account: &'a solana_account::Account,
    ring: Address,
    bump: u8,
}

impl ConfigAccount<'_> {
    fn decode(self) -> Result<RingConfiguration, ClientError> {
        let config = AccountCheck::<RingProgramConfig> {
            account: self.account,
            owner: self.ring,
            discriminator: RING_PROGRAM_CONFIG,
            error: "custom ring config account is invalid",
            account_type: PhantomData,
        }
        .decode()?;
        if config.bump != self.bump || is_reserved_p256_derivation_point(&config.auditor_pubkey) {
            return Err(ClientError::Rpc(
                "custom ring config account is invalid".to_owned(),
            ));
        }
        let auditor_pubkey = P256Pubkey::from_bytes(config.auditor_pubkey)
            .map_err(|_| ClientError::Rpc("custom ring config account is invalid".to_owned()))?;
        Ok(RingConfiguration {
            auditor_pubkey,
            authority: config.authority,
        })
    }
}

struct ProgramDataAccount<'a> {
    account: &'a solana_account::Account,
}

impl ProgramDataAccount<'_> {
    fn upgrade_authority(self) -> Result<Option<Address>, ClientError> {
        let invalid = || ClientError::Rpc("program data account is invalid".to_owned());
        let (state, _) = bincode::serde::decode_from_slice::<UpgradeableLoaderState, _>(
            &self.account.data,
            bincode::config::legacy(),
        )
        .map_err(|_| invalid())?;
        let UpgradeableLoaderState::ProgramData {
            upgrade_authority_address,
            ..
        } = state
        else {
            return Err(invalid());
        };
        Ok(upgrade_authority_address.filter(|key| *key != Address::default()))
    }
}

struct ReaderAccount<'a> {
    account: &'a solana_account::Account,
    grant: ReaderGrant,
}

impl ReaderAccount<'_> {
    fn validate(self) -> Result<(), ClientError> {
        let record = AccountCheck::<ReadAccessRecord> {
            account: self.account,
            owner: self.grant.ring,
            discriminator: READ_ACCESS_RECORD,
            error: "custom ring reader account is invalid",
            account_type: PhantomData,
        }
        .decode()?;
        let reader = self.grant.reader.to_bytes();
        let seed_hash = ReadAccessRecord::seed_hash(&reader)
            .map_err(|_| ClientError::Rpc("custom ring reader account is invalid".to_owned()))?;
        let bump =
            Address::find_program_address(&[ReadAccessRecord::SEED, &seed_hash], &self.grant.ring)
                .1;
        if record.reader != reader || record.bump != bump {
            return Err(ClientError::Rpc(
                "custom ring reader account is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

struct AccountCheck<'a, T> {
    account: &'a solana_account::Account,
    owner: Address,
    discriminator: u8,
    error: &'static str,
    account_type: PhantomData<T>,
}

impl<T: Pod + Copy> AccountCheck<'_, T> {
    fn decode(self) -> Result<T, ClientError> {
        if self.account.owner.to_bytes() != self.owner.to_bytes()
            || self.account.data.len() != core::mem::size_of::<T>()
        {
            return Err(ClientError::Rpc(self.error.to_owned()));
        }
        let value = bytemuck::try_from_bytes::<T>(&self.account.data)
            .copied()
            .map_err(|_| ClientError::Rpc(self.error.to_owned()))?;
        if self.account.data.first().copied() != Some(self.discriminator) {
            return Err(ClientError::Rpc(self.error.to_owned()));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::{bytes_of, Zeroable};
    use solana_account::Account;
    use solana_keypair::Keypair;
    use solana_signer::Signer;
    use zolana_interface::P_CONST_SEC1;
    use zolana_keypair::ViewingKey;

    use super::*;

    fn account<T: Pod>(owner: Address, value: &T) -> Account {
        Account {
            lamports: 1,
            data: bytes_of(value).to_vec(),
            owner,
            executable: false,
            rent_epoch: 0,
        }
    }

    const AUTHORITY: Address = Address::new_from_array([7; 32]);

    fn config_account(ring: Address, key: [u8; 33], bump: u8) -> Account {
        let mut config = RingProgramConfig::zeroed();
        config.discriminator = RING_PROGRAM_CONFIG;
        config.authority = AUTHORITY;
        config.auditor_pubkey = key;
        config.bump = bump;
        account(ring, &config)
    }

    fn program_data(state: &UpgradeableLoaderState, owner: Address) -> Account {
        Account {
            lamports: 1,
            data: bincode::serde::encode_to_vec(state, bincode::config::legacy()).expect("state"),
            owner,
            executable: false,
            rent_epoch: 0,
        }
    }

    #[test]
    fn program_data_reports_the_upgrade_authority_or_none_when_immutable() {
        let loader = Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID);
        let authority = Address::new_from_array([6; 32]);
        let upgradeable = program_data(
            &UpgradeableLoaderState::ProgramData {
                slot: 1,
                upgrade_authority_address: Some(authority),
            },
            loader,
        );
        assert_eq!(
            ProgramDataAccount {
                account: &upgradeable
            }
            .upgrade_authority()
            .expect("program data"),
            Some(authority)
        );
        let immutable = program_data(
            &UpgradeableLoaderState::ProgramData {
                slot: 1,
                upgrade_authority_address: None,
            },
            loader,
        );
        assert_eq!(
            ProgramDataAccount {
                account: &immutable
            }
            .upgrade_authority()
            .expect("program data"),
            None
        );
        let not_program_data = program_data(&UpgradeableLoaderState::Uninitialized, loader);
        assert!(ProgramDataAccount {
            account: &not_program_data
        }
        .upgrade_authority()
        .is_err());
    }

    #[test]
    fn config_accounts_require_the_canonical_layout() {
        let ring = Address::new_from_array([9; 32]);
        let bump = Address::find_program_address(&[CONFIG_PDA_SEED], &ring).1;
        let key = ViewingKey::new().pubkey();
        let valid = config_account(ring, *key.as_bytes(), bump);
        assert_eq!(
            ConfigAccount {
                account: &valid,
                ring,
                bump,
            }
            .decode()
            .expect("config")
            .auditor_pubkey,
            key
        );
        assert_eq!(
            ConfigAccount {
                account: &valid,
                ring,
                bump,
            }
            .decode()
            .expect("config")
            .authority,
            AUTHORITY
        );

        let mut wrong_owner = valid.clone();
        wrong_owner.owner = Address::new_from_array([8; 32]);
        let mut wrong_size = valid.clone();
        wrong_size.data.push(0);
        let mut wrong_discriminator = valid.clone();
        wrong_discriminator.data[0] = 0;
        for invalid in [wrong_owner, wrong_size, wrong_discriminator] {
            assert!(ConfigAccount {
                account: &invalid,
                ring,
                bump,
            }
            .decode()
            .is_err());
        }
        assert!(ConfigAccount {
            account: &valid,
            ring,
            bump: bump.wrapping_add(1),
        }
        .decode()
        .is_err());
        for invalid_key in [P_CONST_SEC1, [0; 33]] {
            let invalid = config_account(ring, invalid_key, bump);
            assert!(ConfigAccount {
                account: &invalid,
                ring,
                bump,
            }
            .decode()
            .is_err());
        }
    }

    fn reader_account(ring: Address, reader: ReaderKey, bump: u8) -> Account {
        let mut record = ReadAccessRecord::zeroed();
        record.discriminator = READ_ACCESS_RECORD;
        record.reader = reader.to_bytes();
        record.bump = bump;
        account(ring, &record)
    }

    #[test]
    fn reader_accounts_bind_both_reader_schemes() {
        let ring = Address::new_from_array([9; 32]);
        let readers = [
            ReaderKey::ed25519(Keypair::new().pubkey()).expect("Ed25519 reader"),
            ReaderKey::p256(ViewingKey::new().pubkey()).expect("P256 reader"),
        ];
        for reader in readers {
            let grant = ReaderGrant { ring, reader };
            let bump = Address::find_program_address(
                &[
                    ReadAccessRecord::SEED,
                    &ReadAccessRecord::seed_hash(&reader.to_bytes()).expect("seed"),
                ],
                &ring,
            )
            .1;
            let valid = reader_account(ring, reader, bump);
            assert!(ReaderAccount {
                account: &valid,
                grant,
            }
            .validate()
            .is_ok());

            let mut wrong_reader = valid.clone();
            wrong_reader.data[1] ^= 1;
            let wrong_bump = reader_account(ring, reader, bump.wrapping_add(1));
            for invalid in [&wrong_reader, &wrong_bump] {
                assert!(ReaderAccount {
                    account: invalid,
                    grant,
                }
                .validate()
                .is_err());
            }
        }
    }
}
