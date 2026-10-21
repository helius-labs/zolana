use std::{future::Future, time::Duration};

use async_trait::async_trait;
use custom_ring_interface::{ReadAccessRecord, RingAccount, RingMode, RingProgramConfig};
use solana_account::Account;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_loader_v3_interface::get_program_data_address;
use solana_rpc_client::{
    nonblocking::rpc_client::RpcClient as NonblockingRpcClient,
    rpc_client::GetConfirmedSignaturesForAddress2Config,
};
use solana_signature::Signature;
use std::num::NonZeroUsize;
use zolana_api::ZolanaApi;
use zolana_client::{
    program_data, AsyncRpc, AsyncSolanaRpc, AsyncZolanaIndexer, ClientError,
    GetShieldedTransactionsByTagsResponse, IndexedShieldedTransaction, IndexerRpcConfig,
    RingHistoryOptions,
};
use zolana_indexer_api::{GetRingMemberRecordsRequest, GetRingMemberRecordsResponse};
use zolana_interface::BPF_LOADER_UPGRADEABLE_ID;
use zolana_keypair::X25519Pubkey;
use zolana_ring_client::{
    ring_deposits_in, AuditError, ConfirmedEventKind, MergeAudit, MergeAuditPage, ReaderKey,
    RingOrigin, TransactionOrigin,
};
use zolana_transaction::AssetRegistry;

use zolana_ring_client::rpc::{DepositRecord, RingChainStatus, RingDepositsResponse};

use crate::audit::Page;

const MAX_MERGE_MEMBER_PAGES: NonZeroUsize = NonZeroUsize::new(100).unwrap();
const MAX_MERGE_CANDIDATE_ATTEMPTS: NonZeroUsize = NonZeroUsize::new(100_000).unwrap();

pub trait TransactionSource: Send + Sync {
    fn transactions_by_tag(
        &self,
        request: TransactionPage<'_>,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send;

    /// Rows strictly after the requested position, in history order.
    fn ring_history(
        &self,
        request: RingHistoryPage<'_>,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send;

    fn merge_audit_page<'a>(
        &'a self,
        request: MergeAuditRequest<'a>,
    ) -> impl Future<Output = Result<MergeAuditPage, AuditError>> + Send + 'a;

    fn transaction_origin(
        &self,
        signature: Signature,
        event_index: u16,
        ring: Address,
    ) -> impl Future<Output = Result<RingOrigin, AuditError>> + Send;

    fn ring_deposits(
        &self,
        page: DepositPage,
    ) -> impl Future<Output = Result<DepositHistory, ClientError>> + Send;

    fn ring_config(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<Option<RingConfiguration>, ClientError>> + Send;

    fn ring_chain_status(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<RingChainStatus, ClientError>> + Send;

    fn ring_member_records(
        &self,
        request: GetRingMemberRecordsRequest,
    ) -> impl Future<Output = Result<GetRingMemberRecordsResponse, ClientError>> + Send;

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

#[must_use]
pub struct RingHistoryPage<'a> {
    pub ring: Address,
    pub page: &'a Page,
}

#[must_use]
pub struct MergeAuditRequest<'a> {
    pub ring: Address,
    pub auditor: &'a zolana_keypair::X25519Keypair,
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

impl From<DepositHistory> for RingDepositsResponse {
    fn from(history: DepositHistory) -> Self {
        Self {
            deposits: history.deposits,
            cursor: history
                .cursor
                .map(|signature| signature.as_ref().to_vec().into()),
            oldest_slot: history.oldest_slot,
        }
    }
}

#[derive(Clone, Copy)]
#[must_use]
pub struct ReaderGrant {
    pub ring: Address,
    pub reader: ReaderKey,
}

#[derive(Clone, Copy)]
pub struct RingConfiguration {
    pub auditor_pubkey: X25519Pubkey,
    pub authority: Address,
    pub mode: RingMode,
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

struct MergeAuditSource<'a> {
    rpc: &'a AsyncSolanaRpc,
    indexer: &'a AsyncZolanaIndexer,
}

#[async_trait]
impl AsyncRpc for MergeAuditSource<'_> {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.rpc.get_account(address).await
    }

    async fn get_ring_member_records(
        &self,
        request: GetRingMemberRecordsRequest,
    ) -> Result<GetRingMemberRecordsResponse, ClientError> {
        self.indexer.get_ring_member_records(request).await
    }

    async fn get_shielded_transactions_by_ring(
        &self,
        options: RingHistoryOptions,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        ordered_ring_history(self.indexer, options, config).await
    }
}

async fn ordered_ring_history(
    indexer: &AsyncZolanaIndexer,
    options: RingHistoryOptions,
    config: Option<IndexerRpcConfig>,
) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
    let cursor = options.cursor.clone();
    let response = indexer
        .get_shielded_transactions_by_ring(options, config)
        .await?;
    validate_history_order(cursor.as_deref(), &response)?;
    Ok(response)
}

/// Photon orders tag and ring history by the fixed-width cursor it returns.
fn history_position(cursor: &[u8]) -> Option<(u64, [u8; 64], u16)> {
    let (&2, body) = cursor.split_first()? else {
        return None;
    };
    let (&slot, body) = body.split_first_chunk::<8>()?;
    let (&signature, body) = body.split_first_chunk::<64>()?;
    let (&event_index, []) = body.split_first_chunk::<2>()? else {
        return None;
    };
    Some((
        u64::from_be_bytes(slot),
        signature,
        u16::from_be_bytes(event_index),
    ))
}

fn validate_history_order(
    cursor: Option<&[u8]>,
    response: &GetShieldedTransactionsByTagsResponse,
) -> Result<(), ClientError> {
    let invalid = || ClientError::Indexer("invalid history cursor or row order".to_owned());
    let mut previous = match cursor {
        Some(cursor) => Some(history_position(cursor).ok_or_else(invalid)?),
        None => None,
    };
    for tx in &response.transactions {
        let event_index = tx.event_index.ok_or_else(invalid)?;
        let position = (tx.slot, *tx.tx_signature.as_array(), event_index);
        if previous.is_some_and(|previous| position <= previous) {
            return Err(invalid());
        }
        previous = Some(position);
    }
    if let Some(next) = response.next_cursor.as_deref() {
        let next = history_position(next).ok_or_else(invalid)?;
        if Some(next) != previous {
            return Err(invalid());
        }
    }
    Ok(())
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
    ) -> Result<Option<Account>, ClientError> {
        Ok(self
            .rpc
            .get_account(address)
            .await?
            .filter(|account| account.owner == owner))
    }
}

impl TransactionSource for ChainSource {
    async fn merge_audit_page<'a>(
        &'a self,
        request: MergeAuditRequest<'a>,
    ) -> Result<MergeAuditPage, AuditError> {
        MergeAudit::new(request.ring, request.auditor)
            .with_cursor(request.page.cursor().map(ToOwned::to_owned))
            .with_page_size(request.page.limit())
            // Either cap fails the read with MergeAuditWorkBudget, never a partial page.
            .with_max_member_pages(MAX_MERGE_MEMBER_PAGES)
            .with_max_candidate_attempts(MAX_MERGE_CANDIDATE_ATTEMPTS)
            .page(
                &MergeAuditSource {
                    rpc: &self.rpc,
                    indexer: &self.indexer,
                },
                &self.rpc,
            )
            .await
    }

    async fn transactions_by_tag(
        &self,
        request: TransactionPage<'_>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        let cursor = request.page.cursor().map(ToOwned::to_owned);
        let response = self
            .indexer
            .get_shielded_transactions_by_tags(
                vec![request.tag],
                cursor.clone(),
                Some(request.page.limit().get()),
                None,
            )
            .await?;
        validate_history_order(cursor.as_deref(), &response)?;
        Ok(response)
    }

    async fn ring_history(
        &self,
        request: RingHistoryPage<'_>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        let options = RingHistoryOptions {
            ring_program_id: request.ring,
            cursor: request.page.cursor().map(ToOwned::to_owned),
            limit: Some(request.page.limit().get()),
        };
        ordered_ring_history(&self.indexer, options, None).await
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
            let signature = confirmed_signature(&entry.signature)?;
            oldest = Some((signature, entry.slot));
            if entry.err.is_some() {
                continue;
            }
            let response = self
                .indexer
                .get_shielded_transactions_by_signature(signature, None)
                .await?;
            for indexed in response.transactions {
                let records = ConfirmedDepositRecords {
                    origin: &self.rpc,
                    signature,
                    ring,
                    indexed,
                };
                deposits.extend(records.read().await?);
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
        event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        self.rpc.origin(signature, event_index, ring).await
    }

    async fn ring_config(&self, ring: Address) -> Result<Option<RingConfiguration>, ClientError> {
        let (address, bump) = Address::find_program_address(&[RingProgramConfig::SEED], &ring);
        let Some(account) = self.owned_account(address, ring).await? else {
            return Ok(None);
        };
        CanonicalAccount {
            account: &account,
            ring,
            bump,
        }
        .configuration()
        .map(Some)
    }

    async fn ring_chain_status(&self, ring: Address) -> Result<RingChainStatus, ClientError> {
        RingChainStatus::read(&self.rpc, ring).await
    }

    async fn ring_member_records(
        &self,
        request: GetRingMemberRecordsRequest,
    ) -> Result<GetRingMemberRecordsResponse, ClientError> {
        self.indexer.get_ring_member_records(request).await
    }

    async fn upgrade_authority(&self, program: Address) -> Result<Option<Address>, ClientError> {
        let loader = Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID);
        let address = get_program_data_address(&program);
        let Some(account) = self.owned_account(address, loader).await? else {
            return Ok(None);
        };
        let data = program_data(&account)
            .ok_or_else(|| ClientError::Rpc("program data account is invalid".to_owned()))?;
        Ok(data
            .upgrade_authority
            .filter(|key| *key != Address::default()))
    }

    async fn reader_granted(&self, request: ReaderGrant) -> Result<bool, ClientError> {
        let address = request.reader.record_address(&request.ring);
        let Some(account) = self.rpc.get_account(address).await? else {
            return Ok(false);
        };
        check_reader(&account, request)?;
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
        self.rpc.asset_registry().await
    }
}

/// A malformed signature must stop the page before its cursor can advance.
fn confirmed_signature(value: &str) -> Result<Signature, ClientError> {
    value
        .parse()
        .map_err(|_| ClientError::Rpc("confirmed ring signature is invalid".to_owned()))
}

/// Public deposit metadata needs the same settlement binding as private recovery.
#[must_use]
struct ConfirmedDepositRecords<'a, O> {
    origin: &'a O,
    signature: Signature,
    ring: Address,
    indexed: IndexedShieldedTransaction,
}

impl<O: TransactionOrigin> ConfirmedDepositRecords<'_, O> {
    async fn read(self) -> Result<Vec<DepositRecord>, ClientError> {
        let Self {
            origin,
            signature,
            ring,
            mut indexed,
        } = self;
        let transaction = &mut indexed.transaction;
        let failure = |error: AuditError| {
            ClientError::Rpc(format!("confirmed deposit event refused because {error}"))
        };
        if transaction.tx_signature != signature
            || transaction.event_index != Some(indexed.event_index)
        {
            return Err(failure(AuditError::ConfirmedEventMismatch));
        }
        let confirmed = origin
            .origin(signature, indexed.event_index, ring)
            .await
            .map_err(failure)?;
        if !confirmed.ring_invoked || confirmed.event.kind() != ConfirmedEventKind::Deposit {
            return Ok(Vec::new());
        }
        confirmed
            .bind_transaction(transaction, ring)
            .map_err(failure)?;
        let slots = transaction
            .output_slots
            .iter()
            .map(|slot| (slot.view_tag, slot.payload.clone()));
        Ok(ring_deposits_in(slots, ring)
            .into_iter()
            .map(|found| DepositRecord {
                signature: signature.into(),
                slot: transaction.slot,
                depositor: found.depositor.into(),
                asset: found.asset.to_bytes().into(),
                amount: found.amount,
            })
            .collect())
    }
}

const INVALID_CONFIG: &str = "custom ring config account is invalid";
const INVALID_READER: &str = "custom ring reader account is invalid";

/// The program's initialized account at the address `bump` derives.
#[must_use]
struct CanonicalAccount<'a> {
    account: &'a Account,
    ring: Address,
    bump: u8,
}

impl CanonicalAccount<'_> {
    fn decode<T: RingAccount>(&self) -> Option<T> {
        T::decode(&self.account.owner, &self.ring, &self.account.data)
            .filter(|value| value.bump() == self.bump)
    }

    fn configuration(&self) -> Result<RingConfiguration, ClientError> {
        let invalid = || ClientError::Rpc(INVALID_CONFIG.to_owned());
        let config: RingProgramConfig = self.decode().ok_or_else(invalid)?;
        Ok(RingConfiguration {
            auditor_pubkey: X25519Pubkey::from_bytes(config.auditor_pubkey)
                .map_err(|_| invalid())?,
            authority: config.authority,
            mode: config.mode().map_err(|_| invalid())?,
        })
    }
}

fn check_reader(account: &Account, grant: ReaderGrant) -> Result<(), ClientError> {
    let invalid = || ClientError::Rpc(INVALID_READER.to_owned());
    let reader = grant.reader.to_bytes();
    let seed_hash = ReadAccessRecord::seed_hash(&reader).map_err(|_| invalid())?;
    let seeds: &[&[u8]] = &[ReadAccessRecord::SEED, &seed_hash];
    let bump = Address::find_program_address(seeds, &grant.ring).1;
    let record: ReadAccessRecord = CanonicalAccount {
        account,
        ring: grant.ring,
        bump,
    }
    .decode()
    .ok_or_else(invalid)?;
    (record.reader == reader).then_some(()).ok_or_else(invalid)
}

#[cfg(test)]
#[path = "../../../custom-rings/client/tests/common/origin.rs"]
mod origin_fixture;

#[cfg(test)]
mod tests {
    use bytemuck::{bytes_of, Pod, Zeroable};
    use custom_ring_interface::{CONFIG_PDA_SEED, READ_ACCESS_RECORD, RING_PROGRAM_CONFIG};
    use solana_keypair::Keypair;
    use solana_signer::Signer;

    use super::*;

    #[test]
    fn malformed_confirmed_signature_aborts_a_deposit_page() {
        assert!(confirmed_signature("not a Solana signature").is_err());
        let valid = Signature::from([7; 64]);
        assert_eq!(confirmed_signature(&valid.to_string()).unwrap(), valid);
    }

    #[test]
    fn history_pages_reject_repeated_or_reordered_indexer_rows() {
        use zolana_transaction::ShieldedTransaction;

        let position = |slot: u64, signature: &Signature, event_index: u16| {
            let mut cursor = vec![2];
            cursor.extend_from_slice(&slot.to_be_bytes());
            cursor.extend_from_slice(signature.as_array());
            cursor.extend_from_slice(&event_index.to_be_bytes());
            cursor
        };
        let tx = |slot: u64, event_index: u16| ShieldedTransaction {
            slot,
            tx_signature: Signature::from([7; 64]),
            event_index: Some(event_index),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![],
            messages: vec![],
            nullifiers: vec![],
            proofless: false,
            ring_config: None,
            ring_program_id: None,
        };
        let first = tx(9, 1);
        let second = tx(9, 2);
        let mut response = GetShieldedTransactionsByTagsResponse {
            context: zolana_client::Context {
                slot: 9,
                block_time: 0,
            },
            transactions: vec![first.clone(), second.clone()],
            next_cursor: Some(position(9, &second.tx_signature, 2)),
            scanned_through: None,
            output_tree_id: None,
        };
        assert!(validate_history_order(None, &response).is_ok());
        let previous = position(9, &first.tx_signature, 1);
        assert!(validate_history_order(Some(&previous), &response).is_err());
        response.transactions = vec![first.clone(), first.clone()];
        assert!(validate_history_order(None, &response).is_err());
        response.transactions = vec![second.clone(), first];
        assert!(validate_history_order(None, &response).is_err());
        response.transactions = vec![second];
        response.next_cursor = Some(previous);
        assert!(validate_history_order(None, &response).is_err());
    }

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

    #[test]
    fn config_accounts_require_the_canonical_layout() {
        let ring = Address::new_from_array([9; 32]);
        let bump = Address::find_program_address(&[CONFIG_PDA_SEED], &ring).1;
        let key = zolana_keypair::X25519Keypair::new().pubkey();
        let valid = config_account(ring, *key.as_bytes(), bump);
        let configuration = |account: &Account, bump| {
            CanonicalAccount {
                account,
                ring,
                bump,
            }
            .configuration()
        };
        let config = configuration(&valid, bump).expect("config");
        assert_eq!(config.auditor_pubkey, key);
        assert_eq!(config.authority, AUTHORITY);

        let mut wrong_owner = valid.clone();
        wrong_owner.owner = Address::new_from_array([8; 32]);
        let mut wrong_size = valid.clone();
        wrong_size.data.push(0);
        let mut wrong_discriminator = valid.clone();
        wrong_discriminator.data[0] = 0;
        for invalid in [wrong_owner, wrong_size, wrong_discriminator] {
            assert!(configuration(&invalid, bump).is_err());
        }
        assert!(configuration(&valid, bump.wrapping_add(1)).is_err());
        for invalid_key in [[2; 33], [0; 33]] {
            let invalid = config_account(ring, invalid_key, bump);
            assert!(configuration(&invalid, bump).is_err());
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
            ReaderKey::p256(
                zolana_ring_client::P256ReaderKey::from_bytes(
                    hex::decode(
                        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                    )
                    .unwrap()
                    .try_into()
                    .unwrap(),
                )
                .unwrap(),
            )
            .expect("P256 reader"),
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
            assert!(check_reader(&valid, grant).is_ok());

            let mut wrong_reader = valid.clone();
            wrong_reader.data[1] ^= 1;
            let wrong_bump = reader_account(ring, reader, bump.wrapping_add(1));
            for invalid in [&wrong_reader, &wrong_bump] {
                assert!(check_reader(invalid, grant).is_err());
            }
        }
    }

    struct ConfirmedOrigin(RingOrigin);

    impl TransactionOrigin for ConfirmedOrigin {
        async fn origin(&self, _: Signature, _: u16, _: Address) -> Result<RingOrigin, AuditError> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn public_deposit_history_rejects_forged_amount_asset_context_and_signature() {
        use zolana_transaction::{OutputContext, OutputSlot, ShieldedTransaction};
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../custom-rings/client/tests/fixtures/confirmed-deposit-event.json"
        ))
        .unwrap();
        let ring: Address = fixture["ring"].as_str().unwrap().parse().unwrap();
        let output = &fixture["expected"]["outputs"][0];
        let bytes = |key: &str| hex::decode(output[key].as_str().unwrap()).unwrap();
        let signature = Signature::from([7; 64]);
        let indexed = IndexedShieldedTransaction {
            event_index: 0,
            transaction: ShieldedTransaction {
                slot: 99,
                tx_signature: signature,
                event_index: Some(0),
                tx_viewing_pk: None,
                salt: None,
                proofless: true,
                ring_config: None,
                ring_program_id: Some(ring),
                messages: Vec::new(),
                nullifiers: Vec::new(),
                output_slots: vec![OutputSlot {
                    view_tag: bytes("viewTagHex").try_into().unwrap(),
                    output_context: OutputContext {
                        hash: bytes("hashHex").try_into().unwrap(),
                        tree_id: output["treeId"].as_u64().unwrap() as u16,
                        leaf_index: output["leafIndex"].as_u64().unwrap(),
                    },
                    payload: bytes("payloadHex"),
                }],
            },
        };
        let origin = ConfirmedOrigin(RingOrigin {
            ring_invoked: true,
            event: super::origin_fixture::event(&indexed.transaction).with_slot(99),
            signers: Vec::new(),
            withdrawals: Vec::new(),
            deposits: Vec::new(),
            merge_disclosure: None,
            transact: None,
        });
        let records = |origin, indexed| ConfirmedDepositRecords {
            origin,
            signature,
            ring,
            indexed,
        };
        let opened = records(&origin, indexed.clone()).read().await.unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].amount, 123);
        type Mutation = fn(&mut IndexedShieldedTransaction);
        let mutations: &[Mutation] = &[
            |tx| tx.transaction.tx_signature = Signature::from([8; 64]),
            |tx| tx.transaction.event_index = Some(1),
            |tx| tx.transaction.slot += 1,
            |tx| tx.transaction.proofless = false,
            |tx| tx.transaction.output_slots[0].output_context.leaf_index += 1,
            // Borsh outer tag + Vec length + scheme, then owner hash and asset.
            |tx| tx.transaction.output_slots[0].payload[6 + 32] ^= 1,
            |tx| tx.transaction.output_slots[0].payload[6 + 32 + 32] ^= 1,
        ];
        for mutate in mutations {
            let mut forged = indexed.clone();
            mutate(&mut forged);
            assert!(records(&origin, forged).read().await.is_err());
        }
        let foreign = ConfirmedOrigin(RingOrigin {
            ring_invoked: false,
            ..origin.0.clone()
        });
        assert!(records(&foreign, indexed).read().await.unwrap().is_empty());
    }
}
