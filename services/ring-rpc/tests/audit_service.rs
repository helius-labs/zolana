#[path = "../../../custom-rings/client/tests/common/deposit.rs"]
mod deposit_fixture;
#[path = "../../../custom-rings/client/tests/common/origin.rs"]
mod origin_fixture;
#[path = "../../../custom-rings/client/tests/common/transfer.rs"]
pub mod transfer;

use custom_ring_interface::{stream::RingTag, EscrowKey, RingMode};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, LazyLock, Mutex,
    },
    time::Duration,
};
use zolana_keypair::{X25519Keypair, X25519Pubkey};
use zolana_ring_member_registry::{MemberRecord, MemberRegistryTree, RecordTree};
use zolana_ring_policy::Member;

use p256::ecdsa::signature::hazmat::PrehashSigner;
use sha2::Digest;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ClientError, Context, GetShieldedTransactionsByTagsResponse};
use zolana_event::encode_ring_confidential_delivered_output;
use zolana_hasher::primitives::right_align;
use zolana_indexer_api::{
    Base64String, GetRingMemberOpeningsRequest, GetRingMemberOpeningsResponse,
    GetRingMemberRecordsRequest, GetRingMemberRecordsResponse, GetRingRecordQueueResponse, Hash,
    Limit, RingIndexedMemberRecordView, RingMemberOpening, RingMemberRecordView,
    RingQueueEntryView, RingRecordPathView, RingRegistryRootView,
};
use zolana_keypair::ViewingKey;
use zolana_ring_client::P256ReaderKey;
use zolana_ring_client::{
    auditor_view_tag, ring_event_origin_in,
    rpc::{
        unix_now, AuditorKeyStatement, CreateAuditorKeyRequest, CreateAuditorKeyResponse,
        DecryptedInputRing, DecryptedPayloadError, DecryptedSender, DecryptedTransaction,
        DecryptedWithdrawal, DepositRecord, GetAuditedMergesResponse, GetAuditedUtxosRequest,
        GetAuditedUtxosResponse, GetDecryptedTransactionsRequest, GetDecryptedTransactionsResponse,
        HealthResponse, KeyMode, PagedRead, ReadAttestation, ReadAuth, ReadBuildError,
        ReadSignature, ReadSigner, ReadTarget, RegistryRoot, RegistryStatus, RingActivation,
        RingChainStatus, RingDepositsRequest, RingDepositsResponse, RingState, RingStatusRequest,
        RingStatusResponse, SkippedReason, WebAuthnAssertion, AUDITED_UTXOS_LIMIT,
        CREATE_AUDITOR_KEY, GET_AUDITED_MERGES, GET_AUDITED_UTXOS, GET_DECRYPTED_TRANSACTIONS,
        HEALTH, RING_DEPOSITS, RING_STATUS,
    },
    seal_deposits, AnonymousInputs, AuditDisclosure, AuditError, ConfirmedDeposit, DepositOpening,
    MergeAuditPage, MergeAuditResult, OutputPayloadErrorKind, ReaderKey, RingOrigin,
    RingWithdrawal,
};
use zolana_ring_rpc::{
    rpc_module, AuditRead, AuditService, Clock, DepositHistory, DepositPage, Hub,
    MergeAuditRequest, OriginPolicy, Origins, Page, ReadCheck, ReaderGrant, RingConfiguration,
    RingHistoryPage, RingRpcError, RootSecret, TransactionPage, TransactionSource, Unauthorized,
    AUTH_SKEW,
};
use zolana_transaction::{
    derive_output_blinding_seed, serialization::RingDeliveredBody, AssetRegistry,
    ShieldedTransaction, SOL_MINT,
};

use transfer::{
    data_free, field, input_opening, x25519_u, Frame, Output, Placement, Publish, Rail, Transfer,
    UtxoFields,
};

/// Raw id of the tree these fixtures publish into. A slot names the id, not the
/// account; the account is `pda::tree(TREE_ID)` wherever one is needed.
const TREE_ID: u16 = 4;
const RING: Address = Address::new_from_array([5; 32]);
const GENESIS: [u8; 32] = [9; 32];
const FIXTURE_AUDITOR: [u8; 32] = [0x41; 32];
/// Ring history reads past it fail, a cycling page set ends there.
const HISTORY_READ_CAP: usize = 1_000;
const OTHER_RING: Address = Address::new_from_array([6; 32]);
const SENDER: Address = Address::new_from_array([7; 32]);
const RECIPIENT: Address = Address::new_from_array([8; 32]);
const WITHDRAWN: u64 = 250;
const TOKEN_ACCOUNT: Address = Address::new_from_array([9; 32]);
const MINT: Address = Address::new_from_array([10; 32]);
const SPL_WITHDRAWN: u64 = 75;
const ORIGIN: &str = "http://localhost:3000";
const USER_PRESENT_AND_VERIFIED: u8 = 0x05;

fn authority() -> Keypair {
    Keypair::new_from_array([42; 32])
}

fn delegate() -> Keypair {
    Keypair::new_from_array([45; 32])
}

fn deployer() -> Keypair {
    Keypair::new_from_array([44; 32])
}

fn stranger() -> Keypair {
    Keypair::new_from_array([43; 32])
}

struct Passkey {
    key: p256::ecdsa::SigningKey,
    origin: &'static str,
    relying_party: &'static str,
    flags: u8,
    cross_origin: bool,
    padded_challenge: bool,
    top_origin: Option<&'static str>,
}

impl Passkey {
    fn new(byte: u8) -> Self {
        Self {
            key: p256::ecdsa::SigningKey::from_bytes(&[byte; 32].into()).expect("scalar"),
            origin: ORIGIN,
            relying_party: "localhost",
            flags: USER_PRESENT_AND_VERIFIED,
            cross_origin: false,
            padded_challenge: false,
            top_origin: None,
        }
    }

    fn origin(mut self, origin: &'static str) -> Self {
        self.origin = origin;
        self
    }

    fn relying_party(mut self, relying_party: &'static str) -> Self {
        self.relying_party = relying_party;
        self
    }

    fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    fn cross_origin(mut self) -> Self {
        self.cross_origin = true;
        self
    }

    fn padded_challenge(mut self) -> Self {
        self.padded_challenge = true;
        self
    }

    fn top_origin(mut self, origin: &'static str) -> Self {
        self.top_origin = Some(origin);
        self
    }

    fn pubkey(&self) -> P256ReaderKey {
        let sec1 = self.key.verifying_key().to_encoded_point(true);
        P256ReaderKey::from_bytes(sec1.as_bytes().try_into().expect("compressed key")).expect("key")
    }
}

impl ReadSigner for Passkey {
    fn reader(&self) -> Result<ReaderKey, zolana_ring_client::ReaderKeyError> {
        ReaderKey::p256(self.pubkey())
    }

    fn sign(&self, attestation: &[u8]) -> Result<ReadSignature, ReadBuildError> {
        let mut challenge = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            sha2::Sha256::digest(attestation),
        );
        if self.padded_challenge {
            challenge.push('=');
        }
        let top_origin = self
            .top_origin
            .map(|origin| format!(r#", "topOrigin":"{origin}""#))
            .unwrap_or_default();
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{}","crossOrigin":{}{top_origin}}}"#,
            self.origin, self.cross_origin
        );
        let mut authenticator_data = sha2::Sha256::digest(self.relying_party).to_vec();
        authenticator_data.push(self.flags);
        authenticator_data.extend_from_slice(&[0, 0, 0, 1]);
        let mut signed = sha2::Sha256::new();
        signed.update(&authenticator_data);
        signed.update(sha2::Sha256::digest(client_data.as_bytes()));
        let signature: p256::ecdsa::Signature = self
            .key
            .sign_prehash(&signed.finalize())
            .expect("signature");
        Ok(ReadSignature::WebAuthn {
            signature_der: signature.to_der().as_bytes().to_vec(),
            assertion: WebAuthnAssertion {
                authenticator_data: authenticator_data.into(),
                client_data_json: client_data.into_bytes().into(),
            },
        })
    }
}

fn origins() -> Origins {
    OriginPolicy::new(vec![ORIGIN.to_owned()])
        .with_relying_party_id("localhost".to_owned())
        .build()
        .expect("origins")
}

/// Fixture hubs share one auditor key and so one service key.
static FIXTURE_SERVICE: LazyLock<Address> = LazyLock::new(|| {
    let fixture = Fixture::new();
    fixture.hub(fixture.source()).service_pubkey()
});

fn target(ring: Address) -> ReadTarget {
    ReadTarget {
        cluster: GENESIS,
        service: *FIXTURE_SERVICE,
        ring,
    }
}

fn served(hub: &Hub<StaticSource>, ring: Address) -> ReadTarget {
    ReadTarget {
        cluster: GENESIS,
        service: hub.service_pubkey(),
        ring,
    }
}

fn signed_request<S: ReadSigner + ?Sized>(
    signer: &S,
    target: ReadTarget,
    timestamp: u64,
) -> GetDecryptedTransactionsRequest {
    GetDecryptedTransactionsRequest::read(target)
        .at(timestamp)
        .sign(signer)
        .expect("signed request")
}

fn auth<S: ReadSigner + ?Sized>(signer: &S) -> ReadAuth {
    signed_request(signer, target(RING), unix_now().expect("clock")).auth
}

fn decide_now(auth: &ReadAuth, origins: &Origins) -> Result<ReaderKey, Unauthorized> {
    let attestation = ReadAttestation {
        read: PagedRead::DecryptedTransactions,
        target: target(RING),
        cursor: None,
        limit: None,
    };
    ReadCheck {
        auth,
        attestation: &attestation,
        now: unix_now().expect("clock"),
        origins,
    }
    .decide()
    .map(|claim| claim.reader)
}

#[test]
fn signatures_bind_the_reader_and_request() {
    let wallet = delegate();
    assert_eq!(
        decide_now(&auth(&wallet), &origins()).expect("wallet claim"),
        ReaderKey::ed25519(wallet.pubkey()).expect("reader")
    );
    let passkey = Passkey::new(46);
    assert_eq!(
        decide_now(&auth(&passkey), &origins()).expect("passkey claim"),
        ReaderKey::p256(passkey.pubkey()).expect("reader")
    );

    let mut changed = auth(&wallet);
    changed.timestamp += 1;
    assert_eq!(
        decide_now(&changed, &origins()),
        Err(Unauthorized::BadSignature)
    );
    assert_eq!(
        decide_now(
            &signed_request(&wallet, target(OTHER_RING), unix_now().expect("clock")).auth,
            &origins()
        ),
        Err(Unauthorized::BadSignature)
    );
}

#[test]
fn passkeys_require_canonical_same_origin_assertions() {
    for (passkey, expected) in [
        (
            Passkey::new(46).origin("https://evil.example"),
            Unauthorized::OriginNotAllowed,
        ),
        (
            Passkey::new(46).relying_party("evil.example"),
            Unauthorized::RelyingPartyMismatch,
        ),
        (
            Passkey::new(46).flags(0x01),
            Unauthorized::UserVerificationMissing,
        ),
        (
            Passkey::new(46).flags(0x04),
            Unauthorized::UserVerificationMissing,
        ),
        (
            Passkey::new(46).cross_origin(),
            Unauthorized::CrossOriginAssertion,
        ),
        (
            Passkey::new(46).top_origin("https://top.example"),
            Unauthorized::CrossOriginAssertion,
        ),
        (
            Passkey::new(46).padded_challenge(),
            Unauthorized::ChallengeMismatch,
        ),
    ] {
        assert_eq!(decide_now(&auth(&passkey), &origins()), Err(expected));
    }
}

type Frames = Arc<Mutex<HashMap<Signature, Vec<u8>>>>;

#[derive(Clone)]
struct StaticSource {
    transactions: Vec<ShieldedTransaction>,
    origins: HashMap<(Signature, u16), bool>,
    frames: Frames,
    /// Confirmed deposits and merges do not carry transfer auditor messages.
    confirmed_events: HashMap<(Signature, u16), zolana_ring_client::ConfirmedEvent>,
    /// The capsule bindings of each audited deposit.
    deposits: HashMap<Signature, Vec<ConfirmedDeposit>>,
    next_cursor: Option<Vec<u8>>,
    scanned_through: Option<Vec<u8>>,
    /// Per ring, so a read can never be authorized against another ring's
    /// config.
    configs: HashMap<Address, RingConfiguration>,
    /// Per ring, the default where SPP and the registry hold nothing.
    chain: HashMap<Address, RingChainStatus>,
    /// Per auditor view tag, empty when every read shares `transactions`.
    by_tag: HashMap<[u8; 32], Vec<ShieldedTransaction>>,
    granted: HashSet<ReaderKey>,
    /// Per program, absent when immutable or not deployed.
    upgrade_authorities: HashMap<Address, Address>,
    healthy: bool,
    assets: Option<AssetRegistry>,
    asset_reads: Arc<AtomicUsize>,
    asset_delay: Option<Duration>,
    /// Ring history, newest first.
    history: Vec<Examined>,
    examined_limit: Arc<AtomicUsize>,
    /// Per request cursor, empty when every read shares one page.
    pages: HashMap<Option<Vec<u8>>, Paged>,
    /// The ring's registry, replaced while a hub serves it.
    registry: Arc<Mutex<Option<EscrowRegistry>>>,
    record_reads: Arc<AtomicUsize>,
    opening_reads: Arc<AtomicUsize>,
    history_reads: Arc<AtomicUsize>,
}

/// The indexer page one cursor reads.
#[derive(Clone)]
struct Paged {
    transactions: Vec<ShieldedTransaction>,
    next_cursor: Option<Vec<u8>>,
    scanned_through: Option<Vec<u8>>,
}

/// One ring signature and the deposits it made.
#[derive(Clone)]
struct Examined {
    signature: Signature,
    slot: u64,
    deposits: Vec<DepositRecord>,
}

impl StaticSource {
    fn registry(&self) -> Option<EscrowRegistry> {
        self.registry.lock().unwrap().clone()
    }

    fn with_transactions(mut self, transactions: Vec<ShieldedTransaction>) -> Self {
        self.origins = transactions
            .iter()
            .filter_map(|transaction| {
                transaction
                    .event_index
                    .map(|event_index| ((transaction.tx_signature, event_index), true))
            })
            .collect();
        self.transactions = transactions;
        self
    }
}

impl StaticSource {
    /// The page `page` names, else every transaction the source holds under `tagged`.
    fn page_at(
        &self,
        page: &Page,
        tagged: Option<&Vec<ShieldedTransaction>>,
    ) -> GetShieldedTransactionsByTagsResponse {
        assert!(page.limit().get() <= 100);
        let paged = self
            .pages
            .get(&page.cursor().map(ToOwned::to_owned))
            .cloned()
            .unwrap_or_else(|| Paged {
                transactions: tagged.cloned().unwrap_or_else(|| self.transactions.clone()),
                next_cursor: self.next_cursor.clone(),
                scanned_through: self.scanned_through.clone(),
            });
        GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 99,
            },
            transactions: paged.transactions,
            next_cursor: paged.next_cursor,
            scanned_through: paged.scanned_through,
            output_tree_id: Some(TREE_ID),
        }
    }
}

impl TransactionSource for StaticSource {
    async fn merge_audit_page(
        &self,
        _request: MergeAuditRequest<'_>,
    ) -> Result<MergeAuditPage, AuditError> {
        Ok(MergeAuditPage {
            context: zolana_indexer_api::Context {
                block_time: 0,
                slot: 99,
            },
            result: MergeAuditResult {
                opened: Vec::new(),
                unresolved: Vec::new(),
            },
            next_cursor: None,
        })
    }

    fn transactions_by_tag(
        &self,
        request: TransactionPage<'_>,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send
    {
        let response = self.page_at(request.page, self.by_tag.get(&request.tag));
        async move { Ok(response) }
    }

    fn ring_history(
        &self,
        request: RingHistoryPage<'_>,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send
    {
        let capped = self.history_reads.fetch_add(1, Ordering::Relaxed) >= HISTORY_READ_CAP;
        let response = self.page_at(request.page, None);
        async move {
            match capped {
                true => Err(ClientError::Rpc("history read cap".to_owned())),
                false => Ok(response),
            }
        }
    }

    fn transaction_origin(
        &self,
        signature: Signature,
        event_index: u16,
        _ring: Address,
    ) -> impl Future<Output = Result<RingOrigin, AuditError>> + Send {
        let origin = self
            .origins
            .get(&(signature, event_index))
            .copied()
            .map(|ring_invoked| RingOrigin {
                event: self
                    .confirmed_events
                    .get(&(signature, event_index))
                    .cloned()
                    .unwrap_or_else(|| {
                        origin_fixture::event(
                            self.transactions
                                .iter()
                                .chain(self.by_tag.values().flatten())
                                .find(|tx| {
                                    tx.tx_signature == signature
                                        && tx.event_index == Some(event_index)
                                })
                                .expect("confirmed event"),
                        )
                    }),
                ring_invoked,
                signers: vec![SENDER],
                deposits: self.deposits.get(&signature).cloned().unwrap_or_default(),
                merge_disclosure: None,
                transact: self.frames.lock().unwrap().get(&signature).cloned(),
                withdrawals: vec![
                    RingWithdrawal {
                        recipient: RECIPIENT,
                        asset: SOL_MINT,
                        amount: WITHDRAWN,
                    },
                    RingWithdrawal {
                        recipient: TOKEN_ACCOUNT,
                        asset: MINT,
                        amount: SPL_WITHDRAWN,
                    },
                ],
            })
            .ok_or_else(|| AuditError::Unavailable {
                signature,
                message: "not found".to_owned(),
            });
        async move { origin }
    }

    async fn ring_deposits(&self, page: DepositPage) -> Result<DepositHistory, ClientError> {
        self.examined_limit.store(page.limit, Ordering::Relaxed);
        let start = match page.before {
            Some(before) => self
                .history
                .iter()
                .position(|entry| entry.signature == before)
                .map(|index| index + 1)
                .ok_or_else(|| ClientError::Rpc("unknown cursor".to_owned()))?,
            None => 0,
        };
        let examined: Vec<_> = self
            .history
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take(page.limit)
            .collect();
        Ok(DepositHistory {
            deposits: examined
                .iter()
                .flat_map(|entry| entry.deposits.clone())
                .collect(),
            cursor: examined
                .last()
                .map(|entry| entry.signature)
                .filter(|_| examined.len() == page.limit),
            oldest_slot: examined.last().map(|entry| entry.slot),
        })
    }

    fn ring_config(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<Option<RingConfiguration>, ClientError>> + Send {
        let config = self.configs.get(&ring).copied();
        async move { Ok(config) }
    }

    fn ring_chain_status(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<RingChainStatus, ClientError>> + Send {
        let mut status = self.chain.get(&ring).cloned().unwrap_or_default();
        if let Some(registry) = self.registry().filter(|_| ring == RING) {
            status.registry = Some(registry.status());
        }
        async move { Ok(status) }
    }

    async fn ring_member_records(
        &self,
        request: GetRingMemberRecordsRequest,
    ) -> Result<GetRingMemberRecordsResponse, ClientError> {
        self.record_reads.fetch_add(1, Ordering::Relaxed);
        let registry = self.registry().expect("registry");
        // A network page never answers in the same poll.
        tokio::task::yield_now().await;
        let first = usize::try_from(request.start_index - 1).expect("leaf");
        let records: Vec<_> = registry
            .records
            .iter()
            .skip(first)
            .take(usize::try_from(request.limit).expect("limit"))
            .cloned()
            .collect();
        let end = request.start_index + records.len() as u64;
        Ok(GetRingMemberRecordsResponse {
            context: zolana_indexer_api::Context {
                block_time: 0,
                slot: 99,
            },
            root: registry.root_view(),
            records,
            next_leaf_index: (end < request.expected_next_index).then_some(end),
        })
    }

    async fn ring_member_openings(
        &self,
        request: GetRingMemberOpeningsRequest,
    ) -> Result<GetRingMemberOpeningsResponse, ClientError> {
        self.opening_reads.fetch_add(1, Ordering::Relaxed);
        let registry = self.registry().expect("registry");
        let openings = request
            .members
            .iter()
            .map(|member| {
                let row = registry
                    .records
                    .iter()
                    .find(|row| row.record.member == *member)
                    .expect("registered member");
                RingMemberOpening {
                    present: true,
                    record: row.record.clone(),
                    path: row.path.clone(),
                }
            })
            .collect();
        Ok(GetRingMemberOpeningsResponse {
            context: zolana_indexer_api::Context {
                block_time: 0,
                slot: 99,
            },
            root: registry.root_view(),
            openings,
        })
    }

    async fn ring_record_queue(
        &self,
        _ring: Address,
    ) -> Result<GetRingRecordQueueResponse, ClientError> {
        let registry = self.registry().expect("registry");
        Ok(GetRingRecordQueueResponse {
            context: zolana_indexer_api::Context {
                block_time: 0,
                slot: 99,
            },
            head: registry.applied,
            tail: registry.applied + registry.queue.len() as u64,
            chain_head: Hash([0; 32]),
            entries: registry.queue.clone(),
        })
    }

    fn reader_granted(
        &self,
        request: ReaderGrant,
    ) -> impl Future<Output = Result<bool, ClientError>> + Send {
        let granted = self.granted.contains(&request.reader);
        async move { Ok(granted) }
    }

    fn upgrade_authority(
        &self,
        program: Address,
    ) -> impl Future<Output = Result<Option<Address>, ClientError>> + Send {
        let authority = self.upgrade_authorities.get(&program).copied();
        async move { Ok(authority) }
    }

    fn health(&self) -> impl Future<Output = Result<(), ClientError>> + Send {
        let healthy = self.healthy;
        async move {
            healthy
                .then_some(())
                .ok_or_else(|| ClientError::Rpc("unavailable".to_owned()))
        }
    }

    async fn genesis_hash(&self) -> Result<[u8; 32], ClientError> {
        Ok(GENESIS)
    }

    async fn asset_registry(&self) -> Result<AssetRegistry, ClientError> {
        self.asset_reads.fetch_add(1, Ordering::Relaxed);
        if let Some(delay) = self.asset_delay {
            tokio::time::sleep(delay).await;
        }
        tokio::task::yield_now().await;
        self.assets
            .clone()
            .ok_or_else(|| ClientError::Rpc("asset registry unavailable".to_owned()))
    }
}

/// The transfer whose first nullifier, keys and salt derive from `seed`.
fn ring_transfer(seed: u8) -> Transfer {
    let first_nullifier = field(seed);
    let blinding_seed = right_align(&[seed]);
    Transfer {
        tx_key: ViewingKey::from_bytes(&[seed; 32]),
        ring: RING,
        first_nullifier,
        salt: [seed; 16],
        blinding_seed,
        seed_out: derive_output_blinding_seed(&first_nullifier, &blinding_seed)
            .expect("output seed"),
        tree_id: TREE_ID,
        nullifiers: vec![first_nullifier],
    }
}

fn utxo(owner: u8, asset_address: Address, amount: u64) -> UtxoFields {
    UtxoFields {
        owner_key: [owner; 32],
        nullifier_pk: field(owner ^ 0x80),
        asset_address,
        amount,
        ..UtxoFields::default()
    }
}

fn sol(owner: u8, amount: u64) -> UtxoFields {
    utxo(owner, SOL_MINT, amount)
}

/// A confidential ring output, its recipient published as the owner tag.
fn paid(utxo: UtxoFields, recipient_u: [u8; 32]) -> Output {
    Output::Ring {
        utxo,
        recipient_u,
        tag: None,
    }
}

#[derive(Clone, Copy)]
struct Spend {
    utxo: UtxoFields,
    blinding: [u8; 32],
}

struct Indexed<'a> {
    transfer: &'a Transfer,
    outputs: &'a [Output],
    auditor: &'a X25519Pubkey,
    signature: u8,
    frames: &'a Frames,
}

impl Indexed<'_> {
    fn packed(self) -> ShieldedTransaction {
        self.packed_with(false)
    }

    /// Under key escrow every output nullifier key leaves the disclosure.
    fn packed_with(self, key_escrow: bool) -> ShieldedTransaction {
        let disclosure = self
            .transfer
            .disclosure(Rail::Packed, self.outputs, key_escrow);
        self.publish(Rail::Packed, &disclosure)
    }

    fn delivered(self) -> ShieldedTransaction {
        let disclosure = self
            .transfer
            .disclosure(Rail::Delivered, self.outputs, false);
        self.publish(Rail::Delivered, &disclosure)
    }

    /// The entry key's disclosure, the first spent UTXO's owner the sender.
    fn anonymous(self, spent: &[Option<Spend>]) -> ShieldedTransaction {
        let sender = spent.iter().flatten().next().expect("a spent UTXO").utxo;
        let inputs = AnonymousInputs::Openings {
            sender_nullifier_pk: sender.nullifier_pk,
            inputs: spent
                .iter()
                .map(|spend| spend.map(|spend| input_opening(&spend.utxo, spend.blinding)))
                .collect(),
        };
        self.anonymous_with(sender.owner_key, inputs)
    }

    /// The commitment key's disclosure, each published input named by its UTXO hash.
    fn anonymous_commitments(
        self,
        sender: UtxoFields,
        spent: &[Option<[u8; 32]>],
    ) -> ShieldedTransaction {
        self.anonymous_with(
            sender.owner_key,
            AnonymousInputs::Commitments(spent.to_vec()),
        )
    }

    fn anonymous_with(self, sender_key: [u8; 32], inputs: AnonymousInputs) -> ShieldedTransaction {
        let disclosure = self
            .transfer
            .anonymous_disclosure(sender_key, self.outputs, inputs);
        self.publish(Rail::Anonymous, &disclosure)
    }

    fn publish(self, rail: Rail, disclosure: &AuditDisclosure) -> ShieldedTransaction {
        let mut transaction = self.transfer.publish(Publish {
            slots: self
                .transfer
                .slots(rail, self.outputs)
                .into_iter()
                .map(|slot| slot.output)
                .collect(),
            disclosure,
            auditor: self.auditor,
        });
        transaction.slot = 42;
        transaction.tx_signature = Signature::from([self.signature; 64]);
        let frame = self.transfer.frame(Frame {
            tx: &transaction,
            layout: disclosure.layout(),
            data_free: data_free(self.outputs),
        });
        self.frames
            .lock()
            .unwrap()
            .insert(transaction.tx_signature, frame);
        transaction
    }
}

struct Fixture {
    auditor: X25519Keypair,
    recipient_u: [u8; 32],
    audited: ShieldedTransaction,
    foreign_key: ShieldedTransaction,
    missing_message: ShieldedTransaction,
    frames: Frames,
}

impl Fixture {
    fn new() -> Self {
        let auditor = X25519Keypair::from_bytes(&FIXTURE_AUDITOR);
        let auditor_pk = auditor.pubkey();
        let recipient_u = x25519_u(0x40);
        let frames = Frames::default();
        let audited = Indexed {
            transfer: &ring_transfer(1),
            outputs: &[
                paid(sol(0xb0, 500), recipient_u),
                paid(sol(0xb1, 7), recipient_u),
            ],
            auditor: &auditor_pk,
            signature: 1,
            frames: &frames,
        }
        .packed();
        let mut foreign_key = Indexed {
            transfer: &ring_transfer(2),
            outputs: &[paid(sol(0xb2, 9), recipient_u)],
            auditor: &X25519Keypair::new().pubkey(),
            signature: 2,
            frames: &frames,
        }
        .packed();
        foreign_key.messages[0].view_tag = auditor_view_tag(&auditor_pk);
        let mut missing_message = Indexed {
            transfer: &ring_transfer(3),
            outputs: &[paid(sol(0xb3, 11), recipient_u)],
            auditor: &auditor_pk,
            signature: 3,
            frames: &frames,
        }
        .packed();
        missing_message.messages.clear();
        Self {
            auditor,
            recipient_u,
            audited,
            foreign_key,
            missing_message,
            frames,
        }
    }

    fn source(&self) -> StaticSource {
        let source = StaticSource {
            transactions: Vec::new(),
            origins: HashMap::new(),
            frames: self.frames.clone(),
            confirmed_events: HashMap::new(),
            deposits: HashMap::new(),
            next_cursor: Some(vec![7, 7]),
            scanned_through: None,
            configs: HashMap::from([(
                RING,
                RingConfiguration {
                    auditor_pubkey: self.auditor.pubkey(),
                    authority: authority().pubkey(),
                    mode: RingMode::Off,
                },
            )]),
            chain: HashMap::new(),
            by_tag: HashMap::new(),
            granted: HashSet::from([
                ReaderKey::ed25519(delegate().pubkey()).expect("delegate reader"),
                ReaderKey::p256(Passkey::new(46).pubkey()).expect("passkey reader"),
            ]),
            upgrade_authorities: HashMap::from([(RING, deployer().pubkey())]),
            healthy: true,
            assets: Some(AssetRegistry::default()),
            asset_reads: Arc::new(AtomicUsize::new(0)),
            asset_delay: None,
            history: Vec::new(),
            examined_limit: Arc::new(AtomicUsize::new(0)),
            pages: HashMap::new(),
            registry: Arc::default(),
            record_reads: Arc::new(AtomicUsize::new(0)),
            opening_reads: Arc::new(AtomicUsize::new(0)),
            history_reads: Arc::new(AtomicUsize::new(0)),
        };
        source.with_transactions(vec![
            self.audited.clone(),
            self.foreign_key.clone(),
            self.missing_message.clone(),
        ])
    }

    fn hub(&self, source: StaticSource) -> Hub<StaticSource> {
        Hub::builder(source, GENESIS)
            .with_origins(origins())
            .local(RING, self.auditor.clone())
            .expect("hub")
    }

    fn hub_at(&self, source: StaticSource, now: u64) -> Hub<StaticSource> {
        Hub::builder(source, GENESIS)
            .with_origins(origins())
            .with_clock(Clock::Fixed(now))
            .local(RING, self.auditor.clone())
            .expect("hub")
    }

    async fn read_anonymous(
        &self,
        transactions: Vec<ShieldedTransaction>,
    ) -> GetDecryptedTransactionsResponse {
        let mut source = self.source().with_transactions(transactions);
        source.configs.get_mut(&RING).expect("config").mode = RingMode::Anonymous;
        self.hub(source)
            .service(None)
            .expect("service")
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &auth(&delegate()),
                page: &page(),
            })
            .await
            .expect("read")
    }
}

fn amounts(item: &DecryptedTransaction) -> Vec<u64> {
    item.outputs
        .iter()
        .map(|output| output.utxo.as_ref().expect("utxo").amount)
        .collect()
}

fn page() -> Page {
    Page::new(None, None).expect("page")
}

#[tokio::test]
async fn granted_reader_opens_audited_transfers_and_reports_the_rest() {
    let fixture = Fixture::new();
    let service = fixture
        .hub(fixture.source())
        .service(None)
        .expect("service");
    let page = page();
    let request = auth(&delegate());
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request,
            page: &page,
        })
        .await
        .expect("read");

    assert_eq!(response.context.slot, 99);
    assert_eq!(response.value.cursor, Some(Base64String(vec![7, 7])));
    let [item] = response.value.items.as_slice() else {
        panic!("expected one audited transaction");
    };
    assert_eq!(amounts(item), [500, 7]);
    for output in &item.outputs {
        let mint = output.utxo.as_ref().and_then(|utxo| utxo.mint.as_ref());
        assert_eq!(mint.map(|mint| mint.0), Some(SOL_MINT));
        // The published owner tag, nothing recovered from the recipient's ciphertext.
        assert_eq!(output.recipient_u, Some(Hash(fixture.recipient_u)));
    }
    assert_eq!(item.signers, vec![SENDER.to_bytes().into()]);
    assert_eq!(
        item.withdrawals,
        vec![
            DecryptedWithdrawal {
                recipient: RECIPIENT.to_bytes().into(),
                asset: SOL_MINT.to_bytes().into(),
                amount: WITHDRAWN,
            },
            DecryptedWithdrawal {
                recipient: TOKEN_ACCOUNT.to_bytes().into(),
                asset: MINT.to_bytes().into(),
                amount: SPL_WITHDRAWN,
            }
        ]
    );
    assert_eq!(item.nullifiers.len(), 1);
    let reasons: Vec<(Signature, SkippedReason)> = response
        .value
        .skipped
        .iter()
        .map(|skipped| (skipped.tx_signature.0, skipped.reason))
        .collect();
    assert_eq!(
        reasons,
        vec![
            (
                fixture.foreign_key.tx_signature,
                SkippedReason::InvalidAuditData
            ),
            (
                fixture.missing_message.tx_signature,
                SkippedReason::MissingAuditorMessage
            ),
        ]
    );
}

#[tokio::test]
async fn a_terminal_indexer_page_has_no_next_audit_cursor() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.scanned_through = Some(vec![9, 9]);
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
    let request = auth(&delegate());
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request,
            page: &page,
        })
        .await
        .expect("read");

    assert_eq!(response.value.items.len(), 1);
    assert_eq!(response.value.cursor, None);
}

#[tokio::test]
async fn events_in_one_signature_keep_distinct_ordinals() {
    let fixture = Fixture::new();
    let mut second = fixture.audited.clone();
    second.event_index = Some(1);
    let source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone(), second]);
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
    let request = auth(&delegate());
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request,
            page: &page,
        })
        .await
        .expect("read");

    assert_eq!(response.value.items.len(), 2);
    assert_eq!(
        response.value.items[0].tx_signature,
        response.value.items[1].tx_signature
    );
    assert_eq!(response.value.items[0].event_index, 0);
    assert_eq!(response.value.items[1].event_index, 1);
}

#[tokio::test]
async fn passkey_reader_opens_anonymous_spend_trace() {
    let fixture = Fixture::new();
    let mut transfer = ring_transfer(70);
    transfer.nullifiers.push(field(0x71));
    let sender = Spend {
        utxo: sol(0xa1, 900),
        blinding: field(0x60),
    };
    let tag = RingTag::from_bytes([0x53; 31]);
    let outputs = [
        Output::Ring {
            utxo: sol(0xb5, 500),
            recipient_u: x25519_u(0x50),
            tag: Some(RingTag::from_bytes([0x51; 31])),
        },
        Output::Ring {
            utxo: sol(0xb6, 501),
            recipient_u: x25519_u(0x52),
            tag: Some(tag),
        },
    ];
    let tx = Indexed {
        transfer: &transfer,
        outputs: &outputs,
        auditor: &fixture.auditor.pubkey(),
        signature: 70,
        frames: &fixture.frames,
    }
    .anonymous(&[Some(sender), None]);
    let mut source = fixture.source().with_transactions(vec![tx]);
    source.configs.get_mut(&RING).expect("config").mode = RingMode::Anonymous;
    let module = rpc_module(Arc::new(fixture.hub(source))).expect("module");
    let response: GetDecryptedTransactionsResponse = module
        .call(
            GET_DECRYPTED_TRANSACTIONS,
            as_object(signed_request(
                &Passkey::new(46),
                target(RING),
                unix_now().expect("clock"),
            )),
        )
        .await
        .expect("passkey read");
    let [item] = response.value.items.as_slice() else {
        panic!("anonymous transaction must be readable")
    };
    assert_eq!(
        item.sender,
        Some(DecryptedSender {
            owner_key: sender.utxo.owner_key.into(),
            nullifier_pk: Some(sender.utxo.nullifier_pk.into()),
        })
    );
    let [spent, dummy] = item.inputs.as_slice() else {
        panic!("one input per published nullifier")
    };
    assert_eq!(
        spent.opening.as_ref().map(|opening| opening.amount),
        Some(900)
    );
    assert_eq!(dummy.opening, None);
    assert_eq!(amounts(item), [500, 501]);
    assert_eq!(item.outputs[1].tag, Some(Hash(tag.field())));
    assert!(item.payload_errors.is_empty());
    assert!(response.value.skipped.is_empty());
}

#[tokio::test]
async fn an_input_spending_a_utxo_the_page_opened_resolves_its_ring() {
    let fixture = Fixture::new();
    let utxos = SpentUtxo::new(&fixture);
    let opened = Some(DecryptedInputRing::Ring {
        commitment: utxos.commitment.into(),
    });
    for spent in [&utxos.entry, &utxos.spent] {
        let page = fixture
            .read_anonymous(vec![utxos.paid.clone(), spent.clone()])
            .await;
        assert_eq!(input_ring(&page), opened);
    }
    // The entry key opens the input itself, only its ring stays open.
    assert!(matches!(
        input_ring(&fixture.read_anonymous(vec![utxos.entry.clone()]).await),
        Some(DecryptedInputRing::Unresolved { .. })
    ));
    let alone = fixture.read_anonymous(vec![utxos.spent.clone()]).await;
    assert!(alone.value.items.is_empty());
    let reasons: Vec<SkippedReason> = alone
        .value
        .skipped
        .iter()
        .map(|skipped| skipped.reason)
        .collect();
    assert_eq!(reasons, [SkippedReason::UnseenInput]);
}

/// A member paid on an anonymous ring, then two transfers that spend the member's UTXO.
struct SpentUtxo {
    paid: ShieldedTransaction,
    /// The commitment key's spend, the input named by its UTXO hash.
    spent: ShieldedTransaction,
    /// The entry key's spend, the input opened in full.
    entry: ShieldedTransaction,
    /// The paid output as the spending input names it.
    commitment: [u8; 32],
    member: UtxoFields,
}

impl SpentUtxo {
    fn new(fixture: &Fixture) -> Self {
        let auditor = &fixture.auditor.pubkey();
        let member = sol(0xa4, 70);
        let paying = ring_transfer(80);
        let payment = [
            Output::Ring {
                utxo: member,
                recipient_u: x25519_u(0x54),
                tag: Some(RingTag::from_bytes([0x55; 31])),
            },
            Output::Dummy,
        ];
        let paid = Indexed {
            transfer: &paying,
            outputs: &payment,
            auditor,
            signature: 80,
            frames: &fixture.frames,
        }
        .anonymous(&[Some(Spend {
            utxo: sol(0xa5, 70),
            blinding: field(0x65),
        })]);
        let received = paying.slot(Rail::Anonymous, 0, &payment[0]);
        let commitment = received.output.output_context.hash;
        let exit = [Output::Exit(sol(0xe8, 70)), Output::Dummy];
        let spent = Indexed {
            transfer: &ring_transfer(81),
            outputs: &exit,
            auditor,
            signature: 81,
            frames: &fixture.frames,
        }
        .anonymous_commitments(member, &[Some(commitment)]);
        let entry = Indexed {
            transfer: &ring_transfer(82),
            outputs: &exit,
            auditor,
            signature: 82,
            frames: &fixture.frames,
        }
        .anonymous(&[Some(Spend {
            utxo: member,
            blinding: received.blinding,
        })]);
        Self {
            paid,
            spent,
            entry,
            commitment,
            member,
        }
    }

    /// The anonymous ring serving `pages` by cursor.
    fn source(&self, fixture: &Fixture, pages: [(Option<Vec<u8>>, Paged); 2]) -> StaticSource {
        let mut source = fixture.source().with_transactions(vec![
            self.paid.clone(),
            self.spent.clone(),
            self.entry.clone(),
        ]);
        source.configs.get_mut(&RING).expect("config").mode = RingMode::Anonymous;
        source.pages = HashMap::from(pages);
        source
    }
}

fn paged(transactions: Vec<ShieldedTransaction>, next: Option<u8>, frontier: Option<u8>) -> Paged {
    Paged {
        transactions,
        next_cursor: next.map(|byte| vec![byte]),
        scanned_through: frontier.map(|byte| vec![byte]),
    }
}

fn input_ring(response: &GetDecryptedTransactionsResponse) -> Option<DecryptedInputRing> {
    response
        .value
        .items
        .last()
        .expect("spending transfer")
        .inputs[0]
        .opening
        .as_ref()
        .expect("opening")
        .ring
        .clone()
}

/// A read of the page `cursor` names, the attestation covers the cursor.
async fn read_at(
    service: &AuditService<StaticSource>,
    cursor: Option<u8>,
) -> GetDecryptedTransactionsResponse {
    let page = Page::new(cursor.map(|byte| vec![byte].into()), None).expect("page");
    let request = match cursor {
        Some(byte) => GetDecryptedTransactionsRequest::read(target(RING))
            .with_cursor(vec![byte].into())
            .expect("cursor"),
        None => GetDecryptedTransactionsRequest::read(target(RING)),
    }
    .sign(&delegate())
    .expect("request");
    service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request.auth,
            page: &page,
        })
        .await
        .expect("read")
}

fn utxos_request(hashes: Vec<Hash>) -> GetAuditedUtxosRequest {
    GetAuditedUtxosRequest::read(target(RING), hashes)
        .expect("UTXO read")
        .sign(&delegate())
        .expect("signed UTXO read")
}

#[tokio::test]
async fn an_input_whose_utxo_an_earlier_page_opened_resolves_through_the_store() {
    let fixture = Fixture::new();
    let utxos = SpentUtxo::new(&fixture);
    let source = utxos.source(
        &fixture,
        [
            (None, paged(vec![utxos.paid.clone()], Some(1), None)),
            (
                Some(vec![1]),
                paged(vec![utxos.spent.clone()], None, Some(2)),
            ),
        ],
    );
    let service = fixture.hub(source).service(None).expect("service");
    read_at(&service, None).await;
    assert_eq!(
        input_ring(&read_at(&service, Some(1)).await),
        Some(DecryptedInputRing::Ring {
            commitment: utxos.commitment.into(),
        })
    );
}

#[tokio::test]
async fn a_backfill_fills_the_store_before_any_page_read() {
    let fixture = Fixture::new();
    let utxos = SpentUtxo::new(&fixture);
    let mut source = utxos.source(
        &fixture,
        [
            (None, paged(vec![utxos.paid.clone()], Some(1), None)),
            (Some(vec![1]), paged(Vec::new(), None, Some(2))),
        ],
    );
    source.pages.insert(
        Some(vec![9]),
        paged(vec![utxos.spent.clone()], None, Some(10)),
    );
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    let found = service
        .audited_utxos(&utxos_request(vec![utxos.commitment.into()]))
        .await
        .expect("UTXO read");
    let [Some(view)] = found.value.utxos.as_slice() else {
        panic!("the backfill opened the paid UTXO, {:?}", found.value.utxos);
    };
    assert_eq!(found.context.slot, 99);
    assert_eq!(
        (view.utxo.amount, view.utxo.owner_key.0.to_bytes()),
        (utxos.member.amount, utxos.member.owner_key)
    );
    assert_eq!(view.tx_signature.0, utxos.paid.tx_signature);
    assert_eq!(
        input_ring(&read_at(&service, Some(9)).await),
        Some(DecryptedInputRing::Ring {
            commitment: utxos.commitment.into(),
        })
    );
}

/// The audited deposit of `member` into the ring at `blinding`, its capsule sealed to `auditor`.
fn audited_deposit(
    auditor: &X25519Pubkey,
    member: &UtxoFields,
    blinding: [u8; 32],
) -> (ShieldedTransaction, Vec<ConfirmedDeposit>) {
    let opening = DepositOpening {
        owner_hash: member.owner_hash(),
        blinding: zeroize::Zeroizing::new(blinding),
        owner_key: Some(member.owner_key),
    };
    let owner_utxo_hash =
        zolana_transaction::owner_utxo_hash(&opening.owner_hash, &opening.blinding).unwrap();
    let sealed = seal_deposits(&[opening], auditor).unwrap();
    let capsule = custom_ring_interface::RingDepositAuditCapsule {
        slot_index: 0,
        eph_pk: sealed.ephemeral_pk.as_bytes(),
        ciphertext: &sealed.ciphertexts[0],
        recipient_ciphertext: &[],
    }
    .encode();
    let group = deposit_fixture::group(RING, true, vec![(owner_utxo_hash, capsule.clone())]);
    let commitment = member.commitment(Placement {
        blinding,
        ring: Some(RING),
        tree_id: TREE_ID,
    });
    let deposit = ShieldedTransaction {
        slot: 40,
        tx_signature: Signature::from([79; 64]),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![zolana_transaction::OutputSlot {
            view_tag: field(0x56),
            output_context: zolana_transaction::OutputContext {
                hash: commitment,
                tree_id: TREE_ID,
                leaf_index: 3,
            },
            payload: zolana_event::encode_encrypted_ring_deposit_output(
                zolana_event::EncryptedRingDepositOutput {
                    owner_utxo_hash,
                    asset: member.asset_address.to_bytes(),
                    amount: member.amount,
                    data_hash: None,
                    ring_program_id: RING.to_bytes(),
                    ring_data_hash: [0; 32],
                    encrypted: zolana_event::EncryptedRingDepositData {
                        tx_viewing_pk: [0; 33],
                        salt: [0; 16],
                        ciphertext: capsule,
                    },
                },
            ),
        }],
        messages: Vec::new(),
        nullifiers: Vec::new(),
        proofless: true,
        ring_config: None,
        ring_program_id: Some(RING),
    };
    let bindings = ring_event_origin_in(&[group], 0, RING).unwrap().deposits;
    (deposit, bindings)
}

#[tokio::test]
async fn a_backfill_opens_a_deposited_utxo_a_later_spend_names() {
    let fixture = Fixture::new();
    let member = sol(0xa6, 64);
    let blinding = field(0x66);
    let (deposit, bindings) = audited_deposit(&fixture.auditor.pubkey(), &member, blinding);
    let commitment = deposit.output_slots[0].output_context.hash;
    let exit = [Output::Exit(sol(0xe9, 64)), Output::Dummy];
    let spent = Indexed {
        transfer: &ring_transfer(83),
        outputs: &exit,
        auditor: &fixture.auditor.pubkey(),
        signature: 83,
        frames: &fixture.frames,
    }
    .anonymous_commitments(member, &[Some(commitment)]);
    let mut source = fixture
        .source()
        .with_transactions(vec![deposit.clone(), spent.clone()]);
    source.configs.get_mut(&RING).expect("config").mode = RingMode::Anonymous;
    source.deposits.insert(deposit.tx_signature, bindings);
    source.pages = HashMap::from([
        (None, paged(vec![deposit, spent.clone()], Some(1), None)),
        (Some(vec![1]), paged(Vec::new(), None, Some(2))),
        (Some(vec![9]), paged(vec![spent], None, Some(10))),
    ]);
    let service = fixture.hub(source).service(None).expect("service");
    let before = read_at(&service, Some(9)).await;
    assert_eq!(
        before
            .value
            .skipped
            .iter()
            .map(|row| row.reason)
            .collect::<Vec<_>>(),
        [SkippedReason::UnseenInput]
    );
    service.backfill_utxos().await.expect("backfill");
    let found = service
        .audited_utxos(&utxos_request(vec![commitment.into()]))
        .await
        .expect("UTXO read");
    let [Some(view)] = found.value.utxos.as_slice() else {
        panic!("the backfill opened the deposit, {:?}", found.value.utxos);
    };
    assert_eq!(
        (view.utxo.amount, view.utxo.nullifier_pk.clone()),
        (64, None)
    );
    let after = read_at(&service, Some(9)).await;
    assert_eq!(
        input_ring(&after),
        Some(DecryptedInputRing::Ring {
            commitment: commitment.into(),
        })
    );
    assert_eq!(
        after.value.items[0].sender.as_ref().unwrap().nullifier_pk,
        None
    );
}

#[tokio::test]
async fn audited_utxos_answer_in_request_order_with_null_for_an_unseen_hash() {
    let fixture = Fixture::new();
    let hub = Arc::new(fixture.hub(fixture.source()));
    let service = hub.service(None).expect("service");
    read_at(&service, None).await;
    let outputs: Vec<[u8; 32]> = fixture
        .audited
        .output_slots
        .iter()
        .map(|slot| slot.output_context.hash)
        .collect();
    let unseen = Hash([0x77; 32]);
    let request = utxos_request(vec![outputs[1].into(), unseen, outputs[0].into()]);
    let module = rpc_module(hub).expect("module");
    let response: GetAuditedUtxosResponse = module
        .call(GET_AUDITED_UTXOS, as_object(&request))
        .await
        .expect("UTXO read");
    let amounts: Vec<Option<u64>> = response
        .value
        .utxos
        .iter()
        .map(|view| view.as_ref().map(|view| view.utxo.amount))
        .collect();
    assert_eq!(amounts, [Some(7), None, Some(500)]);
    // A page read opens UTXOs, only the backfill vouches for the history before its context.
    assert_eq!(response.context.slot, 0);
    let wire = as_object(response.value.utxos[0].as_ref().expect("opened UTXO"));
    let keys: HashSet<&str> = wire.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        HashSet::from([
            "utxoHash",
            "utxo",
            "slot",
            "txSignature",
            "eventIndex",
            "slotIndex",
        ])
    );
    assert_eq!(
        wire["utxoHash"],
        serde_json::json!(Hash(outputs[1]).to_base58())
    );
    assert_eq!(wire["slotIndex"], serde_json::json!(1));
}

#[tokio::test]
async fn audited_utxos_refuse_an_ungranted_reader_a_bad_count_a_changed_hash_and_a_replay() {
    let fixture = Fixture::new();
    let service = fixture
        .hub(fixture.source())
        .service(None)
        .expect("service");
    let hashes = vec![Hash([0x77; 32])];
    let stranger_request = GetAuditedUtxosRequest::read(target(RING), hashes.clone())
        .expect("UTXO read")
        .sign(&stranger())
        .expect("signed UTXO read");
    assert!(matches!(
        service.audited_utxos(&stranger_request).await,
        Err(RingRpcError::Unauthorized(Unauthorized::NotGranted))
    ));
    for count in [0, AUDITED_UTXOS_LIMIT + 1] {
        let hashes = vec![Hash([0x77; 32]); count];
        assert!(matches!(
            GetAuditedUtxosRequest::read(target(RING), hashes.clone()),
            Err(ReadBuildError::UtxoHashes)
        ));
        let request = GetAuditedUtxosRequest {
            utxo_hashes: hashes,
            ..utxos_request(vec![Hash([0x77; 32])])
        };
        assert!(matches!(
            service.audited_utxos(&request).await,
            Err(RingRpcError::InvalidUtxoRequest)
        ));
    }
    let mut changed = utxos_request(hashes.clone());
    changed.utxo_hashes = vec![Hash([0x78; 32])];
    assert!(matches!(
        service.audited_utxos(&changed).await,
        Err(RingRpcError::Unauthorized(Unauthorized::BadSignature))
    ));
    let request = utxos_request(hashes);
    assert!(service.audited_utxos(&request).await.is_ok());
    assert!(matches!(
        service.audited_utxos(&request).await,
        Err(RingRpcError::Unauthorized(Unauthorized::Replay))
    ));
}

/// Each owner's record escrowing its nullifier key under one registry root.
#[derive(Clone)]
struct EscrowRegistry {
    root: [u8; 32],
    records: Vec<RingIndexedMemberRecordView>,
    next_index: u64,
    applied: u64,
    /// Writes past `applied`, still pending.
    queue: Vec<RingQueueEntryView>,
}

impl EscrowRegistry {
    fn new(owners: &[UtxoFields]) -> Self {
        let sealed = [0x5a; 32];
        let eph_pk = X25519Keypair::new().pubkey();
        let mut members: Vec<([u8; 32], UtxoFields)> = owners
            .iter()
            .map(|utxo| {
                let member = Member::owner_tag(&utxo.owner_key).expect("owner tag");
                (*member.as_bytes(), *utxo)
            })
            .collect();
        members.sort_by_key(|(member, _)| *member);
        let next = |position: usize| {
            members
                .get(position)
                .map_or(MemberRecord::SENTINEL.next, |(member, _)| *member)
        };
        let mut records = vec![MemberRecord {
            next: next(0),
            ..MemberRecord::SENTINEL
        }];
        let mut views = Vec::new();
        for (position, (member, utxo)) in members.iter().enumerate() {
            let escrow_key = EscrowKey {
                nullifier_pk: &utxo.nullifier_pk,
                ciphertext: &sealed,
            }
            .hash()
            .expect("escrow key");
            records.push(MemberRecord {
                member: *member,
                next: next(position + 1),
                lists: 0,
                escrow_key,
            });
            views.push(RingMemberRecordView {
                member: Hash(*member),
                next: Hash(next(position + 1)),
                lists: 0,
                escrow_key: Hash(escrow_key),
                owner_pubkey: Some(Address::new_from_array(utxo.owner_key).into()),
                nullifier_pk: Some(Hash(utxo.nullifier_pk)),
                eph_pk: Some(Base64String(eph_pk.as_bytes().to_vec())),
                ciphertext: Some(Base64String(sealed.to_vec())),
            });
        }
        let tree = MemberRegistryTree::from_records(records).expect("record tree");
        let records: Vec<RingIndexedMemberRecordView> = views
            .into_iter()
            .zip(1u64..)
            .map(|(record, index)| {
                let path = tree.path(index).expect("path");
                RingIndexedMemberRecordView {
                    record,
                    path: RingRecordPathView {
                        index,
                        siblings: path.siblings.iter().map(|level| level.map(Hash)).collect(),
                    },
                }
            })
            .collect();
        Self {
            root: tree.root().expect("root"),
            next_index: records.len() as u64 + 1,
            records,
            applied: 0,
            queue: Vec::new(),
        }
    }

    fn applied(mut self, applied: u64) -> Self {
        self.applied = applied;
        self
    }

    /// `owners` registered after the newest application.
    fn with_pending(mut self, owners: &[UtxoFields]) -> Self {
        self.queue = owners
            .iter()
            .zip(self.applied..)
            .map(|(utxo, position)| RingQueueEntryView {
                position,
                member: Hash(
                    *Member::owner_tag(&utxo.owner_key)
                        .expect("owner tag")
                        .as_bytes(),
                ),
                mask: 0,
                value: 0,
                escrow_key: Hash([0; 32]),
                slot: 41,
            })
            .collect();
        self
    }

    fn status(&self) -> RegistryStatus {
        RegistryStatus {
            history: vec![Some(RegistryRoot {
                root: Hash(self.root),
                applied: self.applied,
                slot: 40,
            })],
            history_cursor: 0,
            next_index: u32::try_from(self.next_index).expect("registry size"),
            floor: 0,
            prior_floor: 0,
            floor_slot: 0,
            queue_head: self.applied,
            queue_tail: self.applied + self.queue.len() as u64,
        }
    }

    fn root_view(&self) -> RingRegistryRootView {
        RingRegistryRootView {
            root: Hash(self.root),
            root_index: 0,
            applied: self.applied,
            next_index: self.next_index,
        }
    }
}

/// A packed transfer of a Registry-mode ring, its owners' nullifier keys left to the registry.
fn escrowed_source(
    fixture: &Fixture,
    owners: &[UtxoFields],
    registered: &[UtxoFields],
) -> StaticSource {
    let audited = Indexed {
        transfer: &ring_transfer(90),
        outputs: &owners
            .iter()
            .map(|utxo| paid(*utxo, fixture.recipient_u))
            .collect::<Vec<_>>(),
        auditor: &fixture.auditor.pubkey(),
        signature: 90,
        frames: &fixture.frames,
    }
    .packed_with(true);
    let mut source = fixture.source().with_transactions(vec![audited.clone()]);
    source.configs.get_mut(&RING).expect("config").mode = RingMode::Registry;
    source.pages = HashMap::from([
        (None, paged(vec![audited], None, Some(1))),
        (Some(vec![1]), paged(Vec::new(), None, Some(1))),
    ]);
    *source.registry.lock().unwrap() = Some(EscrowRegistry::new(registered));
    source
}

#[tokio::test]
async fn an_escrowed_ring_opens_its_outputs_with_the_keys_its_registry_holds() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners);
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    let page = read_at(&service, None).await;
    let [item] = page.value.items.as_slice() else {
        panic!("one escrowed transfer, {:?}", page.value.skipped);
    };
    assert!(item.payload_errors.is_empty(), "{:?}", item.payload_errors);
    assert_eq!(amounts(item), [30, 12]);
    let keys: Vec<Hash> = item
        .outputs
        .iter()
        .map(|output| output.utxo.as_ref().expect("utxo").nullifier_pk.clone())
        .collect();
    assert_eq!(keys, owners.map(|utxo| Hash(utxo.nullifier_pk)));
    assert_eq!(record_reads.load(Ordering::Relaxed), 1);
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(record_reads.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_read_never_reads_the_registry() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners);
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    let page = read_at(&service, None).await;
    assert_eq!(
        escrow_errors(&page),
        [OutputPayloadErrorKind::EscrowUnknown; 2]
    );
    assert_eq!(record_reads.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn concurrent_backfills_read_the_registry_once() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30)];
    let source = escrowed_source(&fixture, &owners, &owners);
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    let (first, second) = tokio::join!(service.backfill_utxos(), service.backfill_utxos());
    first.expect("first backfill");
    second.expect("second backfill");
    assert_eq!(record_reads.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn an_applied_write_rereads_only_the_members_it_names() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners);
    let registry = source.registry.clone();
    *registry.lock().unwrap() = Some(EscrowRegistry::new(&owners[..1]).with_pending(&owners[1..]));
    let record_reads = source.record_reads.clone();
    let opening_reads = source.opening_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(
        escrow_errors(&read_at(&service, None).await),
        [OutputPayloadErrorKind::EscrowUnknown]
    );

    *registry.lock().unwrap() = Some(EscrowRegistry::new(&owners).applied(1));
    service.backfill_utxos().await.expect("backfill");
    assert!(escrow_errors(&read_at(&service, None).await).is_empty());
    assert_eq!(record_reads.load(Ordering::Relaxed), 1);
    assert_eq!(opening_reads.load(Ordering::Relaxed), 1);

    // Writes no refresh saw pending leave only the full scan.
    let late = [owners[0], owners[1], sol(0xc2, 5)];
    *registry.lock().unwrap() = Some(EscrowRegistry::new(&late).applied(3));
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(record_reads.load(Ordering::Relaxed), 2);
    assert_eq!(opening_reads.load(Ordering::Relaxed), 1);
}

fn escrow_errors(page: &GetDecryptedTransactionsResponse) -> Vec<OutputPayloadErrorKind> {
    let [item] = page.value.items.as_slice() else {
        panic!("one escrowed transfer, {:?}", page.value.skipped);
    };
    item.payload_errors.iter().map(|error| error.kind).collect()
}

#[tokio::test]
async fn an_owner_the_registry_never_escrowed_reports_its_slot() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners[..1]);
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    let page = read_at(&service, None).await;
    let [item] = page.value.items.as_slice() else {
        panic!("one escrowed transfer, {:?}", page.value.skipped);
    };
    assert_eq!(amounts(item), [30]);
    assert_eq!(
        item.payload_errors,
        [DecryptedPayloadError {
            slot_index: 1,
            kind: OutputPayloadErrorKind::EscrowUnknown,
        }]
    );
}

/// A page short of a record keeps no partial key map, the next backfill reads again.
#[tokio::test]
async fn a_registry_page_short_of_a_record_escrows_no_key() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30), sol(0xc1, 12)];
    let source = escrowed_source(&fixture, &owners, &owners);
    source
        .registry
        .lock()
        .unwrap()
        .as_mut()
        .expect("registry")
        .records
        .remove(0);
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(
        escrow_errors(&read_at(&service, None).await),
        [OutputPayloadErrorKind::EscrowUnknown; 2]
    );
    let refreshed = record_reads.load(Ordering::Relaxed);
    service.backfill_utxos().await.expect("backfill");
    assert!(record_reads.load(Ordering::Relaxed) > refreshed);
}

#[tokio::test]
async fn the_backfill_reads_the_escrowed_keys_before_its_first_page() {
    let fixture = Fixture::new();
    let owners = [sol(0xc0, 30)];
    let mut source = escrowed_source(&fixture, &owners, &owners);
    let audited = source.transactions.clone();
    source.pages = HashMap::from([(None, paged(audited, None, Some(1)))]);
    let record_reads = source.record_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("backfill");
    assert_eq!(record_reads.load(Ordering::Relaxed), 1);
    let hash = fixture_output_hash(&service, &owners[0]).await;
    let found = service
        .audited_utxos(&utxos_request(vec![hash]))
        .await
        .expect("UTXO read");
    assert_eq!(
        found.value.utxos[0].as_ref().map(|view| view.utxo.amount),
        Some(30)
    );
}

/// The commitment of `owner`'s output on the ring's audited page.
async fn fixture_output_hash(service: &AuditService<StaticSource>, owner: &UtxoFields) -> Hash {
    let page = read_at(service, None).await;
    page.value.items[0]
        .outputs
        .iter()
        .find(|output| {
            output
                .utxo
                .as_ref()
                .is_some_and(|utxo| utxo.owner_key.0.to_bytes() == owner.owner_key)
        })
        .expect("owner output")
        .output_context
        .hash
        .clone()
}

#[tokio::test]
async fn confirmed_deposit_and_merge_tag_collisions_do_not_poison_an_audit_page() {
    let fixture = Fixture::new();
    let mut deposit = fixture.missing_message.clone();
    deposit.tx_signature = Signature::from([11; 64]);
    deposit.proofless = true;
    deposit.tx_viewing_pk = None;
    deposit.nullifiers.clear();
    let mut merge = fixture.missing_message.clone();
    merge.tx_signature = Signature::from([12; 64]);
    merge.tx_viewing_pk = None;
    let source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone(), deposit, merge]);
    let service = fixture.hub(source).service(None).unwrap();
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &auth(&delegate()),
            page: &page(),
        })
        .await
        .unwrap();
    assert_eq!(response.value.items.len(), 1);
    assert_eq!(
        response.value.items[0].tx_signature,
        fixture.audited.tx_signature.into()
    );
    assert!(response.value.skipped.is_empty());
}

#[tokio::test]
async fn recipient_bodies_cannot_poison_an_audit_page_or_trigger_registry_refresh() {
    let fixture = Fixture::new();
    let auditor = fixture.auditor.pubkey();
    let outputs: Vec<Output> = (0u8..6)
        .map(|k| paid(sol(0xb0 + k, 10 + u64::from(k)), x25519_u(0x40 + k)))
        .chain([Output::Dummy, Output::Dummy])
        .collect();
    let delivered = |seed: u8| {
        Indexed {
            transfer: &ring_transfer(seed),
            outputs: &outputs,
            auditor: &auditor,
            signature: seed,
            frames: &fixture.frames,
        }
        .delivered()
    };
    // The body is a stream cipher, a flipped bit changes the amount the commitment binds.
    let mut corrupted = delivered(8);
    *corrupted.output_slots[1]
        .payload
        .last_mut()
        .expect("delivered body") ^= 1;
    let mut unknown_mint = delivered(9);
    let secret = ring_transfer(9).delivered_secret(&x25519_u(0x42), 2);
    let body = RingDeliveredBody {
        asset_address: Address::new_from_array([0x99; 32]),
        amount: 12,
    }
    .seal(&secret)
    .expect("delivered body");
    unknown_mint.output_slots[2].payload = encode_ring_confidential_delivered_output(&body);
    let mut invalid_disclosure = delivered(10);
    // The first disclosure field, past the tagged ephemeral key and the sealed key.
    invalid_disclosure.messages[0].data[65] = 0xff;
    let mut source =
        fixture
            .source()
            .with_transactions(vec![corrupted, unknown_mint, invalid_disclosure]);
    source.assets = None;
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service(None).unwrap();
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &auth(&delegate()),
            page: &page(),
        })
        .await
        .unwrap();
    assert_eq!(response.value.items.len(), 2);
    for (item, slot_index) in response.value.items.iter().zip([1, 2]) {
        assert_eq!(item.outputs.len(), outputs.len() - 1);
        assert_eq!(
            item.payload_errors,
            [DecryptedPayloadError {
                slot_index,
                kind: OutputPayloadErrorKind::Commitment,
            }]
        );
    }
    assert_eq!(response.value.skipped.len(), 1);
    assert_eq!(
        response.value.skipped[0].reason,
        SkippedReason::InvalidAuditData
    );
    assert_eq!(reads.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn unknown_assets_share_refresh_and_back_off_after_failure() {
    const ASSET_ID: u64 = 2;
    let asset = Address::new_from_array([8; 32]);
    let fixture = Fixture::new();
    let mut source = fixture.source().with_transactions(vec![Indexed {
        transfer: &ring_transfer(8),
        outputs: &[paid(utxo(0xb8, asset, 13), fixture.recipient_u)],
        auditor: &fixture.auditor.pubkey(),
        signature: 8,
        frames: &fixture.frames,
    }
    .packed()]);
    source.assets = Some(AssetRegistry::new([(ASSET_ID, asset)]).expect("asset registry"));
    let unknown_transactions = source.transactions.clone();
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
    let ed25519 = auth(&delegate());
    let p256 = auth(&Passkey::new(46));
    let (first, second) = tokio::join!(
        service.read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &ed25519,
            page: &page,
        }),
        service.read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &p256,
            page: &page,
        })
    );
    let mint = |response: &GetDecryptedTransactionsResponse| {
        let utxo = response.value.items[0].outputs[0].utxo.as_ref();
        utxo.and_then(|utxo| utxo.mint.as_ref()).map(|mint| mint.0)
    };
    for result in [first, second] {
        assert_eq!(mint(&result.expect("refreshed read")), Some(asset));
    }
    assert_eq!(reads.load(Ordering::Relaxed), 1);

    let mut source = fixture
        .source()
        .with_transactions(unknown_transactions.clone());
    source.assets = None;
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    for signer in [&delegate() as &dyn ReadSigner, &Passkey::new(46)] {
        let response = service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &auth(signer),
                page: &page,
            })
            .await
            .unwrap();
        assert_eq!(response.value.items[0].outputs.len(), 1);
        assert_eq!(mint(&response), None);
        assert!(response.value.skipped.is_empty());
    }
    assert_eq!(reads.load(Ordering::Relaxed), 1);

    let mut source = fixture.source().with_transactions(unknown_transactions);
    source.asset_delay = Some(Duration::from_secs(1));
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    let first = auth(&delegate());
    assert!(tokio::time::timeout(
        Duration::from_millis(1),
        service.read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &first,
            page: &page,
        })
    )
    .await
    .is_err());
    let second = auth(&Passkey::new(46));
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &second,
            page: &page,
        })
        .await
        .unwrap();
    assert_eq!(mint(&response), None);
    assert!(response.value.skipped.is_empty());
    assert_eq!(reads.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn only_granted_readers_with_the_configured_auditor_key_can_read() {
    let fixture = Fixture::new();
    let page = page();
    let service = fixture
        .hub(fixture.source())
        .service(None)
        .expect("service");
    for signer in [&delegate() as &dyn ReadSigner, &Passkey::new(46)] {
        let request = auth(signer);
        assert!(service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page,
            })
            .await
            .is_ok());
    }

    for signer in [&authority() as &dyn ReadSigner, &stranger()] {
        let request = auth(signer);
        assert!(matches!(
            service
                .read(AuditRead {
                    read: PagedRead::DecryptedTransactions,
                    auth: &request,
                    page: &page,
                })
                .await,
            Err(RingRpcError::Unauthorized(Unauthorized::NotGranted))
        ));
    }

    let mut source = fixture.source();
    source.configs.insert(
        RING,
        RingConfiguration {
            auditor_pubkey: X25519Keypair::new().pubkey(),
            authority: authority().pubkey(),
            mode: RingMode::Off,
        },
    );
    let service = fixture.hub(source).service(None).expect("service");
    let request = auth(&delegate());
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page,
            })
            .await,
        Err(RingRpcError::Unauthorized(Unauthorized::AuditorKeyMismatch))
    ));
}

#[tokio::test]
async fn rows_outside_the_ring_are_dropped() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source
        .origins
        .insert((fixture.audited.tx_signature, 0), false);
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
    let request = auth(&delegate());
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request,
            page: &page,
        })
        .await
        .expect("read");
    assert!(response.value.items.is_empty());
    assert_eq!(response.value.skipped.len(), 2);
    assert_eq!(response.value.cursor, Some(Base64String(vec![7, 7])));
}

#[tokio::test]
async fn origin_cache_separates_event_ordinals_in_one_transaction() {
    let fixture = Fixture::new();
    let first = fixture.audited.clone();
    let mut second = first.clone();
    second.event_index = Some(1);
    let signature = first.tx_signature;
    let mut source = fixture.source();
    source.transactions = vec![first, second];
    source.origins = HashMap::from([((signature, 0), true), ((signature, 1), false)]);
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
    let request = auth(&delegate());
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request,
            page: &page,
        })
        .await
        .expect("read");

    assert_eq!(response.value.items.len(), 1);
}

#[tokio::test]
async fn missing_event_index_fails_closed() {
    let fixture = Fixture::new();
    let mut transaction = fixture.audited.clone();
    transaction.event_index = None;
    let mut source = fixture.source();
    source.transactions = vec![transaction];
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
    let request = auth(&delegate());

    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page,
            })
            .await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));
}

#[tokio::test]
async fn unknown_origins_fail_the_page() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.origins.remove(&(fixture.audited.tx_signature, 0));
    let service = fixture.hub(source).service(None).expect("service");
    let page = page();
    let request = auth(&delegate());
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page,
            })
            .await,
        Err(RingRpcError::Origin(AuditError::Unavailable { .. }))
    ));
}

#[tokio::test]
async fn accepted_nonces_are_single_use() {
    let fixture = Fixture::new();
    let service = fixture
        .hub(fixture.source())
        .service(None)
        .expect("service");
    let page = page();
    let request = auth(&delegate());
    assert!(service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &request,
            page: &page,
        })
        .await
        .is_ok());
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page,
            })
            .await,
        Err(RingRpcError::Unauthorized(Unauthorized::Replay))
    ));
    let distinct = auth(&delegate());
    assert!(service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &distinct,
            page: &page,
        })
        .await
        .is_ok());
}

#[tokio::test]
async fn indexer_pages_must_match_the_attested_bounds() {
    let fixture = Fixture::new();
    let signer = delegate();

    let source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone(); 101]);
    let service = fixture.hub(source).service(None).expect("service");
    let request = auth(&signer);
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page(),
            })
            .await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));

    for cursor in [Vec::new(), vec![1; 257]] {
        let mut source = fixture.source();
        source.next_cursor = Some(cursor);
        let service = fixture.hub(source).service(None).expect("service");
        let request = auth(&signer);
        assert!(matches!(
            service
                .read(AuditRead {
                    read: PagedRead::DecryptedTransactions,
                    auth: &request,
                    page: &page(),
                })
                .await,
            Err(RingRpcError::InvalidIndexerResponse)
        ));
    }

    for (transactions, scanned_through) in [
        (vec![fixture.audited.clone()], Vec::new()),
        (vec![fixture.audited.clone(); 100], vec![9]),
    ] {
        let mut source = fixture.source().with_transactions(transactions);
        source.scanned_through = Some(scanned_through);
        let service = fixture.hub(source).service(None).expect("service");
        let request = auth(&signer);
        assert!(matches!(
            service
                .read(AuditRead {
                    read: PagedRead::DecryptedTransactions,
                    auth: &request,
                    page: &page(),
                })
                .await,
            Err(RingRpcError::InvalidIndexerResponse)
        ));
    }

    let mut source = fixture.source();
    source.next_cursor = None;
    let service = fixture.hub(source).service(None).expect("service");
    let request = auth(&signer);
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page(),
            })
            .await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));

    let mut source = fixture.source();
    source.next_cursor = Some(vec![8]);
    let service = fixture.hub(source).service(None).expect("service");
    let repeated_page = Page::new(Some(vec![8].into()), None).expect("page");
    let request = GetDecryptedTransactionsRequest::read(target(RING))
        .with_cursor(vec![8].into())
        .expect("cursor")
        .sign(&signer)
        .expect("request")
        .auth;
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &repeated_page
            })
            .await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));

    let mut source = fixture.source();
    source.transactions[0].nullifiers.push([2; 32]);
    source.transactions[0].output_slots = vec![source.transactions[0].output_slots[0].clone(); 17];
    let service = fixture.hub(source).service(None).expect("service");
    let request = auth(&signer);
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page(),
            })
            .await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));
}

#[test]
fn request_builder_rejects_noncanonical_pages() {
    assert!(matches!(
        GetDecryptedTransactionsRequest::read(target(RING)).with_cursor(Vec::new().into()),
        Err(ReadBuildError::Cursor)
    ));
    assert!(matches!(
        GetDecryptedTransactionsRequest::read(target(RING))
            .with_limit(Limit::new(101).expect("indexer limit")),
        Err(ReadBuildError::Limit)
    ));
    assert!(matches!(
        Page::new(Some(Vec::new().into()), None),
        Err(RingRpcError::InvalidPage)
    ));
}

fn as_object<T: serde::Serialize>(value: T) -> serde_json::Map<String, serde_json::Value> {
    let serde_json::Value::Object(map) = serde_json::to_value(value).expect("JSON object") else {
        panic!("expected JSON object");
    };
    map
}

#[tokio::test]
async fn rpc_wire_uses_camel_case_and_rejects_another_local_ring() {
    let fixture = Fixture::new();
    let module = rpc_module(Arc::new(fixture.hub(fixture.source()))).expect("module");
    let health: HealthResponse = module.call(HEALTH, [(); 0]).await.expect("health");
    assert_eq!(health.mode, KeyMode::Local);

    let request = GetDecryptedTransactionsRequest::read(target(RING))
        .sign(&delegate())
        .expect("request");
    let object = as_object(request);
    assert!(object.contains_key("ringProgramId"));
    let page: GetDecryptedTransactionsResponse = module
        .call(GET_DECRYPTED_TRANSACTIONS, object)
        .await
        .expect("read");
    assert_eq!(page.value.items.len(), 1);
    let merges: GetAuditedMergesResponse = module
        .call(
            GET_AUDITED_MERGES,
            as_object(
                PagedRead::AuditedMerges
                    .request(target(RING))
                    .sign(&delegate())
                    .expect("merge read request"),
            ),
        )
        .await
        .expect("merge read");
    assert!(merges.value.opened.is_empty());
    assert!(merges.value.unresolved.is_empty());
    let item = as_object(&page.value.items[0]);
    assert_eq!(
        item.get("withdrawals"),
        Some(&serde_json::json!([
            {
                "recipient": RECIPIENT.to_string(),
                "asset": SOL_MINT.to_string(),
                "amount": WITHDRAWN,
            },
            {
                "recipient": TOKEN_ACCOUNT.to_string(),
                "asset": MINT.to_string(),
                "amount": SPL_WITHDRAWN,
            }
        ]))
    );

    let other_ring = CreateAuditorKeyRequest::for_ring(OTHER_RING, GENESIS)
        .sign(&authority())
        .expect("signed request");
    let result: Result<CreateAuditorKeyResponse, _> =
        module.call(CREATE_AUDITOR_KEY, as_object(other_ring)).await;
    assert!(result.is_err());
}

fn signed_by(authority: &Keypair) -> CreateAuditorKeyRequest {
    CreateAuditorKeyRequest::for_ring(RING, GENESIS)
        .sign(authority)
        .expect("signed request")
}

async fn authorize(
    hub: &Hub<StaticSource>,
    request: &CreateAuditorKeyRequest,
) -> Result<(), RingRpcError> {
    hub.service(Some(RING))
        .expect("service")
        .auditor_key_statement(&request.auth)
        .await
        .map(drop)
}

/// The service signs the cluster and nonce the authority's request names.
fn released(created: &CreateAuditorKeyResponse, request: &CreateAuditorKeyRequest) -> bool {
    let nonce: [u8; 32] = request.auth.nonce.0.as_slice().try_into().expect("nonce");
    let statement = AuditorKeyStatement {
        cluster: &request.auth.genesis_hash.0,
        ring: &request.ring_program_id.0,
        auditor_pubkey: created.auditor_pubkey.as_key(),
        nonce: &nonce,
    };
    created
        .signature
        .0
        .verify(created.service_pubkey.0.as_ref(), &statement.message())
}

fn refused(result: Result<(), RingRpcError>, expected: Unauthorized) -> bool {
    matches!(result, Err(RingRpcError::Unauthorized(reason)) if reason == expected)
}

#[tokio::test]
async fn auditor_keys_are_released_to_the_ring_authorities_only() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.configs.clear();
    let hub = Arc::new(fixture.hub(source));
    let module = rpc_module(hub.clone()).expect("module");
    let request = signed_by(&deployer());
    let created: CreateAuditorKeyResponse = module
        .call(CREATE_AUDITOR_KEY, as_object(&request))
        .await
        .expect("deployer before config");
    assert_eq!(created.auditor_pubkey.as_key(), &fixture.auditor.pubkey());
    assert!(released(&created, &request));
    let replayed = signed_by(&deployer());
    assert!(!released(&created, &replayed));
    assert!(refused(
        authorize(&hub, &signed_by(&authority())).await,
        Unauthorized::NotRingAuthority
    ));

    let hub = fixture.hub(fixture.source());
    authorize(&hub, &signed_by(&authority()))
        .await
        .expect("config authority");
    for signer in [deployer(), stranger(), delegate()] {
        assert!(refused(
            authorize(&hub, &signed_by(&signer)).await,
            Unauthorized::NotRingAuthority
        ));
    }

    let mut immutable = fixture.source();
    immutable.configs.clear();
    immutable.upgrade_authorities.clear();
    let hub = fixture.hub(immutable);
    assert!(refused(
        authorize(&hub, &signed_by(&deployer())).await,
        Unauthorized::NotRingAuthority
    ));
}

#[tokio::test]
async fn an_unsigned_auditor_key_request_is_refused() {
    let fixture = Fixture::new();
    let hub = fixture.hub(fixture.source());
    let mut blank = signed_by(&authority());
    blank.auth.signature = vec![0; 64].into();
    assert!(refused(
        authorize(&hub, &blank).await,
        Unauthorized::BadSignature
    ));
}

#[tokio::test]
async fn auditor_key_requests_bind_cluster_ring_time_and_nonce() {
    let fixture = Fixture::new();
    let hub = fixture.hub(fixture.source());

    let other_cluster = CreateAuditorKeyRequest::for_ring(RING, [10; 32])
        .sign(&authority())
        .expect("signed request");
    assert!(refused(
        authorize(&hub, &other_cluster).await,
        Unauthorized::ClusterMismatch
    ));

    let mut relabelled = other_cluster;
    relabelled.auth.genesis_hash = Hash(GENESIS);
    assert!(refused(
        authorize(&hub, &relabelled).await,
        Unauthorized::BadSignature
    ));

    let other_ring = CreateAuditorKeyRequest::for_ring(OTHER_RING, GENESIS)
        .sign(&authority())
        .expect("signed request");
    assert!(refused(
        authorize(&hub, &other_ring).await,
        Unauthorized::BadSignature
    ));

    let mut forged = signed_by(&stranger());
    forged.auth.authority = authority().pubkey().to_bytes().into();
    assert!(refused(
        authorize(&hub, &forged).await,
        Unauthorized::BadSignature
    ));

    let mut shifted = signed_by(&authority());
    shifted.auth.timestamp += 1;
    assert!(refused(
        authorize(&hub, &shifted).await,
        Unauthorized::BadSignature
    ));

    let request = signed_by(&authority());
    authorize(&hub, &request).await.expect("first use");
    assert!(refused(
        authorize(&hub, &request).await,
        Unauthorized::Replay
    ));
}

#[tokio::test]
async fn auditor_key_requests_are_accepted_exactly_within_the_skew_window() {
    let fixture = Fixture::new();
    let now = 1_000_000_000;
    let hub = fixture.hub_at(fixture.source(), now);

    for timestamp in [now - AUTH_SKEW.as_secs() - 1, now + AUTH_SKEW.as_secs() + 1] {
        let outside = CreateAuditorKeyRequest::for_ring(RING, GENESIS)
            .at(timestamp)
            .sign(&authority())
            .expect("signed request");
        assert!(refused(
            authorize(&hub, &outside).await,
            Unauthorized::StaleTimestamp
        ));
    }

    for timestamp in [now - AUTH_SKEW.as_secs(), now + AUTH_SKEW.as_secs()] {
        let boundary = CreateAuditorKeyRequest::for_ring(RING, GENESIS)
            .at(timestamp)
            .sign(&authority())
            .expect("signed request");
        authorize(&hub, &boundary).await.expect("boundary request");
    }
}

#[tokio::test]
async fn invalid_audit_requests_do_not_consume_valid_capacity() {
    let fixture = Fixture::new();
    let module = rpc_module(Arc::new(fixture.hub(fixture.source()))).expect("module");

    let mut request = signed_request(&delegate(), target(RING), unix_now().expect("clock"));
    request.auth.timestamp += 1;
    let result: Result<GetDecryptedTransactionsResponse, _> = module
        .call(GET_DECRYPTED_TRANSACTIONS, as_object(request))
        .await;
    assert!(result.is_err());

    let response: GetDecryptedTransactionsResponse = module
        .call(
            GET_DECRYPTED_TRANSACTIONS,
            as_object(signed_request(
                &delegate(),
                target(RING),
                unix_now().expect("clock"),
            )),
        )
        .await
        .expect("valid request");
    assert_eq!(response.value.items.len(), 1);
}

fn deposit(byte: u8, slot: u64, amount: u64) -> DepositRecord {
    DepositRecord {
        signature: Signature::from([byte; 64]).into(),
        slot,
        depositor: [byte; 32].into(),
        asset: SOL_MINT.to_bytes().into(),
        amount,
    }
}

fn examined(byte: u8, slot: u64, deposits: Vec<DepositRecord>) -> Examined {
    Examined {
        signature: Signature::from([byte; 64]),
        slot,
        deposits,
    }
}

fn deposits_request(limit: Option<u32>, cursor: Option<Base64String>) -> RingDepositsRequest {
    RingDepositsRequest {
        ring_program_id: RING.to_bytes().into(),
        limit,
        cursor,
    }
}

/// The limit counts signatures examined, so a page can hold fewer deposits
/// than the limit and still carry a cursor over older history.
#[tokio::test]
async fn deposit_pages_walk_the_whole_ring_history() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.history = vec![
        examined(21, 30, vec![deposit(21, 30, 500)]),
        examined(22, 20, Vec::new()),
        examined(23, 10, vec![deposit(23, 10, 7)]),
    ];
    let module = rpc_module(Arc::new(fixture.hub(source))).expect("module");

    let first: RingDepositsResponse = module
        .call(RING_DEPOSITS, as_object(deposits_request(Some(2), None)))
        .await
        .expect("first page");
    let wire = as_object(&first);
    assert!(wire.contains_key("oldestSlot"));
    assert!(wire.contains_key("cursor"));
    assert_eq!(first.deposits.len(), 1);
    assert_eq!(first.deposits[0].amount, 500);
    assert_eq!(first.oldest_slot, Some(20));
    let cursor = first.cursor.clone().expect("older history");
    assert_eq!(
        cursor,
        Base64String(Signature::from([22; 64]).as_ref().to_vec())
    );

    let second: RingDepositsResponse = module
        .call(
            RING_DEPOSITS,
            as_object(deposits_request(Some(2), Some(cursor))),
        )
        .await
        .expect("second page");
    assert_eq!(second.deposits.len(), 1);
    assert_eq!(second.deposits[0].amount, 7);
    assert_eq!(second.oldest_slot, Some(10));
    assert_eq!(second.cursor, None);
    assert!(!as_object(&second).contains_key("cursor"));
}

/// A page over signatures that made no deposit reports how far back it
/// reached, which the cursor alone does not say.
#[tokio::test]
async fn a_deposit_page_without_deposits_reports_its_frontier() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.history = vec![examined(24, 40, Vec::new()), examined(25, 30, Vec::new())];
    let module = rpc_module(Arc::new(fixture.hub(source))).expect("module");

    let page: RingDepositsResponse = module
        .call(RING_DEPOSITS, as_object(deposits_request(Some(1), None)))
        .await
        .expect("page");
    assert!(page.deposits.is_empty());
    assert_eq!(page.oldest_slot, Some(40));
    assert_eq!(
        page.cursor,
        Some(Base64String(Signature::from([24; 64]).as_ref().to_vec()))
    );
}

#[tokio::test]
async fn deposit_pages_clamp_the_examined_limit_and_reject_bad_cursors() {
    let fixture = Fixture::new();

    for (limit, expected) in [(None, 50), (Some(7), 7), (Some(500), 200)] {
        let source = fixture.source();
        let examined_limit = source.examined_limit.clone();
        let module = rpc_module(Arc::new(fixture.hub(source))).expect("module");
        let page: RingDepositsResponse = module
            .call(RING_DEPOSITS, as_object(deposits_request(limit, None)))
            .await
            .expect("page");
        assert_eq!(examined_limit.load(Ordering::Relaxed), expected);
        assert!(page.deposits.is_empty());
        assert_eq!(page.cursor, None);
        assert_eq!(page.oldest_slot, None);
    }

    let module = rpc_module(Arc::new(fixture.hub(fixture.source()))).expect("module");
    let result: Result<RingDepositsResponse, _> = module
        .call(
            RING_DEPOSITS,
            as_object(deposits_request(None, Some(Base64String(vec![1, 2, 3])))),
        )
        .await;
    assert!(result.is_err());
}

/// The state a ring is in decides whether `init` may pin a key, so it travels
/// over the wire for every ring the caller names.
#[tokio::test]
async fn ring_status_reports_the_state_of_each_ring() {
    let fixture = Fixture::new();
    let served = Address::new_from_array([1; 32]);
    let foreign = Address::new_from_array([3; 32]);
    let uninitialized = Address::new_from_array([4; 32]);
    let mut source = fixture.source();
    source.configs = HashMap::from([(
        foreign,
        RingConfiguration {
            auditor_pubkey: fixture.auditor.pubkey(),
            authority: authority().pubkey(),
            mode: RingMode::Off,
        },
    )]);
    let hub = Arc::new(
        Hub::builder(source, GENESIS)
            .with_origins(origins())
            .derived(RootSecret::from_bytes([7; 32]).expect("root"))
            .expect("hub"),
    );
    let derived = hub.service(Some(served)).expect("service").auditor_pubkey();
    let chain = RingChainStatus {
        activation: Some(RingActivation {
            activated: true,
            paused: false,
        }),
        registry: Some(RegistryStatus {
            history: vec![
                Some(RegistryRoot {
                    root: Hash([1; 32]),
                    applied: 3,
                    slot: 40,
                }),
                None,
            ],
            history_cursor: 0,
            next_index: 3,
            floor: 3,
            prior_floor: 0,
            floor_slot: 40,
            queue_head: 3,
            queue_tail: 5,
        }),
    };
    let mut source = fixture.source();
    source.chain = HashMap::from([(served, chain.clone())]);
    source.configs = HashMap::from([
        (
            served,
            RingConfiguration {
                auditor_pubkey: derived,
                authority: authority().pubkey(),
                mode: RingMode::Off,
            },
        ),
        (
            foreign,
            RingConfiguration {
                auditor_pubkey: fixture.auditor.pubkey(),
                authority: authority().pubkey(),
                mode: RingMode::Off,
            },
        ),
    ]);
    let module = rpc_module(Arc::new(
        Hub::builder(source, GENESIS)
            .with_origins(origins())
            .derived(RootSecret::from_bytes([7; 32]).expect("root"))
            .expect("hub"),
    ))
    .expect("module");

    for (ring, state) in [
        (served, RingState::Served),
        (foreign, RingState::ForeignAuditor),
        (uninitialized, RingState::Uninitialized),
    ] {
        let status: RingStatusResponse = module
            .call(
                RING_STATUS,
                as_object(RingStatusRequest {
                    ring_program_id: ring.to_bytes().into(),
                }),
            )
            .await
            .expect("status");
        assert_eq!(status.state, state);
        assert_eq!(status.ring_program_id.0, ring);
        assert_eq!(status.service_pubkey.0, hub.service_pubkey());
        let expected = match ring == served {
            true => chain.clone(),
            false => RingChainStatus::default(),
        };
        assert_eq!(
            (status.activation, status.registry),
            (expected.activation, expected.registry)
        );
    }

    let object = as_object(RingStatusRequest {
        ring_program_id: served.to_bytes().into(),
    });
    assert!(object.contains_key("ringProgramId"));
    let raw: serde_json::Value = module.call(RING_STATUS, object).await.expect("status");
    assert_eq!(raw.get("state"), Some(&serde_json::json!("served")));
    assert!(raw.get("auditorPubkey").is_none());
    assert!(raw.get("auditorViewTag").is_none());
    assert!(raw.get("configAuditorPubkey").is_some());
    assert_eq!(
        raw.get("activation"),
        Some(&serde_json::json!({ "activated": true, "paused": false }))
    );
    let raw: serde_json::Value = module
        .call(
            RING_STATUS,
            as_object(RingStatusRequest {
                ring_program_id: uninitialized.to_bytes().into(),
            }),
        )
        .await
        .expect("status");
    assert!(raw.get("activation").is_none());
    assert!(raw.get("registry").is_none());
}

/// One instance, two rings: each read must use its own derived key, its own
/// view tag and its own config.
#[tokio::test]
async fn two_rings_read_only_their_own_transactions() {
    let fixture = Fixture::new();
    let hub_of = |source: StaticSource| {
        Hub::builder(source, GENESIS)
            .with_origins(origins())
            .derived(RootSecret::from_bytes([7; 32]).expect("root"))
            .expect("hub")
    };
    let probe = hub_of(fixture.source());
    let ring_a = Address::new_from_array([1; 32]);
    let ring_b = Address::new_from_array([2; 32]);
    let key_a = probe
        .service(Some(ring_a))
        .expect("ring a")
        .auditor_pubkey();
    let key_b = probe
        .service(Some(ring_b))
        .expect("ring b")
        .auditor_pubkey();
    assert_ne!(key_a, key_b);

    let audited_a = Indexed {
        transfer: &Transfer {
            ring: ring_a,
            ..ring_transfer(11)
        },
        outputs: &[paid(sol(0xb0, 500), fixture.recipient_u)],
        auditor: &key_a,
        signature: 11,
        frames: &fixture.frames,
    }
    .packed();
    let audited_b = Indexed {
        transfer: &Transfer {
            ring: ring_b,
            ..ring_transfer(12)
        },
        outputs: &[paid(sol(0xb0, 7), fixture.recipient_u)],
        auditor: &key_b,
        signature: 12,
        frames: &fixture.frames,
    }
    .packed();
    let mut source = fixture.source();
    source.origins = HashMap::from([
        ((audited_a.tx_signature, 0), true),
        ((audited_b.tx_signature, 0), true),
    ]);
    source.transactions = Vec::new();
    source.by_tag = HashMap::from([
        (auditor_view_tag(&key_a), vec![audited_a.clone()]),
        (auditor_view_tag(&key_b), vec![audited_b.clone()]),
    ]);
    source.configs = HashMap::from([
        (
            ring_a,
            RingConfiguration {
                auditor_pubkey: key_a,
                authority: authority().pubkey(),
                mode: RingMode::Off,
            },
        ),
        (
            ring_b,
            RingConfiguration {
                auditor_pubkey: key_b,
                authority: authority().pubkey(),
                mode: RingMode::Off,
            },
        ),
    ]);
    let hub = hub_of(source);
    let page = page();

    for (ring, expected, amount) in [
        (ring_a, audited_a.tx_signature, 500),
        (ring_b, audited_b.tx_signature, 7),
    ] {
        let request =
            signed_request(&delegate(), served(&hub, ring), unix_now().expect("clock")).auth;
        let response = hub
            .service(Some(ring))
            .expect("service")
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page,
            })
            .await
            .expect("read");
        let [item] = response.value.items.as_slice() else {
            panic!("expected one audited transaction for {ring}");
        };
        assert_eq!(item.tx_signature.0, expected);
        assert_eq!(amounts(item), [amount]);
    }
}

/// A ring registered with a key this instance did not derive stays closed, and
/// says so before anything is decrypted.
#[tokio::test]
async fn a_ring_registered_with_another_auditor_stays_closed() {
    let fixture = Fixture::new();
    let ring = Address::new_from_array([3; 32]);
    let uninitialized = Address::new_from_array([4; 32]);
    let mut source = fixture.source();
    source.configs = HashMap::from([(
        ring,
        RingConfiguration {
            auditor_pubkey: fixture.auditor.pubkey(),
            authority: authority().pubkey(),
            mode: RingMode::Off,
        },
    )]);
    let hub = Hub::builder(source, GENESIS)
        .with_origins(origins())
        .derived(RootSecret::from_bytes([7; 32]).expect("root"))
        .expect("hub");
    let service = hub.service(Some(ring)).expect("service");
    assert_ne!(service.auditor_pubkey(), fixture.auditor.pubkey());

    assert_eq!(
        service.configured_auditor().await.expect("status"),
        Some(fixture.auditor.pubkey())
    );
    assert_eq!(
        hub.service(Some(uninitialized))
            .expect("service")
            .configured_auditor()
            .await
            .expect("status"),
        None
    );

    let request = signed_request(&delegate(), served(&hub, ring), unix_now().expect("clock")).auth;
    let page = page();
    assert!(matches!(
        service
            .read(AuditRead {
                read: PagedRead::DecryptedTransactions,
                auth: &request,
                page: &page,
            })
            .await,
        Err(RingRpcError::Unauthorized(Unauthorized::AuditorKeyMismatch))
    ));
}

#[tokio::test]
async fn derived_keys_are_ring_and_cluster_specific() {
    let fixture = Fixture::new();
    let root_bytes = [7; 32];
    let root = RootSecret::from_bytes(root_bytes).expect("root");
    let derivation_root = RootSecret::from_bytes(root_bytes).expect("root");
    let genesis_hash = [9; 32];
    let ring_a = Address::new_from_array([1; 32]);
    let ring_b = Address::new_from_array([2; 32]);
    let mut source = fixture.source();
    source
        .upgrade_authorities
        .insert(ring_a, deployer().pubkey());
    let hub = Hub::builder(source, genesis_hash)
        .derived(root)
        .expect("hub");
    let key_a = hub.service(Some(ring_a)).expect("ring a").auditor_pubkey();
    let key_b = hub.service(Some(ring_b)).expect("ring b").auditor_pubkey();
    let other_genesis = Hub::builder(fixture.source(), [10; 32])
        .derived(RootSecret::from_bytes(root_bytes).expect("root"))
        .expect("hub");
    assert_ne!(
        other_genesis
            .service(Some(ring_a))
            .expect("ring a")
            .auditor_pubkey(),
        key_a
    );
    assert_eq!(
        hub.service_pubkey().to_string(),
        "FQ7ZZ4DEkoubT5Ca9BzzbgXDTmjKdRh6a3snGfPjpEZT"
    );
    assert_eq!(
        hex::encode(key_a.as_bytes()),
        "046ac65f6fa828249939ac012a53b665c474fadedc018f71010fb7fcf4b5585248"
    );
    assert_ne!(key_a, key_b);
    let second = Hub::builder(fixture.source(), genesis_hash)
        .derived(derivation_root)
        .expect("hub");
    assert_eq!(
        second
            .service(Some(ring_a))
            .expect("ring a")
            .auditor_pubkey(),
        key_a
    );
    assert!(matches!(hub.service(None), Err(RingRpcError::RingRequired)));

    let module = rpc_module(Arc::new(hub)).expect("module");
    let health: HealthResponse = module.call(HEALTH, [(); 0]).await.expect("health");
    assert_eq!(health.mode, KeyMode::Derived);
    let request = CreateAuditorKeyRequest::for_ring(ring_a, genesis_hash)
        .sign(&deployer())
        .expect("signed request");
    let created: CreateAuditorKeyResponse = module
        .call(CREATE_AUDITOR_KEY, as_object(&request))
        .await
        .expect("auditor key");
    assert_eq!(created.auditor_pubkey.as_key(), &key_a);
    assert!(released(&created, &request));
    let mut other_cluster = request;
    other_cluster.auth.genesis_hash = Hash([10; 32]);
    assert!(!released(&created, &other_cluster));
}

#[tokio::test]
async fn an_indexer_forgery_is_reported_without_hiding_other_verified_outputs() {
    let fixture = Fixture::new();
    let confirmed = fixture.audited.clone();
    let mut forged = confirmed.clone();
    forged.output_slots[0].output_context.leaf_index += 1;
    let mut valid = confirmed.clone();
    valid.tx_signature = Signature::from([44; 64]);
    let frame = fixture.frames.lock().unwrap()[&confirmed.tx_signature].clone();
    fixture
        .frames
        .lock()
        .unwrap()
        .insert(valid.tx_signature, frame);
    let mut source = fixture.source().with_transactions(vec![forged, valid]);
    source.confirmed_events.insert(
        (confirmed.tx_signature, confirmed.event_index.unwrap()),
        origin_fixture::event(&confirmed),
    );
    let service = fixture.hub(source).service(None).unwrap();
    let response = service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &auth(&delegate()),
            page: &page(),
        })
        .await
        .unwrap();
    assert_eq!(response.value.items.len(), 1);
    assert_eq!(response.value.skipped.len(), 1);
    assert_eq!(
        response.value.skipped[0].reason,
        zolana_ring_client::rpc::SkippedReason::InvalidAuditData
    );
}

#[tokio::test]
async fn an_outsider_row_never_reaches_the_origin_read() {
    let fixture = Fixture::new();
    let mut outsider = fixture.foreign_key.clone();
    outsider.tx_signature = Signature::from([0xee; 64]);
    outsider.ring_program_id = None;
    let rows = vec![outsider.clone(), fixture.audited.clone()];
    let mut source = fixture.source().with_transactions(rows.clone());
    source.origins.remove(&(
        outsider.tx_signature,
        outsider.event_index.expect("event index"),
    ));
    source.pages = HashMap::from([(None, paged(rows, None, Some(1)))]);
    let service = fixture.hub(source).service(None).expect("service");
    let page = read_at(&service, None).await;
    let [item] = page.value.items.as_slice() else {
        panic!("one ring transfer, {:?}", page.value.skipped);
    };
    assert_eq!(item.tx_signature.0, fixture.audited.tx_signature);
    service.backfill_utxos().await.expect("backfill");
}

#[tokio::test]
async fn a_read_signed_for_another_method_cluster_or_service_is_refused() {
    let fixture = Fixture::new();
    let service = fixture
        .hub(fixture.source())
        .service(None)
        .expect("service");
    let page = page();
    let signed = |read: PagedRead, target: ReadTarget| {
        read.request(target)
            .sign(&delegate())
            .expect("request")
            .auth
    };
    let refused = [
        signed(PagedRead::AuditedMerges, target(RING)),
        signed(
            PagedRead::DecryptedTransactions,
            ReadTarget {
                cluster: [8; 32],
                ..target(RING)
            },
        ),
        signed(
            PagedRead::DecryptedTransactions,
            ReadTarget {
                service: Address::new_from_array([3; 32]),
                ..target(RING)
            },
        ),
    ];
    for auth in &refused {
        assert!(matches!(
            service
                .read(AuditRead {
                    read: PagedRead::DecryptedTransactions,
                    auth,
                    page: &page,
                })
                .await,
            Err(RingRpcError::Unauthorized(Unauthorized::BadSignature))
        ));
    }
    let valid = signed(PagedRead::DecryptedTransactions, target(RING));
    service
        .read(AuditRead {
            read: PagedRead::DecryptedTransactions,
            auth: &valid,
            page: &page,
        })
        .await
        .expect("read");
}

#[tokio::test]
async fn a_backfill_stops_at_its_page_budget() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = HashMap::from([
        (None, paged(Vec::new(), Some(1), None)),
        (Some(vec![1]), paged(Vec::new(), Some(2), None)),
        (Some(vec![2]), paged(Vec::new(), Some(1), None)),
    ]);
    let reads = source.history_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("bounded backfill");
    assert!(reads.load(Ordering::Relaxed) < HISTORY_READ_CAP);
}

#[tokio::test]
async fn the_utxo_context_moves_only_at_the_scan_frontier() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.pages = HashMap::from([
        (None, paged(vec![fixture.audited.clone()], Some(1), None)),
        (Some(vec![1]), paged(Vec::new(), Some(1), None)),
    ]);
    let service = fixture.hub(source).service(None).expect("service");
    assert!(matches!(
        service.backfill_utxos().await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));
    let hash = Hash(fixture.audited.output_slots[0].output_context.hash);
    let found = service
        .audited_utxos(&utxos_request(vec![hash]))
        .await
        .expect("UTXO read");
    assert!(found.value.utxos[0].is_some());
    assert_eq!(found.context.slot, 0);
}

#[tokio::test]
async fn an_unconfigured_ring_backfills_nothing() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.configs.clear();
    let reads = source.history_reads.clone();
    let service = fixture.hub(source).service(None).expect("service");
    service.backfill_utxos().await.expect("unconfigured ring");
    assert_eq!(reads.load(Ordering::Relaxed), 0);
}
