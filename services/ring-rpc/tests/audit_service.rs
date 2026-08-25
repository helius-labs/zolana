use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use p256::ecdsa::signature::hazmat::PrehashSigner;
use sha2::Digest;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ClientError, Context, GetShieldedTransactionsByTagsResponse};
use zolana_indexer_api::{Base64String, Limit};
use zolana_interface::instruction::MessageData;
use zolana_keypair::{constants::SALT_LEN, P256Pubkey, ViewingKey};
use zolana_ring_client::{
    auditor_view_tag, AuditorEncryption, OriginError, ReaderKey, RingOrigin, RingWithdrawal,
};
use zolana_ring_rpc::{
    auditor_key_attestation, rpc_module, unix_now, AuditRead, Claim, CreateAuditorKeyRequest,
    CreateAuditorKeyResponse, DecryptedWithdrawal, DepositHistory, DepositPage, DepositRecord,
    GetDecryptedTransactionsRequest, GetDecryptedTransactionsResponse, HealthResponse, Hub,
    KeyMode, OriginPolicy, Origins, Page, PageOptions, ReadAttestation, ReadAuth, ReadBuildError,
    ReadCheck, ReadSignature, ReadSigner, ReaderGrant, RingConfiguration, RingDepositsRequest,
    RingDepositsResponse, RingRpcError, RingState, RingStatusRequest, RingStatusResponse,
    RootSecret, SkippedReason, TransactionPage, TransactionSource, Unauthorized, WebAuthnAssertion,
    CREATE_AUDITOR_KEY, GET_DECRYPTED_TRANSACTIONS, HEALTH, RING_DEPOSITS, RING_STATUS,
};
use zolana_transaction::{
    serialization::confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
    AssetRegistry, Data, OutputContext, OutputSlot, ShieldedTransaction, UtxoSerialization,
    SOL_ASSET_ID, SOL_MINT,
};

const SALT: [u8; SALT_LEN] = [3; SALT_LEN];
const TREE: Address = Address::new_from_array([4; 32]);
const RING: Address = Address::new_from_array([5; 32]);
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

    fn pubkey(&self) -> P256Pubkey {
        let sec1 = self.key.verifying_key().to_encoded_point(true);
        P256Pubkey::from_bytes(sec1.as_bytes().try_into().expect("compressed key")).expect("key")
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

fn signed_request<S: ReadSigner + ?Sized>(
    signer: &S,
    ring: Address,
    timestamp: u64,
) -> GetDecryptedTransactionsRequest {
    GetDecryptedTransactionsRequest::read(ring)
        .at(timestamp)
        .sign(signer)
        .expect("signed request")
}

fn auth<S: ReadSigner + ?Sized>(signer: &S) -> ReadAuth {
    signed_request(signer, RING, unix_now().expect("clock")).auth
}

fn decide_now(auth: &ReadAuth, origins: &Origins) -> Result<Claim, Unauthorized> {
    let nonce: &[u8; 32] = auth
        .nonce
        .0
        .as_slice()
        .try_into()
        .map_err(|_| Unauthorized::InvalidNonce)?;
    ReadCheck::new(
        auth,
        &ReadAttestation {
            ring: RING,
            timestamp: auth.timestamp,
            nonce,
            cursor: None,
            limit: None,
        },
    )
    .at(unix_now().expect("clock"))
    .against(origins)
    .decide()
}

#[test]
fn signatures_bind_the_reader_and_request() {
    let wallet = delegate();
    assert_eq!(
        decide_now(&auth(&wallet), &origins())
            .expect("wallet claim")
            .reader_key(),
        ReaderKey::ed25519(wallet.pubkey()).expect("reader")
    );
    let passkey = Passkey::new(46);
    assert_eq!(
        decide_now(&auth(&passkey), &origins())
            .expect("passkey claim")
            .reader_key(),
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
            &signed_request(&wallet, OTHER_RING, unix_now().expect("clock")).auth,
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

#[derive(Clone)]
struct StaticSource {
    transactions: Vec<ShieldedTransaction>,
    origins: HashMap<Signature, bool>,
    next_cursor: Option<Vec<u8>>,
    /// Per ring, so a read can never be authorized against another ring's
    /// config.
    configs: HashMap<Address, RingConfiguration>,
    /// Per auditor view tag, empty when every read shares `transactions`.
    by_tag: HashMap<[u8; 32], Vec<ShieldedTransaction>>,
    granted: HashSet<ReaderKey>,
    healthy: bool,
    assets: Option<AssetRegistry>,
    asset_reads: Arc<AtomicUsize>,
    asset_delay: Option<Duration>,
    /// Ring history, newest first.
    history: Vec<Examined>,
    examined_limit: Arc<AtomicUsize>,
}

/// One ring signature and the deposits it made.
#[derive(Clone)]
struct Examined {
    signature: Signature,
    slot: u64,
    deposits: Vec<DepositRecord>,
}

impl StaticSource {
    fn with_transactions(mut self, transactions: Vec<ShieldedTransaction>) -> Self {
        self.origins = transactions
            .iter()
            .map(|transaction| (transaction.tx_signature, true))
            .collect();
        self.transactions = transactions;
        self
    }
}

impl TransactionSource for StaticSource {
    fn transactions_by_tag(
        &self,
        request: TransactionPage<'_>,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send
    {
        assert!(request.page.limit().get() <= 100);
        let transactions = self
            .by_tag
            .get(&request.tag)
            .cloned()
            .unwrap_or_else(|| self.transactions.clone());
        let response = GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 99,
            },
            transactions,
            next_cursor: self.next_cursor.clone(),
        };
        async move { Ok(response) }
    }

    fn transaction_origin(
        &self,
        signature: Signature,
        _ring: Address,
    ) -> impl Future<Output = Result<RingOrigin, OriginError>> + Send {
        let origin = self
            .origins
            .get(&signature)
            .copied()
            .map(|ring_invoked| RingOrigin {
                ring_invoked,
                signers: vec![SENDER],
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
            .ok_or_else(|| OriginError::Unavailable {
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

    fn reader_granted(
        &self,
        request: ReaderGrant,
    ) -> impl Future<Output = Result<bool, ClientError>> + Send {
        let granted = self.granted.contains(&request.reader);
        async move { Ok(granted) }
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
        Ok([9; 32])
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

fn confidential_slot(
    tx: &ViewingKey,
    recipient: &P256Pubkey,
    amount: u64,
    slot_index: u32,
) -> OutputSlot {
    confidential_asset_slot(tx, recipient, SOL_ASSET_ID, amount, slot_index)
}

fn confidential_asset_slot(
    tx: &ViewingKey,
    recipient: &P256Pubkey,
    asset_id: u64,
    amount: u64,
    slot_index: u32,
) -> OutputSlot {
    let plaintext = ConfidentialOutputPlaintext {
        asset_id,
        amount,
        blinding: [slot_index as u8; 32],
        ring_program_id: None,
        data: Data::default(),
    };
    let encoded = Confidential::encode_plaintext(
        &plaintext,
        [slot_index as u8 | 0x80; 32],
        &ConfidentialEncode {
            tx: tx.clone(),
            recipient_pubkey: *recipient,
            salt: SALT,
            slot_index,
        },
    )
    .expect("confidential slot");
    OutputSlot {
        view_tag: encoded.view_tag,
        output_context: OutputContext {
            hash: [slot_index as u8; 32],
            tree: TREE,
            leaf_index: u64::from(slot_index),
        },
        payload: encoded.data,
    }
}

fn auditor_message(tx: &ViewingKey, auditor_pk: &P256Pubkey) -> MessageData {
    AuditorEncryption::new(tx, auditor_pk)
        .expect("auditor encryption")
        .message
        .to_message_data(auditor_pk)
}

fn transaction(
    signature_byte: u8,
    tx: &ViewingKey,
    output_slots: Vec<OutputSlot>,
    messages: Vec<MessageData>,
) -> ShieldedTransaction {
    ShieldedTransaction {
        slot: 42,
        tx_signature: Signature::from([signature_byte; 64]),
        tx_viewing_pk: Some(tx.pubkey()),
        salt: Some(SALT),
        output_slots,
        messages,
        nullifiers: vec![[signature_byte; 32]],
        proofless: false,
    }
}

struct Fixture {
    auditor: ViewingKey,
    recipient: P256Pubkey,
    audited: ShieldedTransaction,
    foreign_key: ShieldedTransaction,
    missing_message: ShieldedTransaction,
}

impl Fixture {
    fn new() -> Self {
        let auditor = ViewingKey::new();
        let auditor_pk = auditor.pubkey();
        let recipient = ViewingKey::new().pubkey();
        let tx = ViewingKey::new();
        let audited = transaction(
            1,
            &tx,
            vec![
                confidential_slot(&tx, &recipient, 500, 0),
                confidential_slot(&tx, &recipient, 7, 1),
            ],
            vec![auditor_message(&tx, &auditor_pk)],
        );
        let tx = ViewingKey::new();
        let mut message = auditor_message(&tx, &ViewingKey::new().pubkey());
        message.view_tag = auditor_view_tag(&auditor_pk);
        let foreign_key = transaction(
            2,
            &tx,
            vec![confidential_slot(&tx, &recipient, 9, 0)],
            vec![message],
        );
        let tx = ViewingKey::new();
        let mut slot = confidential_slot(&tx, &recipient, 11, 0);
        slot.view_tag = auditor_view_tag(&auditor_pk);
        let missing_message = transaction(3, &tx, vec![slot], Vec::new());
        Self {
            auditor,
            recipient,
            audited,
            foreign_key,
            missing_message,
        }
    }

    fn source(&self) -> StaticSource {
        let source = StaticSource {
            transactions: Vec::new(),
            origins: HashMap::new(),
            next_cursor: Some(vec![7, 7]),
            configs: HashMap::from([(
                RING,
                RingConfiguration {
                    auditor_pubkey: self.auditor.pubkey(),
                },
            )]),
            by_tag: HashMap::new(),
            granted: HashSet::from([
                ReaderKey::ed25519(delegate().pubkey()).expect("delegate reader"),
                ReaderKey::p256(Passkey::new(46).pubkey()).expect("passkey reader"),
            ]),
            healthy: true,
            assets: Some(AssetRegistry::default()),
            asset_reads: Arc::new(AtomicUsize::new(0)),
            asset_delay: None,
            history: Vec::new(),
            examined_limit: Arc::new(AtomicUsize::new(0)),
        };
        source.with_transactions(vec![
            self.audited.clone(),
            self.foreign_key.clone(),
            self.missing_message.clone(),
        ])
    }

    fn hub(&self, source: StaticSource) -> Hub<StaticSource> {
        Hub::builder(source)
            .with_origins(origins())
            .local(RING, self.auditor.clone())
            .expect("hub")
    }
}

fn page() -> Page {
    PageOptions::default().build().expect("page")
}

#[tokio::test]
async fn granted_reader_opens_audited_transfers_and_reports_the_rest() {
    let fixture = Fixture::new();
    let service = fixture.hub(fixture.source()).service().expect("service");
    let page = page();
    let request = auth(&delegate());
    let response = service
        .read(AuditRead {
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
    assert_eq!(item.outputs.len(), 2);
    assert_eq!(item.outputs[0].amount, 500);
    assert_eq!(item.outputs[1].amount, 7);
    assert_eq!(item.outputs[0].asset.0.to_bytes(), SOL_MINT.to_bytes());
    // The slot's own tag, not anything recovered from the ciphertext.
    assert_eq!(item.outputs[0].owner_tag.0, [0x80; 32]);
    assert_eq!(item.outputs[1].owner_tag.0, [0x81; 32]);
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
    assert_eq!(
        item.outputs[0].recipient_viewing_pk,
        Base64String(fixture.recipient.as_bytes().to_vec())
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
async fn unknown_assets_share_refresh_and_back_off_after_failure() {
    const ASSET_ID: u64 = 2;
    let fixture = Fixture::new();
    let tx = ViewingKey::new();
    let mut source = fixture.source().with_transactions(vec![transaction(
        8,
        &tx,
        vec![confidential_asset_slot(
            &tx,
            &fixture.recipient,
            ASSET_ID,
            13,
            0,
        )],
        vec![auditor_message(&tx, &fixture.auditor.pubkey())],
    )]);
    source.assets = Some(
        AssetRegistry::new([(ASSET_ID, Address::new_from_array([8; 32]))]).expect("asset registry"),
    );
    let unknown_transactions = source.transactions.clone();
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service().expect("service");
    let page = page();
    let ed25519 = auth(&delegate());
    let p256 = auth(&Passkey::new(46));
    let (first, second) = tokio::join!(
        service.read(AuditRead {
            auth: &ed25519,
            page: &page,
        }),
        service.read(AuditRead {
            auth: &p256,
            page: &page,
        })
    );
    let asset = Address::new_from_array([8; 32]);
    for result in [first, second] {
        let response = result.expect("refreshed read");
        assert_eq!(response.value.items[0].outputs[0].asset.0, asset);
    }
    assert_eq!(reads.load(Ordering::Relaxed), 1);

    let mut source = fixture
        .source()
        .with_transactions(unknown_transactions.clone());
    source.assets = None;
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service().expect("service");
    let first = auth(&delegate());
    assert!(service
        .read(AuditRead {
            auth: &first,
            page: &page,
        })
        .await
        .is_err());
    let second = auth(&Passkey::new(46));
    assert!(service
        .read(AuditRead {
            auth: &second,
            page: &page,
        })
        .await
        .is_err());
    assert_eq!(reads.load(Ordering::Relaxed), 1);

    let mut source = fixture.source().with_transactions(unknown_transactions);
    source.asset_delay = Some(Duration::from_secs(1));
    let reads = source.asset_reads.clone();
    let service = fixture.hub(source).service().expect("service");
    let first = auth(&delegate());
    assert!(tokio::time::timeout(
        Duration::from_millis(1),
        service.read(AuditRead {
            auth: &first,
            page: &page,
        })
    )
    .await
    .is_err());
    let second = auth(&Passkey::new(46));
    assert!(service
        .read(AuditRead {
            auth: &second,
            page: &page,
        })
        .await
        .is_err());
    assert_eq!(reads.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn only_granted_readers_with_the_configured_auditor_key_can_read() {
    let fixture = Fixture::new();
    let page = page();
    let service = fixture.hub(fixture.source()).service().expect("service");
    for signer in [&delegate() as &dyn ReadSigner, &Passkey::new(46)] {
        let request = auth(signer);
        assert!(service
            .read(AuditRead {
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
            auditor_pubkey: ViewingKey::new().pubkey(),
        },
    );
    let service = fixture.hub(source).service().expect("service");
    let request = auth(&delegate());
    assert!(matches!(
        service
            .read(AuditRead {
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
    source.origins.insert(fixture.audited.tx_signature, false);
    let service = fixture.hub(source).service().expect("service");
    let page = page();
    let request = auth(&delegate());
    let response = service
        .read(AuditRead {
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
async fn unknown_origins_fail_the_page() {
    let fixture = Fixture::new();
    let mut source = fixture.source();
    source.origins.remove(&fixture.audited.tx_signature);
    let service = fixture.hub(source).service().expect("service");
    let page = page();
    let request = auth(&delegate());
    assert!(matches!(
        service
            .read(AuditRead {
                auth: &request,
                page: &page,
            })
            .await,
        Err(RingRpcError::Origin(OriginError::Unavailable { .. }))
    ));
}

#[tokio::test]
async fn accepted_nonces_are_single_use() {
    let fixture = Fixture::new();
    let service = fixture.hub(fixture.source()).service().expect("service");
    let page = page();
    let request = auth(&delegate());
    assert!(service
        .read(AuditRead {
            auth: &request,
            page: &page,
        })
        .await
        .is_ok());
    assert!(matches!(
        service
            .read(AuditRead {
                auth: &request,
                page: &page,
            })
            .await,
        Err(RingRpcError::Unauthorized(Unauthorized::Replay))
    ));
    let distinct = auth(&delegate());
    assert!(service
        .read(AuditRead {
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
    let service = fixture.hub(source).service().expect("service");
    let request = auth(&signer);
    assert!(matches!(
        service
            .read(AuditRead {
                auth: &request,
                page: &page(),
            })
            .await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));

    for cursor in [Vec::new(), vec![1; 257]] {
        let mut source = fixture.source();
        source.next_cursor = Some(cursor);
        let service = fixture.hub(source).service().expect("service");
        let request = auth(&signer);
        assert!(matches!(
            service
                .read(AuditRead {
                    auth: &request,
                    page: &page(),
                })
                .await,
            Err(RingRpcError::InvalidIndexerResponse)
        ));
    }

    let mut source = fixture.source();
    source.next_cursor = Some(vec![8]);
    let service = fixture.hub(source).service().expect("service");
    let repeated_page = PageOptions::default()
        .with_cursor(vec![8].into())
        .expect("cursor")
        .build()
        .expect("page");
    let request = GetDecryptedTransactionsRequest::read(RING)
        .with_cursor(vec![8].into())
        .expect("cursor")
        .sign(&signer)
        .expect("request")
        .auth;
    assert!(matches!(
        service
            .read(AuditRead {
                auth: &request,
                page: &repeated_page
            })
            .await,
        Err(RingRpcError::InvalidIndexerResponse)
    ));

    let mut source = fixture.source();
    source.transactions[0].nullifiers.push([2; 32]);
    source.transactions[0].output_slots = vec![source.transactions[0].output_slots[0].clone(); 8];
    let service = fixture.hub(source).service().expect("service");
    let request = auth(&signer);
    assert!(matches!(
        service
            .read(AuditRead {
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
        GetDecryptedTransactionsRequest::read(RING).with_cursor(Vec::new().into()),
        Err(ReadBuildError::Cursor)
    ));
    assert!(matches!(
        GetDecryptedTransactionsRequest::read(RING)
            .with_limit(Limit::new(101).expect("indexer limit")),
        Err(ReadBuildError::Limit)
    ));
    assert!(matches!(
        PageOptions::default().with_cursor(Vec::new().into()),
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

    let request = GetDecryptedTransactionsRequest::read(RING)
        .sign(&delegate())
        .expect("request");
    let object = as_object(request);
    assert!(object.contains_key("ringProgramId"));
    let page: GetDecryptedTransactionsResponse = module
        .call(GET_DECRYPTED_TRANSACTIONS, object)
        .await
        .expect("read");
    assert_eq!(page.value.items.len(), 1);
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

    let result: Result<CreateAuditorKeyResponse, _> = module
        .call(
            CREATE_AUDITOR_KEY,
            as_object(CreateAuditorKeyRequest {
                ring_program_id: OTHER_RING.to_bytes().into(),
            }),
        )
        .await;
    assert!(result.is_err());
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
    let source = fixture.source();
    let examined_limit = source.examined_limit.clone();
    let module = rpc_module(Arc::new(fixture.hub(source))).expect("module");

    for (limit, expected) in [(None, 50), (Some(7), 7), (Some(500), 200)] {
        let page: RingDepositsResponse = module
            .call(RING_DEPOSITS, as_object(deposits_request(limit, None)))
            .await
            .expect("page");
        assert_eq!(examined_limit.load(Ordering::Relaxed), expected);
        assert!(page.deposits.is_empty());
        assert_eq!(page.cursor, None);
        assert_eq!(page.oldest_slot, None);
    }

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
        },
    )]);
    let hub = Arc::new(
        Hub::builder(source)
            .with_origins(origins())
            .derived(RootSecret::from_bytes([7; 32]).expect("root"), [9; 32])
            .expect("hub"),
    );
    let derived = hub.service_for(served).expect("service").auditor_pubkey();
    let mut source = fixture.source();
    source.configs = HashMap::from([
        (
            served,
            RingConfiguration {
                auditor_pubkey: derived,
            },
        ),
        (
            foreign,
            RingConfiguration {
                auditor_pubkey: fixture.auditor.pubkey(),
            },
        ),
    ]);
    let module = rpc_module(Arc::new(
        Hub::builder(source)
            .with_origins(origins())
            .derived(RootSecret::from_bytes([7; 32]).expect("root"), [9; 32])
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
    }

    let object = as_object(RingStatusRequest {
        ring_program_id: served.to_bytes().into(),
    });
    assert!(object.contains_key("ringProgramId"));
    let raw: serde_json::Value = module.call(RING_STATUS, object).await.expect("status");
    assert_eq!(raw.get("state"), Some(&serde_json::json!("served")));
    assert!(raw.get("auditorViewTag").is_some());
    assert!(raw.get("configAuditorPubkey").is_some());
}

/// One instance, two rings: each read must use its own derived key, its own
/// view tag and its own config.
#[tokio::test]
async fn two_rings_read_only_their_own_transactions() {
    let fixture = Fixture::new();
    let hub_of = |source: StaticSource| {
        Hub::builder(source)
            .with_origins(origins())
            .derived(RootSecret::from_bytes([7; 32]).expect("root"), [9; 32])
            .expect("hub")
    };
    let probe = hub_of(fixture.source());
    let ring_a = Address::new_from_array([1; 32]);
    let ring_b = Address::new_from_array([2; 32]);
    let key_a = probe.service_for(ring_a).expect("ring a").auditor_pubkey();
    let key_b = probe.service_for(ring_b).expect("ring b").auditor_pubkey();
    assert_ne!(key_a, key_b);

    let tx_a = ViewingKey::new();
    let audited_a = transaction(
        11,
        &tx_a,
        vec![confidential_slot(&tx_a, &fixture.recipient, 500, 0)],
        vec![auditor_message(&tx_a, &key_a)],
    );
    let tx_b = ViewingKey::new();
    let audited_b = transaction(
        12,
        &tx_b,
        vec![confidential_slot(&tx_b, &fixture.recipient, 7, 0)],
        vec![auditor_message(&tx_b, &key_b)],
    );
    let mut source = fixture.source();
    source.origins = HashMap::from([
        (audited_a.tx_signature, true),
        (audited_b.tx_signature, true),
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
            },
        ),
        (
            ring_b,
            RingConfiguration {
                auditor_pubkey: key_b,
            },
        ),
    ]);
    let hub = hub_of(source);
    let page = page();

    for (ring, expected, amount) in [
        (ring_a, audited_a.tx_signature, 500),
        (ring_b, audited_b.tx_signature, 7),
    ] {
        let request = signed_request(&delegate(), ring, unix_now().expect("clock")).auth;
        let response = hub
            .service_for(ring)
            .expect("service")
            .read(AuditRead {
                auth: &request,
                page: &page,
            })
            .await
            .expect("read");
        let [item] = response.value.items.as_slice() else {
            panic!("expected one audited transaction for {ring}");
        };
        assert_eq!(item.tx_signature.0, expected);
        assert_eq!(item.outputs[0].amount, amount);
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
        },
    )]);
    let hub = Hub::builder(source)
        .with_origins(origins())
        .derived(RootSecret::from_bytes([7; 32]).expect("root"), [9; 32])
        .expect("hub");
    let service = hub.service_for(ring).expect("service");
    assert_ne!(service.auditor_pubkey(), fixture.auditor.pubkey());

    assert_eq!(
        service.configured_auditor().await.expect("status"),
        Some(fixture.auditor.pubkey())
    );
    assert_eq!(
        hub.service_for(uninitialized)
            .expect("service")
            .configured_auditor()
            .await
            .expect("status"),
        None
    );

    let request = signed_request(&delegate(), ring, unix_now().expect("clock")).auth;
    let page = page();
    assert!(matches!(
        service
            .read(AuditRead {
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
    let hub = Hub::builder(fixture.source())
        .derived(root, genesis_hash)
        .expect("hub");
    let ring_a = Address::new_from_array([1; 32]);
    let ring_b = Address::new_from_array([2; 32]);
    let key_a = hub.service_for(ring_a).expect("ring a").auditor_pubkey();
    let key_b = hub.service_for(ring_b).expect("ring b").auditor_pubkey();
    let other_genesis = Hub::builder(fixture.source())
        .derived(RootSecret::from_bytes(root_bytes).expect("root"), [10; 32])
        .expect("hub");
    assert_ne!(
        other_genesis
            .service_for(ring_a)
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
        "029b177a781c3adfce4d089128bdbd53d006ae9d5166b257d7e394cd1ee31f06b5"
    );
    assert_ne!(key_a, key_b);
    let second = Hub::builder(fixture.source())
        .derived(derivation_root, genesis_hash)
        .expect("hub");
    assert_eq!(
        second.service_for(ring_a).expect("ring a").auditor_pubkey(),
        key_a
    );
    assert!(matches!(hub.service(), Err(RingRpcError::RingRequired)));

    let module = rpc_module(Arc::new(hub)).expect("module");
    let health: HealthResponse = module.call(HEALTH, [(); 0]).await.expect("health");
    assert_eq!(health.mode, KeyMode::Derived);
    let created: CreateAuditorKeyResponse = module
        .call(
            CREATE_AUDITOR_KEY,
            as_object(CreateAuditorKeyRequest {
                ring_program_id: ring_a.to_bytes().into(),
            }),
        )
        .await
        .expect("auditor key");
    assert_eq!(created.auditor_pubkey.as_key(), &key_a);
    assert!(created.signature.0.verify(
        created.service_pubkey.0.as_ref(),
        &auditor_key_attestation(&ring_a, created.auditor_pubkey.as_key())
    ));
}
