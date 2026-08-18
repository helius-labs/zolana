//! The service against an in-memory transaction source: one page holding an
//! audited transfer, a transaction tagged for the auditor but encrypted to
//! another key, and a transaction matched by an output tag only.

use std::{future::Future, sync::Arc};

use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{ClientError, Context, GetShieldedTransactionsByTagsResponse};
use zolana_indexer_api::Base64String;
use zolana_interface::instruction::MessageData;
use zolana_keypair::{constants::SALT_LEN, P256Pubkey, ViewingKey};
use zolana_ring_client::{auditor_view_tag, AuditorEncryption};
use zolana_ring_rpc::{
    api::{
        CreateAuditorKeyRequest, CreateAuditorKeyResponse, GetDecryptedTransactionsRequest,
        GetDecryptedTransactionsResponse, HealthResponse, CREATE_AUDITOR_KEY,
        GET_DECRYPTED_TRANSACTIONS, HEALTH,
    },
    audit::{derive_auditor_key, AuditService, Hub, RingRpcError, TransactionSource},
    server::rpc_module,
};
use zolana_transaction::{
    serialization::confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
    AssetRegistry, Data, OutputContext, OutputSlot, ShieldedTransaction, UtxoSerialization,
    SOL_ASSET_ID, SOL_MINT,
};

const SALT: [u8; SALT_LEN] = [3u8; SALT_LEN];
const TREE: Address = Address::new_from_array([4u8; 32]);

struct StaticSource {
    transactions: Vec<ShieldedTransaction>,
    next_cursor: Option<Vec<u8>>,
}

impl TransactionSource for StaticSource {
    fn transactions_by_tag(
        &self,
        _tag: [u8; 32],
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send
    {
        let response = GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 99,
            },
            transactions: self.transactions.clone(),
            next_cursor: self.next_cursor.clone(),
        };
        async move { Ok(response) }
    }

    fn signers(
        &self,
        signature: Signature,
    ) -> impl Future<Output = Result<Vec<Address>, ClientError>> + Send {
        // One deterministic signer per transaction, derived from its signature.
        let signer = Address::new_from_array([signature.as_ref()[0]; 32]);
        async move { Ok(vec![signer]) }
    }
}

fn confidential_slot(
    tx: &ViewingKey,
    recipient: &P256Pubkey,
    amount: u64,
    slot_index: u32,
) -> OutputSlot {
    let plaintext = ConfidentialOutputPlaintext {
        asset_id: SOL_ASSET_ID,
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
    .expect("encode confidential slot");
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
    AuditorEncryption::new(&tx.secret_bytes(), auditor_pk)
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
    output_tag_only: ShieldedTransaction,
}

fn fixture() -> Fixture {
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

    // Tagged for this auditor, encrypted to someone else's key.
    let other_auditor = ViewingKey::new().pubkey();
    let tx2 = ViewingKey::new();
    let mut message = auditor_message(&tx2, &other_auditor);
    message.view_tag = auditor_view_tag(&auditor_pk);
    let foreign_key = transaction(
        2,
        &tx2,
        vec![confidential_slot(&tx2, &recipient, 9, 0)],
        vec![message],
    );

    // Returned by the indexer because an output tag collided with the auditor
    // tag; it carries no auditor message and must be dropped.
    let tx3 = ViewingKey::new();
    let mut slot = confidential_slot(&tx3, &recipient, 11, 0);
    slot.view_tag = auditor_view_tag(&auditor_pk);
    let output_tag_only = transaction(3, &tx3, vec![slot], Vec::new());

    Fixture {
        auditor,
        recipient,
        audited,
        foreign_key,
        output_tag_only,
    }
}

fn source(fixture: &Fixture, next_cursor: Option<Vec<u8>>) -> StaticSource {
    StaticSource {
        transactions: vec![
            fixture.audited.clone(),
            fixture.foreign_key.clone(),
            fixture.output_tag_only.clone(),
        ],
        next_cursor,
    }
}

fn hub(fixture: &Fixture, next_cursor: Option<Vec<u8>>) -> Hub<StaticSource> {
    Hub::local(
        fixture.auditor.clone(),
        source(fixture, next_cursor),
        AssetRegistry::default(),
    )
}

fn service(fixture: &Fixture, next_cursor: Option<Vec<u8>>) -> Arc<AuditService<StaticSource>> {
    hub(fixture, next_cursor).ring(None).expect("local service")
}

#[tokio::test]
async fn page_opens_audited_transfers_and_reports_the_rest() {
    let fixture = fixture();
    let service = service(&fixture, Some(vec![7, 7]));

    let response = service
        .decrypted_transactions(None, None)
        .await
        .expect("page");

    assert_eq!(response.context.slot, 99);
    assert_eq!(response.value.cursor, Some(Base64String(vec![7, 7])));

    let [item] = response.value.items.as_slice() else {
        panic!("one audited transaction, got {:?}", response.value.items);
    };
    assert_eq!(item.slot, 42);
    assert_eq!(item.tx_signature.0, fixture.audited.tx_signature);
    assert_eq!(item.outputs.len(), 2);
    assert_eq!(item.outputs[0].amount, 500);
    assert_eq!(item.outputs[1].amount, 7);
    assert_eq!(item.outputs[0].asset.0.to_bytes(), SOL_MINT.to_bytes());
    assert_eq!(item.outputs[1].blinding, Base64String(vec![1u8; 32]));
    assert_eq!(
        item.outputs[0].recipient_viewing_pk,
        Base64String(fixture.recipient.as_bytes().to_vec()),
        "the recipient viewing key is the auditor's to"
    );
    assert_eq!(
        item.signers
            .iter()
            .map(|s| s.0.to_bytes())
            .collect::<Vec<_>>(),
        vec![[1u8; 32]],
        "the transaction signers are the auditor's from"
    );
    assert!(item.undecryptable_slots.is_empty());
    assert_eq!(item.nullifiers.len(), 1);

    let [skipped] = response.value.skipped.as_slice() else {
        panic!("one skipped transaction, got {:?}", response.value.skipped);
    };
    assert_eq!(skipped.tx_signature.0, fixture.foreign_key.tx_signature);
    assert!(
        skipped.reason.contains("does not match"),
        "reason names the key mismatch: {}",
        skipped.reason
    );
}

#[tokio::test]
async fn rpc_methods_answer_over_the_module() {
    let fixture = fixture();
    let module = rpc_module(Arc::new(hub(&fixture, None))).expect("module");

    let health: HealthResponse = module.call(HEALTH, [(); 0]).await.expect("health");
    assert_eq!(health.mode, "local");
    assert_eq!(
        health.auditor_view_tag.expect("local tag").0,
        auditor_view_tag(&fixture.auditor.pubkey())
    );

    let serde_json::Value::Object(request) =
        serde_json::to_value(GetDecryptedTransactionsRequest::default()).expect("request json")
    else {
        panic!("request serializes as an object");
    };
    let page: GetDecryptedTransactionsResponse = module
        .call(GET_DECRYPTED_TRANSACTIONS, request)
        .await
        .expect("decrypted transactions");
    assert_eq!(page.value.items.len(), 1);
    assert_eq!(page.value.skipped.len(), 1);
}

#[tokio::test]
async fn derived_keys_are_per_ring_and_stable() {
    let fixture = fixture();
    let root = zeroize::Zeroizing::new([7u8; 32]);
    let hub = Hub::derived(
        root.clone(),
        source(&fixture, None),
        AssetRegistry::default(),
    );
    let ring_a = Address::new_from_array([1u8; 32]);
    let ring_b = Address::new_from_array([2u8; 32]);
    let key_a = hub.ring(Some(ring_a)).expect("ring a").auditor_pubkey();
    let key_b = hub.ring(Some(ring_b)).expect("ring b").auditor_pubkey();
    assert_ne!(key_a, key_b, "rings get distinct keys");
    assert_eq!(
        derive_auditor_key(&root, ring_a).expect("derive").pubkey(),
        key_a,
        "the same root and ring derive the same key"
    );
    assert!(
        matches!(hub.ring(None), Err(RingRpcError::RingRequired)),
        "derived mode names a ring"
    );

    let module = rpc_module(Arc::new(hub)).expect("module");
    let health: HealthResponse = module.call(HEALTH, [(); 0]).await.expect("health");
    assert_eq!(
        (health.mode.as_str(), health.auditor_view_tag),
        ("derived", None)
    );
    let serde_json::Value::Object(request) = serde_json::to_value(CreateAuditorKeyRequest {
        ring_program_id: ring_a.to_bytes().into(),
    })
    .expect("request json") else {
        panic!("request serializes as an object");
    };
    let created: CreateAuditorKeyResponse = module
        .call(CREATE_AUDITOR_KEY, request)
        .await
        .expect("create auditor key");
    assert_eq!(created.auditor_pubkey.0, key_a.as_bytes().to_vec());
    assert_eq!(created.key_version, 1);
}
