//! In-memory audit round trips.
//!
//! Every transaction here is assembled from the real sender-side encryption path
//! (`Confidential::encode_plaintext` plus the sdk's auditor message codec) into a
//! synthetic [`ShieldedTransaction`], the same struct the indexer returns. No
//! validator, no prover: what is under test is that the auditor recovers the
//! transaction viewing key and returns the exact amounts, assets and blindings
//! the sender encrypted.

use std::{
    collections::HashMap,
    num::{NonZeroU32, NonZeroUsize},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

use borsh::BorshDeserialize;
use custom_ring_interface::RingMode;
use solana_address::Address;
use solana_signature::Signature;
use zeroize::Zeroizing;
use zolana_client::{
    AsyncRpc, Context, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig, ProofInputUtxo,
    ShieldedTransaction,
};
use zolana_hasher::{
    primitives::{hash_bytes, SOLANA_OWNER_TAG},
    Hasher, Poseidon,
};
use zolana_interface::{
    event::{ring_confidential_encrypted_output_body, OutputDataEncoding},
    instruction::MessageData,
};
use zolana_keypair::{constants::SALT_LEN, ViewingKey, X25519Pubkey, X25519Secret};
use zolana_ring_client::{
    auditor_view_tag, AnonymousDisclosure, AnonymousOutputOpening, AuditError, AuditInputOpening,
    AuditedOutput, AuditedTransaction, AuditorEncryption, RingOrigin, RingScan, TransactionAudit,
    TransactionOrigin, AUDITOR_MESSAGE_LEN,
};
use zolana_transaction::{
    serialization::confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
    AssetRegistry, Data, EncryptedScheme, OutputContext, OutputSlot, SppProofOutputUtxo,
    UtxoSerialization, SOL_ASSET_ID, SOL_MINT,
};

const SALT: [u8; SALT_LEN] = [3u8; SALT_LEN];
const TOKEN_ASSET_ID: u64 = 7;
const TOKEN_MINT: Address = Address::new_from_array([9u8; 32]);
const TREE_ID: u16 = 4;

fn registry() -> AssetRegistry {
    AssetRegistry::new([(TOKEN_ASSET_ID, TOKEN_MINT)]).expect("asset registry")
}

fn plaintext(asset_id: u64, amount: u64, blinding: u8) -> ConfidentialOutputPlaintext {
    ConfidentialOutputPlaintext {
        asset_id,
        amount,
        blinding: field(blinding),
        ring_program_id: None,
        data: Data::default(),
    }
}

fn field(value: u8) -> [u8; 32] {
    let mut field = [0u8; 32];
    field[31] = value;
    field
}

fn asset_for_fixture(asset_id: u64) -> Address {
    match asset_id {
        SOL_ASSET_ID => SOL_MINT,
        TOKEN_ASSET_ID => TOKEN_MINT,
        other => Address::new_from_array([other as u8; 32]),
    }
}

fn proof_output(plaintext: &ConfidentialOutputPlaintext, slot_index: u32) -> ProofInputUtxo {
    ProofInputUtxo::new(
        field(slot_index as u8 | 0x40),
        &asset_for_fixture(plaintext.asset_id),
        plaintext.amount,
        &plaintext.blinding,
        TREE_ID,
    )
    .expect("proof output")
    .with_ring([0; 32], &plaintext.ring_program_id)
    .expect("ring output")
}

fn padding_output(slot_index: u32) -> ProofInputUtxo {
    ProofInputUtxo::try_from((
        &SppProofOutputUtxo {
            blinding: field(slot_index as u8 | 0x20),
            ..Default::default()
        },
        TREE_ID,
    ))
    .expect("dummy output")
}

fn output_context(output: &ProofInputUtxo, slot_index: u32) -> OutputContext {
    OutputContext {
        hash: output.hash().expect("output commitment"),
        tree_id: TREE_ID,
        leaf_index: u64::from(slot_index),
    }
}

/// A real confidential slot: the sender-side encoder, keyed to `recipient`,
/// bound to `slot_index`.
fn confidential_slot(
    tx: &ViewingKey,
    recipient: &X25519Pubkey,
    plaintext: &ConfidentialOutputPlaintext,
    slot_index: u32,
) -> OutputSlot {
    let mut encoded = Confidential::encode_plaintext(
        plaintext,
        [slot_index as u8 | 0x80; 32],
        &ConfidentialEncode {
            tx: tx.clone(),
            recipient_pubkey: *recipient,
            salt: SALT,
            slot_index,
        },
    )
    .expect("encode confidential slot");
    if plaintext.ring_program_id.is_some() {
        let OutputDataEncoding::Encrypted(mut blob) =
            OutputDataEncoding::try_from_slice(&encoded.data).expect("encrypted output")
        else {
            panic!("encrypted output")
        };
        blob[0] = EncryptedScheme::RingConfidential.as_byte();
        encoded.data = borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).expect("ring output");
    }
    OutputSlot {
        view_tag: encoded.view_tag,
        output_context: output_context(&proof_output(plaintext, slot_index), slot_index),
        payload: encoded.data,
    }
}

/// A dummy slot as the transfer builder publishes them: length-matched random
/// bytes. Borsh only accepts 0, 1 or 2 as the [`OutputDataEncoding`] tag, so a
/// random first byte almost never parses; 0xff pins that case deterministically.
fn dummy_slot(slot_index: u32) -> OutputSlot {
    OutputSlot {
        view_tag: [0xaa; 32],
        output_context: output_context(&padding_output(slot_index), slot_index),
        payload: vec![0xff; 160],
    }
}

/// A slot published under another encryption scheme, which the auditor must skip
/// instead of failing on.
fn foreign_scheme_slot(slot_index: u32) -> OutputSlot {
    let mut blob = vec![EncryptedScheme::AnonymousRecipient.as_byte()];
    blob.extend_from_slice(&[5u8; 96]);
    OutputSlot {
        view_tag: [0xbb; 32],
        output_context: output_context(&padding_output(slot_index), slot_index),
        payload: borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).expect("borsh output data"),
    }
}

fn transaction(
    tx: &ViewingKey,
    output_slots: Vec<OutputSlot>,
    messages: Vec<MessageData>,
) -> ShieldedTransaction {
    ShieldedTransaction {
        slot: 42,
        tx_signature: Signature::from([6u8; 64]),
        event_index: Some(0),
        tx_viewing_pk: Some(tx.pubkey()),
        salt: Some(SALT),
        output_slots,
        messages,
        nullifiers: vec![[1u8; 32]],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(Address::new_from_array([9u8; 32])),
    }
}

/// The sender side of the audit feature: encrypt the transaction viewing secret
/// key to the auditor and publish it as the last message.
fn auditor_message_data(
    tx: &ViewingKey,
    auditor_pk: &X25519Pubkey,
    output_slots: &[OutputSlot],
) -> MessageData {
    let openings = output_slots
        .iter()
        .enumerate()
        .map(|(index, slot)| {
            let slot_index = u32::try_from(index).expect("slot index");
            let plaintext = slot.output_data().and_then(|output| match output {
                OutputDataEncoding::Encrypted(blob) => blob.get(1..).and_then(|body| {
                    Confidential::decrypt_with_tx_key(tx, body, SALT, slot_index).ok()
                }),
                OutputDataEncoding::Plaintext(_) | OutputDataEncoding::VerifiablyEncrypted(_) => {
                    None
                }
            });
            plaintext.as_ref().map_or_else(
                || padding_output(slot_index),
                |value| proof_output(value, slot_index),
            )
        })
        .collect::<Vec<_>>();
    let encryption = if openings.is_empty() {
        AuditorEncryption::new(tx, auditor_pk)
    } else {
        AuditorEncryption::new_with_outputs(tx, auditor_pk, SALT, &openings)
    }
    .expect("auditor encryption");
    let message = encryption.message.to_message_data(auditor_pk);
    assert_eq!(message.data.len(), AUDITOR_MESSAGE_LEN);
    message
}

fn free_form_message() -> MessageData {
    MessageData {
        view_tag: [0x11; 32],
        data: vec![1, 2, 3],
    }
}

#[test]
fn audit_returns_the_amounts_assets_and_blindings_that_were_encrypted() {
    let auditor = X25519Secret::new();
    let tx_key = ViewingKey::new();
    let recipient_one = ViewingKey::new();
    let recipient_two = ViewingKey::new();

    let sol_output = plaintext(SOL_ASSET_ID, 1_234_567, 0x21);
    let token_output = plaintext(TOKEN_ASSET_ID, 99, 0x22);
    let slots = vec![
        confidential_slot(&tx_key, &recipient_one.pubkey(), &sol_output, 0),
        confidential_slot(&tx_key, &recipient_two.pubkey(), &token_output, 1),
    ];
    let tx = transaction(
        &tx_key,
        slots.clone(),
        // Free-form messages are allowed before the auditor message.
        vec![
            free_form_message(),
            auditor_message_data(&tx_key, &auditor.pubkey(), &slots),
        ],
    );

    let audited = TransactionAudit {
        auditor: &auditor,
        transaction: &tx,
        assets: &registry(),
    }
    .run()
    .expect("audit");

    assert_eq!(
        audited,
        AuditedTransaction {
            tx_signature: Signature::from([6u8; 64]),
            slot: 42,
            tx_viewing_pk: tx_key.pubkey(),
            outputs: vec![
                AuditedOutput {
                    slot_index: 0,
                    recipient_viewing_pk: recipient_one.pubkey(),
                    owner_tag: [0x80; 32],
                    asset: SOL_MINT,
                    amount: 1_234_567,
                    blinding: Zeroizing::new(field(0x21)),
                    ring_program_id: None,
                    data: Data::default(),
                },
                AuditedOutput {
                    slot_index: 1,
                    recipient_viewing_pk: recipient_two.pubkey(),
                    owner_tag: [0x81; 32],
                    asset: TOKEN_MINT,
                    amount: 99,
                    blinding: Zeroizing::new(field(0x22)),
                    ring_program_id: None,
                    data: Data::default(),
                },
            ],
            output_openings: vec![proof_output(&sol_output, 0), proof_output(&token_output, 1),],
            anonymous: None,
            undecryptable_slots: vec![],
        }
    );
}

#[test]
fn anonymous_audit_recovers_the_hidden_recipient_and_checks_the_commitment() {
    let auditor = X25519Secret::new();
    let tx_key = ViewingKey::new();
    let recipient = ViewingKey::new();
    let ring = Address::new_from_array([9u8; 32]);
    let owner_key = [4u8; 32];
    let nullifier_pk = field(7);
    let mut tagged_key = [SOLANA_OWNER_TAG; 33];
    tagged_key[1..].copy_from_slice(&owner_key);
    let identity = hash_bytes(&tagged_key).expect("owner identity");
    let owner_hash = Poseidon::hashv(&[&identity, &nullifier_pk]).expect("owner hash");
    let plaintext = ConfidentialOutputPlaintext {
        ring_program_id: Some(ring),
        ..plaintext(SOL_ASSET_ID, 42, 8)
    };
    let opening = ProofInputUtxo::new(
        owner_hash,
        &SOL_MINT,
        plaintext.amount,
        &plaintext.blinding,
        TREE_ID,
    )
    .expect("output opening")
    .with_ring([0; 32], &Some(ring))
    .expect("ring opening");
    let message = Confidential::encode_ring_anonymous_plaintext(
        &plaintext,
        &ConfidentialEncode {
            tx: tx_key.clone(),
            recipient_pubkey: recipient.pubkey(),
            salt: SALT,
            slot_index: 0,
        },
    )
    .expect("anonymous output");
    let slot = OutputSlot {
        view_tag: [0; 32],
        output_context: output_context(&opening, 0),
        payload: message.data,
    };
    let disclosure = AnonymousDisclosure {
        sender: [3; 32],
        inputs: vec![AuditInputOpening::default()],
        outputs: vec![AnonymousOutputOpening {
            identity_tag: SOLANA_OWNER_TAG,
            identity_key: owner_key,
            viewing_pk: *recipient.pubkey().as_bytes(),
            nullifier_pk,
            amount: plaintext.amount,
            asset: opening.asset,
            blinding: plaintext.blinding,
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
            ring_note: 1,
        }],
    };
    let sealed =
        AuditorEncryption::new_with_anonymous(&tx_key, &auditor.pubkey(), SALT, &disclosure)
            .expect("auditor capsule");
    let mut tx = transaction(
        &tx_key,
        vec![slot],
        vec![sealed.message.to_message_data(&auditor.pubkey())],
    );
    let audit = |tx: &ShieldedTransaction| {
        TransactionAudit {
            auditor: &auditor,
            transaction: tx,
            assets: &registry(),
        }
        .run_with_mode(RingMode::Anonymous)
    };
    let audited = audit(&tx).expect("anonymous audit");
    assert_eq!(audited.output_openings, vec![opening]);
    assert_eq!(audited.outputs.len(), 1);
    assert_eq!(audited.outputs[0].recipient_viewing_pk, recipient.pubkey());
    assert_eq!(audited.outputs[0].owner_tag, owner_key);
    assert_eq!(audited.outputs[0].amount, 42);
    assert_eq!(audited.undecryptable_slots, Vec::<u32>::new());
    assert_eq!(audited.anonymous, Some(disclosure));

    // The regular layout never parses an anonymous disclosure.
    assert!(matches!(
        TransactionAudit {
            auditor: &auditor,
            transaction: &tx,
            assets: &registry(),
        }
        .run(),
        Err(AuditError::MessageLength(_))
    ));
    tx.output_slots[0].output_context.hash[0] ^= 1;
    assert!(matches!(
        audit(&tx),
        Err(AuditError::OutputCommitmentMismatch(0))
    ));
}

#[test]
fn ring_owned_output_keeps_its_ring_program_id() {
    let auditor = X25519Secret::new();
    let tx_key = ViewingKey::new();
    let recipient = ViewingKey::new();
    let ring_program_id = Address::new_from_array([0x5a; 32]);

    let mut output = plaintext(SOL_ASSET_ID, 500, 0x31);
    output.ring_program_id = Some(ring_program_id);
    let slots = vec![confidential_slot(&tx_key, &recipient.pubkey(), &output, 0)];
    let tx = transaction(
        &tx_key,
        slots.clone(),
        vec![auditor_message_data(&tx_key, &auditor.pubkey(), &slots)],
    );
    assert!(ring_confidential_encrypted_output_body(&tx.output_slots[0].payload).is_some());

    let audited = TransactionAudit {
        auditor: &auditor,
        transaction: &tx,
        assets: &registry(),
    }
    .run()
    .expect("audit");
    assert_eq!(
        audited.outputs,
        vec![AuditedOutput {
            slot_index: 0,
            recipient_viewing_pk: recipient.pubkey(),
            owner_tag: [0x80; 32],
            asset: SOL_MINT,
            amount: 500,
            blinding: Zeroizing::new(field(0x31)),
            ring_program_id: Some(ring_program_id),
            data: Data::default(),
        }]
    );
}

/// Dummy and foreign slots are reported, and - because the dummy sits between two
/// real slots - this also pins the slot index rule: the index is the position in
/// `output_slots` counted over ALL slots, exactly as the encoder counts it.
#[test]
fn dummy_and_foreign_slots_are_reported_not_fatal() {
    let auditor = X25519Secret::new();
    let tx_key = ViewingKey::new();
    let recipient_one = ViewingKey::new();
    let recipient_two = ViewingKey::new();

    let first = plaintext(SOL_ASSET_ID, 10, 0x41);
    let second = plaintext(TOKEN_ASSET_ID, 20, 0x42);
    let slots = vec![
        confidential_slot(&tx_key, &recipient_one.pubkey(), &first, 0),
        dummy_slot(1),
        confidential_slot(&tx_key, &recipient_two.pubkey(), &second, 2),
        foreign_scheme_slot(3),
    ];
    let tx = transaction(
        &tx_key,
        slots.clone(),
        vec![auditor_message_data(&tx_key, &auditor.pubkey(), &slots)],
    );

    let audited = TransactionAudit {
        auditor: &auditor,
        transaction: &tx,
        assets: &registry(),
    }
    .run()
    .expect("audit");
    assert_eq!(
        (audited.outputs, audited.undecryptable_slots),
        (
            vec![
                AuditedOutput {
                    slot_index: 0,
                    recipient_viewing_pk: recipient_one.pubkey(),
                    owner_tag: [0x80; 32],
                    asset: SOL_MINT,
                    amount: 10,
                    blinding: Zeroizing::new(field(0x41)),
                    ring_program_id: None,
                    data: Data::default(),
                },
                AuditedOutput {
                    slot_index: 2,
                    recipient_viewing_pk: recipient_two.pubkey(),
                    owner_tag: [0x82; 32],
                    asset: TOKEN_MINT,
                    amount: 20,
                    blinding: Zeroizing::new(field(0x42)),
                    ring_program_id: None,
                    data: Data::default(),
                },
            ],
            vec![1, 3]
        )
    );
}

/// A confidential slot encrypted at the wrong index does not decrypt, which is
/// why the counting rule above is load bearing.
#[test]
fn slot_encrypted_at_another_index_does_not_decrypt() {
    let auditor = X25519Secret::new();
    let tx_key = ViewingKey::new();
    let recipient = ViewingKey::new();

    let output = plaintext(SOL_ASSET_ID, 7, 0x51);
    let mut slot = confidential_slot(&tx_key, &recipient.pubkey(), &output, 1);
    let opening = proof_output(&output, 0);
    slot.output_context = output_context(&opening, 0);
    let slots = vec![slot];
    let message = AuditorEncryption::new_with_outputs(&tx_key, &auditor.pubkey(), SALT, &[opening])
        .expect("auditor encryption")
        .message
        .to_message_data(&auditor.pubkey());
    let tx = transaction(&tx_key, slots.clone(), vec![message]);

    let audited = TransactionAudit {
        auditor: &auditor,
        transaction: &tx,
        assets: &registry(),
    }
    .run()
    .expect("audit");
    assert_eq!(
        (audited.outputs, audited.undecryptable_slots),
        (vec![], vec![0])
    );
}

#[test]
fn another_auditor_key_finds_no_message() {
    let auditor = X25519Secret::new();
    let stranger = X25519Secret::new();
    let tx_key = ViewingKey::new();
    let recipient = ViewingKey::new();

    let output = plaintext(SOL_ASSET_ID, 1, 0x61);
    let slots = vec![confidential_slot(&tx_key, &recipient.pubkey(), &output, 0)];
    let tx = transaction(
        &tx_key,
        slots.clone(),
        vec![auditor_message_data(&tx_key, &auditor.pubkey(), &slots)],
    );

    assert!(matches!(
        TransactionAudit {
            auditor: &stranger,
            transaction: &tx,
            assets: &registry()
        }
        .run(),
        Err(AuditError::MissingAuditorMessage)
    ));
}

/// A message tagged for this auditor but encrypted to a different key: the
/// recovered scalar is a valid key, so only the pubkey integrity check catches
/// it.
#[test]
fn message_encrypted_to_another_key_fails_the_integrity_check() {
    let auditor = X25519Secret::new();
    let other_auditor = X25519Secret::new();
    let tx_key = ViewingKey::new();

    let encryption =
        AuditorEncryption::new(&tx_key, &other_auditor.pubkey()).expect("auditor encryption");
    // Tagged for `auditor`, decryptable only by `other_auditor`. The wrong key
    // yields bytes that fail the clamping check or name another viewing key.
    let mislabeled = encryption.message.to_message_data(&auditor.pubkey());
    let tx = transaction(&tx_key, vec![], vec![mislabeled]);

    assert!(matches!(
        TransactionAudit {
            auditor: &auditor,
            transaction: &tx,
            assets: &registry()
        }
        .run(),
        Err(AuditError::TxViewingKeyMismatch | AuditError::NonCanonicalViewingKey)
    ));
}

#[test]
fn tampered_ciphertext_fails_the_integrity_check() {
    let auditor = X25519Secret::new();
    let tx_key = ViewingKey::new();

    let mut message = auditor_message_data(&tx_key, &auditor.pubkey(), &[]);
    message.data[33] ^= 0x01;
    let tx = transaction(&tx_key, vec![], vec![message]);

    assert!(matches!(
        TransactionAudit {
            auditor: &auditor,
            transaction: &tx,
            assets: &registry()
        }
        .run(),
        Err(AuditError::TxViewingKeyMismatch | AuditError::NonCanonicalViewingKey)
    ));
}

#[test]
fn transaction_without_auditor_message_is_rejected() {
    let auditor = X25519Secret::new();
    let tx_key = ViewingKey::new();
    let recipient = ViewingKey::new();

    let output = plaintext(SOL_ASSET_ID, 3, 0x81);
    let tx = transaction(
        &tx_key,
        vec![confidential_slot(&tx_key, &recipient.pubkey(), &output, 0)],
        vec![free_form_message()],
    );

    assert!(matches!(
        TransactionAudit {
            auditor: &auditor,
            transaction: &tx,
            assets: &registry()
        }
        .run(),
        Err(AuditError::MissingAuditorMessage)
    ));
}

#[test]
fn auditor_message_must_be_the_last_message() {
    let auditor = X25519Secret::new();
    let tx_key = ViewingKey::new();

    let tx = transaction(
        &tx_key,
        vec![],
        vec![
            auditor_message_data(&tx_key, &auditor.pubkey(), &[]),
            free_form_message(),
        ],
    );

    assert!(matches!(
        TransactionAudit {
            auditor: &auditor,
            transaction: &tx,
            assets: &registry()
        }
        .run(),
        Err(AuditError::AuditorMessageNotLast { index: 0, count: 2 })
    ));
}

#[test]
fn two_auditor_messages_are_rejected() {
    let auditor = X25519Secret::new();
    let tx_key = ViewingKey::new();

    let tx = transaction(
        &tx_key,
        vec![],
        vec![
            auditor_message_data(&tx_key, &auditor.pubkey(), &[]),
            auditor_message_data(&tx_key, &auditor.pubkey(), &[]),
        ],
    );

    assert!(matches!(
        TransactionAudit {
            auditor: &auditor,
            transaction: &tx,
            assets: &registry()
        }
        .run(),
        Err(AuditError::DuplicateAuditorMessage)
    ));
}

#[test]
fn missing_transaction_key_material_is_rejected() {
    let auditor = X25519Secret::new();
    let tx_key = ViewingKey::new();

    let mut no_pubkey = transaction(
        &tx_key,
        vec![],
        vec![auditor_message_data(&tx_key, &auditor.pubkey(), &[])],
    );
    no_pubkey.tx_viewing_pk = None;
    let mut no_salt = transaction(
        &tx_key,
        vec![],
        vec![auditor_message_data(&tx_key, &auditor.pubkey(), &[])],
    );
    no_salt.salt = None;

    let assets = registry();
    assert!(matches!(
        TransactionAudit {
            auditor: &auditor,
            transaction: &no_pubkey,
            assets: &assets
        }
        .run(),
        Err(AuditError::MissingTxViewingPk)
    ));
    assert!(matches!(
        TransactionAudit {
            auditor: &auditor,
            transaction: &no_salt,
            assets: &assets
        }
        .run(),
        Err(AuditError::MissingSalt)
    ));
}

/// A decrypted output whose asset the registry cannot resolve is a registry gap,
/// not an undecryptable slot: dropping it would understate audited amounts.
#[test]
fn unknown_asset_id_is_an_error() {
    let auditor = X25519Secret::new();
    let tx_key = ViewingKey::new();
    let recipient = ViewingKey::new();

    let output = plaintext(TOKEN_ASSET_ID + 1, 4, 0x91);
    let slots = vec![confidential_slot(&tx_key, &recipient.pubkey(), &output, 0)];
    let tx = transaction(
        &tx_key,
        slots.clone(),
        vec![auditor_message_data(&tx_key, &auditor.pubkey(), &slots)],
    );

    assert!(matches!(
        TransactionAudit { auditor: &auditor, transaction: &tx, assets: &registry() }.run(),
        Err(AuditError::UnknownAsset { asset_id, .. }) if asset_id == TOKEN_ASSET_ID + 1
    ));
}

/// Cursor paging plus the message-tag filter. Photon's tag filter is an OR over
/// output tags and message tags, so a transaction can arrive because an output
/// tag matched; the scan drops those.
struct PagedIndexer {
    expected_tag: [u8; 32],
    pages: Vec<Vec<ShieldedTransaction>>,
    /// Page size asked for on each round trip, in call order.
    requested: Mutex<Vec<Option<u32>>>,
}

#[async_trait::async_trait]
impl AsyncRpc for PagedIndexer {
    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, zolana_client::ClientError> {
        assert_eq!(tags, vec![self.expected_tag]);
        self.requested.lock().unwrap().push(limit);
        let page_index = usize::from(*cursor.unwrap_or_default().first().unwrap_or(&0));
        let transactions = self.pages.get(page_index).cloned().unwrap_or_default();
        let next_cursor = (page_index + 1 < self.pages.len())
            .then(|| vec![u8::try_from(page_index + 1).expect("page index")]);
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 1,
            },
            transactions,
            next_cursor,
            scanned_through: None,
            output_tree_id: None,
        })
    }
}

struct KnownOrigins {
    ring: Address,
    origins: HashMap<Signature, bool>,
    lookups: AtomicUsize,
}

impl TransactionOrigin for KnownOrigins {
    async fn origin(
        &self,
        signature: Signature,
        _event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        assert_eq!(ring, self.ring);
        self.lookups.fetch_add(1, Ordering::Relaxed);
        self.origins
            .get(&signature)
            .copied()
            .map(|ring_invoked| RingOrigin {
                ring_invoked,
                signers: Vec::new(),
                withdrawals: Vec::new(),
            })
            .ok_or_else(|| AuditError::Unavailable {
                signature,
                message: "not found".to_owned(),
            })
    }
}

fn with_signature(mut tx: ShieldedTransaction, byte: u8) -> ShieldedTransaction {
    tx.tx_signature = Signature::from([byte; 64]);
    tx
}

#[tokio::test]
async fn scan_walks_every_page_and_keeps_only_ring_transactions_tagged_for_the_auditor() {
    let ring = Address::new_from_array([9u8; 32]);
    let auditor = X25519Secret::new();
    let auditor_pk = auditor.pubkey();
    let tx_key_one = ViewingKey::new();
    let tx_key_two = ViewingKey::new();
    let recipient = ViewingKey::new();

    let first_output = plaintext(SOL_ASSET_ID, 111, 0xa1);
    let second_output = plaintext(TOKEN_ASSET_ID, 222, 0xa2);
    let first_slots = vec![confidential_slot(
        &tx_key_one,
        &recipient.pubkey(),
        &first_output,
        0,
    )];
    let first = with_signature(
        transaction(
            &tx_key_one,
            first_slots.clone(),
            vec![auditor_message_data(&tx_key_one, &auditor_pk, &first_slots)],
        ),
        1,
    );
    let second_slots = vec![confidential_slot(
        &tx_key_two,
        &recipient.pubkey(),
        &second_output,
        0,
    )];
    let second = with_signature(
        transaction(
            &tx_key_two,
            second_slots.clone(),
            vec![auditor_message_data(
                &tx_key_two,
                &auditor_pk,
                &second_slots,
            )],
        ),
        2,
    );
    // Matched on an output view tag, carries no auditor message, and is never
    // looked up on chain.
    let mut output_tag_match = with_signature(
        transaction(&tx_key_one, vec![], vec![free_form_message()]),
        3,
    );
    output_tag_match.output_slots.push(OutputSlot {
        view_tag: auditor_view_tag(&auditor_pk),
        output_context: output_context(&padding_output(0), 0),
        payload: vec![0xff; 8],
    });
    let foreign_ring = with_signature(first.clone(), 4);
    let foreign_ring_again = foreign_ring.clone();

    let indexer = PagedIndexer {
        expected_tag: auditor_view_tag(&auditor_pk),
        pages: vec![
            vec![
                first.clone(),
                output_tag_match,
                foreign_ring.clone(),
                foreign_ring_again,
            ],
            vec![second.clone()],
        ],
        requested: Mutex::new(Vec::new()),
    };
    let origin = KnownOrigins {
        ring,
        origins: HashMap::from([
            (first.tx_signature, true),
            (second.tx_signature, true),
            (foreign_ring.tx_signature, false),
        ]),
        lookups: AtomicUsize::new(0),
    };
    assert_eq!(
        RingScan::new(ring, auditor_pk)
            .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
            .run(&indexer, &origin)
            .await
            .expect("scan")
            .transactions,
        vec![first, second]
    );
    assert_eq!(
        origin.lookups.load(Ordering::Relaxed),
        3,
        "one lookup per signature"
    );

    let audited = RingScan::new(ring, auditor_pk)
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .audit(&auditor, &indexer, &origin, &registry())
        .await
        .expect("audit all")
        .transactions;
    assert_eq!(audited.len(), 2);
    assert_eq!(audited[0].tx_viewing_pk, tx_key_one.pubkey());
    assert_eq!(
        &audited[0].outputs,
        &[AuditedOutput {
            slot_index: 0,
            recipient_viewing_pk: recipient.pubkey(),
            owner_tag: [0x80; 32],
            asset: SOL_MINT,
            amount: 111,
            blinding: Zeroizing::new(field(0xa1)),
            ring_program_id: None,
            data: Data::default(),
        }]
    );
    assert_eq!(audited[1].tx_viewing_pk, tx_key_two.pubkey());
    assert_eq!(
        &audited[1].outputs,
        &[AuditedOutput {
            slot_index: 0,
            recipient_viewing_pk: recipient.pubkey(),
            owner_tag: [0x80; 32],
            asset: TOKEN_MINT,
            amount: 222,
            blinding: Zeroizing::new(field(0xa2)),
            ring_program_id: None,
            data: Data::default(),
        }]
    );
}

#[tokio::test]
async fn scan_fails_when_an_origin_is_unavailable() {
    let ring = Address::new_from_array([9u8; 32]);
    let auditor = X25519Secret::new();
    let auditor_pk = auditor.pubkey();
    let tx = transaction(
        &ViewingKey::new(),
        Vec::new(),
        vec![auditor_message_data(&ViewingKey::new(), &auditor_pk, &[])],
    );
    let indexer = PagedIndexer {
        expected_tag: auditor_view_tag(&auditor_pk),
        pages: vec![vec![tx]],
        requested: Mutex::new(Vec::new()),
    };
    let origin = KnownOrigins {
        ring,
        origins: HashMap::new(),
        lookups: AtomicUsize::new(0),
    };

    assert!(matches!(
        RingScan::new(ring, auditor_pk)
            .with_max_pages(NonZeroUsize::new(1).expect("page limit"))
            .run(&indexer, &origin)
            .await,
        Err(AuditError::Unavailable { .. })
    ));
}

/// One auditor-tagged transaction per page, so the paging rules are what the
/// scan is measured on.
fn paged_history(auditor_pk: &X25519Pubkey, pages: u8) -> Vec<Vec<ShieldedTransaction>> {
    (0..pages)
        .map(|index| {
            let tx_key = ViewingKey::new();
            vec![with_signature(
                transaction(
                    &tx_key,
                    Vec::new(),
                    vec![auditor_message_data(&tx_key, auditor_pk, &[])],
                ),
                index + 1,
            )]
        })
        .collect()
}

fn indexer(auditor_pk: &X25519Pubkey, pages: Vec<Vec<ShieldedTransaction>>) -> PagedIndexer {
    PagedIndexer {
        expected_tag: auditor_view_tag(auditor_pk),
        pages,
        requested: Mutex::new(Vec::new()),
    }
}

fn ring_origins(ring: Address, pages: &[Vec<ShieldedTransaction>]) -> KnownOrigins {
    KnownOrigins {
        ring,
        origins: pages
            .iter()
            .flatten()
            .map(|tx| (tx.tx_signature, true))
            .collect(),
        lookups: AtomicUsize::new(0),
    }
}

fn signatures(transactions: &[ShieldedTransaction]) -> Vec<Signature> {
    transactions.iter().map(|tx| tx.tx_signature).collect()
}

#[tokio::test]
async fn the_page_size_is_asked_for_on_every_round_trip() {
    let ring = Address::new_from_array([9u8; 32]);
    let auditor_pk = X25519Secret::new().pubkey();
    let pages = paged_history(&auditor_pk, 3);
    let origin = ring_origins(ring, &pages);
    let indexer = indexer(&auditor_pk, pages.clone());

    let page = RingScan::new(ring, auditor_pk)
        .with_page_size(NonZeroU32::new(1).expect("page size"))
        .with_max_pages(NonZeroUsize::new(3).expect("page limit"))
        .run(&indexer, &origin)
        .await
        .expect("scan");

    assert_eq!(*indexer.requested.lock().unwrap(), vec![Some(1); 3]);
    assert_eq!(
        signatures(&page.transactions),
        signatures(&pages.concat().to_vec())
    );
}

/// A scan cut short by `max_pages` hands back the cursor of the page it did
/// not read, and resuming there repeats nothing and skips nothing.
#[tokio::test]
async fn a_scan_stopped_by_max_pages_resumes_where_it_stopped() {
    let ring = Address::new_from_array([9u8; 32]);
    let auditor_pk = X25519Secret::new().pubkey();
    let pages = paged_history(&auditor_pk, 3);
    let origin = ring_origins(ring, &pages);
    let indexer = indexer(&auditor_pk, pages.clone());

    let stopped = RingScan::new(ring, auditor_pk)
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .run(&indexer, &origin)
        .await
        .expect("first scan");
    let cursor = stopped.next_cursor.clone().expect("unread history");
    assert_eq!(
        signatures(&stopped.transactions),
        signatures(&pages[..2].concat())
    );

    let resumed = RingScan::new(ring, auditor_pk)
        .with_cursor(cursor)
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .run(&indexer, &origin)
        .await
        .expect("resumed scan");
    assert_eq!(resumed.next_cursor, None);
    assert_eq!(signatures(&resumed.transactions), signatures(&pages[2]));
}

#[tokio::test]
async fn an_empty_page_does_not_end_the_scan() {
    let ring = Address::new_from_array([9u8; 32]);
    let auditor_pk = X25519Secret::new().pubkey();
    let last = paged_history(&auditor_pk, 1);
    let pages = vec![Vec::new(), last[0].clone()];
    let origin = ring_origins(ring, &pages);
    let indexer = indexer(&auditor_pk, pages.clone());

    let page = RingScan::new(ring, auditor_pk)
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .run(&indexer, &origin)
        .await
        .expect("scan");

    assert_eq!(page.next_cursor, None);
    assert_eq!(signatures(&page.transactions), signatures(&pages[1]));
}

#[tokio::test]
async fn a_cursor_at_the_end_of_history_returns_an_empty_page() {
    let ring = Address::new_from_array([9u8; 32]);
    let auditor_pk = X25519Secret::new().pubkey();
    let pages = paged_history(&auditor_pk, 2);
    let origin = ring_origins(ring, &pages);
    let indexer = indexer(&auditor_pk, pages);

    let page = RingScan::new(ring, auditor_pk)
        .with_cursor(vec![2])
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .run(&indexer, &origin)
        .await
        .expect("scan");

    assert!(page.transactions.is_empty());
    assert_eq!(page.next_cursor, None);
    assert_eq!(origin.lookups.load(Ordering::Relaxed), 0);
}
