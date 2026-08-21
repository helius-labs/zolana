//! In-memory audit round trips.
//!
//! Every transaction here is assembled from the real sender-side encryption path
//! (`Confidential::encode_plaintext` plus the sdk's auditor message codec) into a
//! synthetic [`ShieldedTransaction`], the same struct the indexer returns. No
//! validator, no prover: what is under test is that the auditor recovers the
//! transaction viewing key and returns the exact amounts, assets and blindings
//! the sender encrypted.

use std::num::{NonZeroU32, NonZeroUsize};

use borsh::BorshDeserialize;
use solana_address::Address;
use solana_signature::Signature;
use zeroize::Zeroizing;
use zolana_client::{
    Context, GetShieldedTransactionsByTagsResponse, RingShieldedTransactionsByTagRequest, Rpc,
    ShieldedTransaction,
};
use zolana_interface::{
    event::{ring_confidential_encrypted_output_body, OutputDataEncoding},
    instruction::MessageData,
    pda,
};
use zolana_keypair::{constants::SALT_LEN, P256Pubkey, ViewingKey};
use zolana_ring_client::{
    auditor_view_tag, AuditError, AuditedOutput, AuditedTransaction, AuditorEncryption, RingAudit,
    RingScan, TransactionAudit, AUDITOR_MESSAGE_LEN,
};
use zolana_transaction::{
    serialization::confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
    AssetRegistry, Data, EncryptedScheme, OutputContext, OutputSlot, RingAssociation,
    UtxoSerialization, SOL_ASSET_ID, SOL_MINT,
};

const SALT: [u8; SALT_LEN] = [3u8; SALT_LEN];
const TOKEN_ASSET_ID: u64 = 7;
const TOKEN_MINT: Address = Address::new_from_array([9u8; 32]);
const TREE: Address = Address::new_from_array([4u8; 32]);

fn registry() -> AssetRegistry {
    AssetRegistry::new([(TOKEN_ASSET_ID, TOKEN_MINT)]).expect("asset registry")
}

fn plaintext(asset_id: u64, amount: u64, blinding: u8) -> ConfidentialOutputPlaintext {
    ConfidentialOutputPlaintext {
        asset_id,
        amount,
        blinding: [blinding; 32],
        ring_program_id: None,
        data: Data::default(),
    }
}

fn output_context(slot_index: u32) -> OutputContext {
    OutputContext {
        hash: [slot_index as u8; 32],
        tree: TREE,
        leaf_index: u64::from(slot_index),
    }
}

/// A real confidential slot: the sender-side encoder, keyed to `recipient`,
/// bound to `slot_index`.
fn confidential_slot(
    tx: &ViewingKey,
    recipient: &P256Pubkey,
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
        output_context: output_context(slot_index),
        payload: encoded.data,
    }
}

/// A dummy slot as the transfer builder publishes them: length-matched random
/// bytes. Borsh only accepts 0, 1 or 2 as the [`OutputDataEncoding`] tag, so a
/// random first byte almost never parses; 0xff pins that case deterministically.
fn dummy_slot(slot_index: u32) -> OutputSlot {
    OutputSlot {
        view_tag: [0xaa; 32],
        output_context: output_context(slot_index),
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
        output_context: output_context(slot_index),
        payload: borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).expect("borsh output data"),
    }
}

fn transaction(
    tx: &ViewingKey,
    output_slots: Vec<OutputSlot>,
    messages: Vec<MessageData>,
) -> ShieldedTransaction {
    let program_id = Address::new_from_array([9u8; 32]);
    ShieldedTransaction {
        slot: 42,
        tx_signature: Signature::from([6u8; 64]),
        ring: RingAssociation::Resolved {
            config: pda::ring_auth(&program_id).0,
            program_id,
        },
        tx_viewing_pk: Some(tx.pubkey()),
        salt: Some(SALT),
        output_slots,
        messages,
        nullifiers: vec![[1u8; 32]],
        proofless: false,
    }
}

/// The sender side of the audit feature: encrypt the transaction viewing secret
/// key to the auditor and publish it as the last message.
fn auditor_message_data(tx: &ViewingKey, auditor_pk: &P256Pubkey) -> MessageData {
    let encryption = AuditorEncryption::new(tx, auditor_pk).expect("auditor encryption");
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
    let auditor = ViewingKey::new();
    let tx_key = ViewingKey::new();
    let recipient_one = ViewingKey::new();
    let recipient_two = ViewingKey::new();

    let sol_output = plaintext(SOL_ASSET_ID, 1_234_567, 0x21);
    let token_output = plaintext(TOKEN_ASSET_ID, 99, 0x22);
    let tx = transaction(
        &tx_key,
        vec![
            confidential_slot(&tx_key, &recipient_one.pubkey(), &sol_output, 0),
            confidential_slot(&tx_key, &recipient_two.pubkey(), &token_output, 1),
        ],
        // Free-form messages are allowed before the auditor message.
        vec![
            free_form_message(),
            auditor_message_data(&tx_key, &auditor.pubkey()),
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
                    asset: SOL_MINT,
                    amount: 1_234_567,
                    blinding: Zeroizing::new([0x21; 32]),
                    ring_program_id: None,
                },
                AuditedOutput {
                    slot_index: 1,
                    recipient_viewing_pk: recipient_two.pubkey(),
                    asset: TOKEN_MINT,
                    amount: 99,
                    blinding: Zeroizing::new([0x22; 32]),
                    ring_program_id: None,
                },
            ],
            undecryptable_slots: vec![],
        }
    );
}

#[test]
fn ring_owned_output_keeps_its_ring_program_id() {
    let auditor = ViewingKey::new();
    let tx_key = ViewingKey::new();
    let recipient = ViewingKey::new();
    let ring_program_id = Address::new_from_array([0x5a; 32]);

    let mut output = plaintext(SOL_ASSET_ID, 500, 0x31);
    output.ring_program_id = Some(ring_program_id);
    let tx = transaction(
        &tx_key,
        vec![confidential_slot(&tx_key, &recipient.pubkey(), &output, 0)],
        vec![auditor_message_data(&tx_key, &auditor.pubkey())],
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
            asset: SOL_MINT,
            amount: 500,
            blinding: Zeroizing::new([0x31; 32]),
            ring_program_id: Some(ring_program_id),
        }]
    );
}

/// Dummy and foreign slots are reported, and - because the dummy sits between two
/// real slots - this also pins the slot index rule: the index is the position in
/// `output_slots` counted over ALL slots, exactly as the encoder counts it.
#[test]
fn dummy_and_foreign_slots_are_reported_not_fatal() {
    let auditor = ViewingKey::new();
    let tx_key = ViewingKey::new();
    let recipient_one = ViewingKey::new();
    let recipient_two = ViewingKey::new();

    let first = plaintext(SOL_ASSET_ID, 10, 0x41);
    let second = plaintext(TOKEN_ASSET_ID, 20, 0x42);
    let tx = transaction(
        &tx_key,
        vec![
            confidential_slot(&tx_key, &recipient_one.pubkey(), &first, 0),
            dummy_slot(1),
            confidential_slot(&tx_key, &recipient_two.pubkey(), &second, 2),
            foreign_scheme_slot(3),
        ],
        vec![auditor_message_data(&tx_key, &auditor.pubkey())],
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
                    asset: SOL_MINT,
                    amount: 10,
                    blinding: Zeroizing::new([0x41; 32]),
                    ring_program_id: None,
                },
                AuditedOutput {
                    slot_index: 2,
                    recipient_viewing_pk: recipient_two.pubkey(),
                    asset: TOKEN_MINT,
                    amount: 20,
                    blinding: Zeroizing::new([0x42; 32]),
                    ring_program_id: None,
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
    let auditor = ViewingKey::new();
    let tx_key = ViewingKey::new();
    let recipient = ViewingKey::new();

    let output = plaintext(SOL_ASSET_ID, 7, 0x51);
    let mut slot = confidential_slot(&tx_key, &recipient.pubkey(), &output, 1);
    slot.output_context = output_context(0);
    let tx = transaction(
        &tx_key,
        vec![slot],
        vec![auditor_message_data(&tx_key, &auditor.pubkey())],
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
        (vec![], vec![0])
    );
}

#[test]
fn another_auditor_key_finds_no_message() {
    let auditor = ViewingKey::new();
    let stranger = ViewingKey::new();
    let tx_key = ViewingKey::new();
    let recipient = ViewingKey::new();

    let output = plaintext(SOL_ASSET_ID, 1, 0x61);
    let tx = transaction(
        &tx_key,
        vec![confidential_slot(&tx_key, &recipient.pubkey(), &output, 0)],
        vec![auditor_message_data(&tx_key, &auditor.pubkey())],
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
    let auditor = ViewingKey::new();
    let other_auditor = ViewingKey::new();
    let tx_key = ViewingKey::new();

    let encryption =
        AuditorEncryption::new(&tx_key, &other_auditor.pubkey()).expect("auditor encryption");
    // Tagged for `auditor`, decryptable only by `other_auditor`.
    let mislabeled = encryption.message.to_message_data(&auditor.pubkey());
    let tx = transaction(&tx_key, vec![], vec![mislabeled]);

    assert!(matches!(
        TransactionAudit {
            auditor: &auditor,
            transaction: &tx,
            assets: &registry()
        }
        .run(),
        Err(AuditError::TxViewingKeyMismatch)
    ));
}

#[test]
fn tampered_ciphertext_fails_the_integrity_check() {
    let auditor = ViewingKey::new();
    let tx_key = ViewingKey::new();

    let mut message = auditor_message_data(&tx_key, &auditor.pubkey());
    let last = message.data.last_mut().expect("message data");
    *last ^= 0x01;
    let tx = transaction(&tx_key, vec![], vec![message]);

    assert!(matches!(
        TransactionAudit {
            auditor: &auditor,
            transaction: &tx,
            assets: &registry()
        }
        .run(),
        Err(AuditError::TxViewingKeyMismatch)
    ));
}

#[test]
fn transaction_without_auditor_message_is_rejected() {
    let auditor = ViewingKey::new();
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
    let auditor = ViewingKey::new();
    let tx_key = ViewingKey::new();

    let tx = transaction(
        &tx_key,
        vec![],
        vec![
            auditor_message_data(&tx_key, &auditor.pubkey()),
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
    let auditor = ViewingKey::new();
    let tx_key = ViewingKey::new();

    let tx = transaction(
        &tx_key,
        vec![],
        vec![
            auditor_message_data(&tx_key, &auditor.pubkey()),
            auditor_message_data(&tx_key, &auditor.pubkey()),
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
    let auditor = ViewingKey::new();
    let tx_key = ViewingKey::new();

    let mut no_pubkey = transaction(
        &tx_key,
        vec![],
        vec![auditor_message_data(&tx_key, &auditor.pubkey())],
    );
    no_pubkey.tx_viewing_pk = None;
    let mut no_salt = transaction(
        &tx_key,
        vec![],
        vec![auditor_message_data(&tx_key, &auditor.pubkey())],
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
    let auditor = ViewingKey::new();
    let tx_key = ViewingKey::new();
    let recipient = ViewingKey::new();

    let output = plaintext(TOKEN_ASSET_ID + 1, 4, 0x91);
    let tx = transaction(
        &tx_key,
        vec![confidential_slot(&tx_key, &recipient.pubkey(), &output, 0)],
        vec![auditor_message_data(&tx_key, &auditor.pubkey())],
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
}

impl Rpc for PagedIndexer {
    fn get_ring_shielded_transactions_by_tag(
        &self,
        request: RingShieldedTransactionsByTagRequest,
    ) -> Result<GetShieldedTransactionsByTagsResponse, zolana_client::ClientError> {
        assert_eq!(request.tag(), self.expected_tag);
        assert_eq!(
            request.ring_program_id(),
            Address::new_from_array([9u8; 32])
        );
        let page_index = usize::from(*request.cursor().unwrap_or_default().first().unwrap_or(&0));
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
        })
    }
}

#[test]
fn scan_walks_every_page_and_keeps_only_auditor_tagged_transactions() {
    let auditor = ViewingKey::new();
    let auditor_pk = auditor.pubkey();
    let tx_key_one = ViewingKey::new();
    let tx_key_two = ViewingKey::new();
    let recipient = ViewingKey::new();

    let first_output = plaintext(SOL_ASSET_ID, 111, 0xa1);
    let second_output = plaintext(TOKEN_ASSET_ID, 222, 0xa2);
    let first = transaction(
        &tx_key_one,
        vec![confidential_slot(
            &tx_key_one,
            &recipient.pubkey(),
            &first_output,
            0,
        )],
        vec![auditor_message_data(&tx_key_one, &auditor_pk)],
    );
    let second = transaction(
        &tx_key_two,
        vec![confidential_slot(
            &tx_key_two,
            &recipient.pubkey(),
            &second_output,
            0,
        )],
        vec![auditor_message_data(&tx_key_two, &auditor_pk)],
    );
    // Matched on an output view tag, carries no auditor message.
    let mut output_tag_match = transaction(&tx_key_one, vec![], vec![free_form_message()]);
    output_tag_match.output_slots.push(OutputSlot {
        view_tag: auditor_view_tag(&auditor_pk),
        output_context: output_context(0),
        payload: vec![0xff; 8],
    });
    let mut foreign_ring = first.clone();
    foreign_ring.ring = RingAssociation::Resolved {
        config: Address::new_from_array([7u8; 32]),
        program_id: Address::new_from_array([6u8; 32]),
    };
    let mut unresolved_ring = first.clone();
    unresolved_ring.ring = RingAssociation::Unresolved {
        config: Address::new_from_array([7u8; 32]),
    };
    let mut no_ring = first.clone();
    no_ring.ring = RingAssociation::None;

    let indexer = PagedIndexer {
        expected_tag: auditor_view_tag(&auditor_pk),
        pages: vec![
            vec![
                first.clone(),
                output_tag_match,
                foreign_ring,
                unresolved_ring,
                no_ring,
            ],
            vec![second.clone()],
        ],
    };

    assert_eq!(
        RingScan::new(Address::new_from_array([9u8; 32]), &auditor_pk)
            .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
            .run(&indexer)
            .expect("scan")
            .transactions,
        vec![first, second]
    );

    let audited = RingAudit::new(Address::new_from_array([9u8; 32]), &auditor)
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .run(&indexer, &registry())
        .expect("audit all")
        .transactions;
    assert_eq!(audited.len(), 2);
    assert_eq!(audited[0].tx_viewing_pk, tx_key_one.pubkey());
    assert_eq!(
        &audited[0].outputs,
        &[AuditedOutput {
            slot_index: 0,
            recipient_viewing_pk: recipient.pubkey(),
            asset: SOL_MINT,
            amount: 111,
            blinding: Zeroizing::new([0xa1; 32]),
            ring_program_id: None,
        }]
    );
    assert_eq!(audited[1].tx_viewing_pk, tx_key_two.pubkey());
    assert_eq!(
        &audited[1].outputs,
        &[AuditedOutput {
            slot_index: 0,
            recipient_viewing_pk: recipient.pubkey(),
            asset: TOKEN_MINT,
            amount: 222,
            blinding: Zeroizing::new([0xa2; 32]),
            ring_program_id: None,
        }]
    );
}

struct FilteringIndexer {
    rows: Vec<ShieldedTransaction>,
}

impl Rpc for FilteringIndexer {
    fn get_ring_shielded_transactions_by_tag(
        &self,
        request: RingShieldedTransactionsByTagRequest,
    ) -> Result<GetShieldedTransactionsByTagsResponse, zolana_client::ClientError> {
        let program_id = request.ring_program_id();
        let limit = usize::try_from(request.limit().expect("page size").get())
            .expect("page size fits usize");
        let transactions = self
            .rows
            .iter()
            .filter(|tx| {
                let config = pda::ring_auth(&program_id).0;
                matches!(
                    tx.ring,
                    RingAssociation::Unresolved { config: candidate }
                        if candidate == config
                ) || matches!(
                    tx.ring,
                    RingAssociation::Resolved {
                        config: candidate_config,
                        program_id: candidate_program,
                    } if candidate_config == config && candidate_program == program_id
                )
            })
            .take(limit)
            .cloned()
            .collect();
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 1,
            },
            transactions,
            next_cursor: None,
        })
    }
}

#[test]
fn scan_accepts_the_canonical_unresolved_ring() {
    let auditor = ViewingKey::new();
    let auditor_pk = auditor.pubkey();
    let target = Address::new_from_array([9u8; 32]);
    let mut matching = transaction(
        &ViewingKey::new(),
        Vec::new(),
        vec![auditor_message_data(&ViewingKey::new(), &auditor.pubkey())],
    );
    matching.ring = RingAssociation::Unresolved {
        config: pda::ring_auth(&target).0,
    };
    let mut foreign = matching.clone();
    foreign.ring = RingAssociation::Unresolved {
        config: Address::new_from_array([7u8; 32]),
    };
    let indexer = PagedIndexer {
        expected_tag: auditor_view_tag(&auditor_pk),
        pages: vec![vec![foreign, matching.clone()]],
    };

    assert_eq!(
        RingScan::new(target, &auditor_pk)
            .with_max_pages(NonZeroUsize::new(1).expect("page limit"))
            .run(&indexer)
            .expect("scan")
            .transactions,
        vec![matching]
    );
}

#[test]
fn scan_applies_the_ring_filter_before_the_page_limit() {
    let auditor = ViewingKey::new();
    let auditor_pk = auditor.pubkey();
    let target = Address::new_from_array([9u8; 32]);
    let mut foreign = transaction(
        &ViewingKey::new(),
        Vec::new(),
        vec![auditor_message_data(&ViewingKey::new(), &auditor.pubkey())],
    );
    foreign.ring = RingAssociation::Resolved {
        config: Address::new_from_array([7u8; 32]),
        program_id: Address::new_from_array([6u8; 32]),
    };
    let target_transaction = transaction(
        &ViewingKey::new(),
        Vec::new(),
        vec![auditor_message_data(&ViewingKey::new(), &auditor.pubkey())],
    );
    let indexer = FilteringIndexer {
        rows: vec![foreign, target_transaction.clone()],
    };

    assert_eq!(
        RingScan::new(target, &auditor_pk)
            .with_page_size(NonZeroU32::MIN)
            .with_max_pages(NonZeroUsize::new(1).expect("page limit"))
            .run(&indexer)
            .expect("scan")
            .transactions,
        vec![target_transaction]
    );
}
