use custom_ring_interface::stream::RingTag;
use solana_keypair::Keypair;
use zolana_keypair::ViewingKey;
use zolana_transaction::OutputContext;

use super::*;
use crate::{
    AuditedInputOpening, AuditedSender, OutputPayloadError,
    OutputPayloadErrorKind::{self, Commitment, Disclosure, EscrowUnknown, Frame, RecipientKey},
};

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ring-rpc-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn deposits_request(limit: Option<u32>, cursor: Option<Vec<u8>>) -> RingDepositsRequest {
    RingDepositsRequest {
        ring_program_id: Address::new_from_array([5; 32]).to_bytes().into(),
        limit,
        cursor: cursor.map(Into::into),
    }
}

#[test]
fn auditor_key_request_attestation_is_stable() {
    let attestation = AuditorKeyAttestation {
        genesis_hash: [9; 32],
        ring: Address::new_from_array([5; 32]),
    }
    .message(1_700_000_000, &[7; 32]);
    assert_eq!(
        String::from_utf8(attestation).expect("utf8"),
        "zolana/ring-rpc-auditor-key-request/v1\n\
         genesis: cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN\n\
         ring: LbUiWL3xVV8hTFYBVdbTNrpDo41NKS6o3LHHuDzjfcY\n\
         timestamp: 1700000000\n\
         nonce: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
    );
}

/// The ring at `[7; 32]` behind the service `[2; 32]` on the cluster `[1; 32]`.
fn target() -> ReadTarget {
    ReadTarget {
        cluster: [1; 32],
        service: Address::new_from_array([2; 32]),
        ring: Address::new_from_array([7; 32]),
    }
}

#[test]
fn read_attestation_is_stable() {
    let message = ReadAttestation {
        read: PagedRead::DecryptedTransactions,
        target: target(),
        cursor: Some(vec![1, 2, 3].into()),
        limit: Some(Limit::new(5).expect("in range")),
    }
    .message(1_700_000_000, &[4; 32]);
    assert_eq!(
        String::from_utf8(message).expect("text"),
        "zolana/ring-rpc-read/v2\nmethod: getDecryptedTransactions\ncluster: 4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\nservice: 8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1700000000\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nlimit: 5\ncursor: AQID"
    );
}

/// A reader's signature names its method, cluster, service and ring, each request a fresh nonce.
#[test]
fn a_signed_read_names_its_method_and_target_and_draws_its_own_nonce() {
    let reader = Keypair::new();
    let sign = |read: PagedRead| {
        read.request(target())
            .at(1_700_000_000)
            .sign(&reader)
            .unwrap()
    };
    let transfers = sign(PagedRead::DecryptedTransactions);
    let nonce: [u8; 32] = transfers.auth.nonce.0.clone().try_into().unwrap();
    let signature = Signature::try_from(transfers.auth.signature.0.as_slice()).unwrap();
    let attested = |read, target| {
        ReadAttestation {
            read,
            target,
            cursor: None,
            limit: None,
        }
        .message(1_700_000_000, &nonce)
    };
    assert!(signature.verify(
        reader.pubkey().as_ref(),
        &attested(PagedRead::DecryptedTransactions, target())
    ));
    let elsewhere = [
        ReadTarget {
            cluster: [9; 32],
            ..target()
        },
        ReadTarget {
            service: Address::new_from_array([9; 32]),
            ..target()
        },
    ];
    for other in elsewhere {
        assert!(!signature.verify(
            reader.pubkey().as_ref(),
            &attested(PagedRead::DecryptedTransactions, other)
        ));
    }
    assert!(!signature.verify(
        reader.pubkey().as_ref(),
        &attested(PagedRead::AuditedMerges, target())
    ));
    assert_ne!(
        sign(PagedRead::DecryptedTransactions).auth.nonce,
        transfers.auth.nonce
    );
}

#[test]
fn audited_utxos_attestation_is_stable() {
    let message = AuditedUtxosAttestation::new(target(), &[Hash([1; 32]), Hash([2; 32])])
        .message(1_700_000_000, &[4; 32]);
    assert_eq!(
        String::from_utf8(message).expect("text"),
        "zolana/ring-rpc-audited-utxos/v1\ncluster: 4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\nservice: 8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1700000000\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nutxos: +Biv03ptw7yS+0RzEBEncAbbTvpukCPNdGjAIzXSKk0="
    );
}

#[test]
fn a_signed_utxo_read_carries_the_hashes_it_signed() {
    let reader = Keypair::new();
    let ring = target().ring;
    let hashes = vec![Hash([1; 32]), Hash([2; 32])];
    let request = GetAuditedUtxosRequest::read(target(), hashes.clone())
        .expect("utxo read")
        .at(1_700_000_000)
        .sign(&reader)
        .expect("signed");
    assert_eq!(request.utxo_hashes, hashes);
    assert_eq!(request.ring_program_id, Some(ring.to_bytes().into()));
    let nonce = request.auth.nonce.0.clone().try_into().expect("nonce");
    let signature = Signature::try_from(request.auth.signature.0.as_slice()).expect("signature");
    let signed = |hashes: &[Hash]| {
        AuditedUtxosAttestation::new(target(), hashes).message(1_700_000_000, &nonce)
    };
    assert!(signature.verify(reader.pubkey().as_ref(), &signed(&hashes)));
    assert!(!signature.verify(
        reader.pubkey().as_ref(),
        &signed(&[Hash([2; 32]), Hash([1; 32])])
    ));
    for count in [0, AUDITED_UTXOS_LIMIT + 1] {
        assert!(matches!(
            GetAuditedUtxosRequest::read(target(), vec![Hash([1; 32]); count]),
            Err(ReadBuildError::UtxoHashes)
        ));
    }
}

/// `Limit` cannot hold zero, so the smallest audit page the wire carries is one.
#[test]
fn an_audit_page_holds_at_its_cursor_and_limit_bounds() {
    assert!(!cursor_in_bounds(&[]));
    assert!(cursor_in_bounds(&vec![1; AUDIT_CURSOR_LIMIT]));
    assert!(!cursor_in_bounds(&vec![1; AUDIT_CURSOR_LIMIT + 1]));
    assert!(limit_in_bounds(&Limit::new(1).expect("indexer limit")));
    assert!(limit_in_bounds(
        &Limit::new(AUDIT_PAGE_LIMIT).expect("indexer limit")
    ));
    assert!(!limit_in_bounds(
        &Limit::new(AUDIT_PAGE_LIMIT + 1).expect("indexer limit")
    ));
}

/// The deposits limit counts signatures examined, so it is clamped, never refused.
#[test]
fn a_deposits_page_clamps_its_limit_into_range() {
    for (limit, expected) in [
        (None, DEPOSITS_PAGE_LIMIT),
        (Some(0), 1),
        (Some(1), 1),
        (Some(MAX_DEPOSITS_PAGE_LIMIT), MAX_DEPOSITS_PAGE_LIMIT),
        (Some(MAX_DEPOSITS_PAGE_LIMIT + 1), MAX_DEPOSITS_PAGE_LIMIT),
        (Some(u32::MAX), MAX_DEPOSITS_PAGE_LIMIT),
    ] {
        assert_eq!(
            deposits_request(limit, None).page_limit(),
            expected as usize
        );
    }
}

/// The deposits cursor is a Solana signature, unlike the opaque audit cursor.
#[test]
fn a_deposits_cursor_is_exactly_one_signature() {
    assert_eq!(
        deposits_request(None, Some(vec![1; 64]))
            .before()
            .expect("cursor"),
        Some(Signature::from([1; 64]))
    );
    assert_eq!(
        deposits_request(None, None).before().expect("no cursor"),
        None
    );
    for length in [0, 63, 65, AUDIT_CURSOR_LIMIT] {
        assert!(matches!(
            deposits_request(None, Some(vec![1; length])).before(),
            Err(ReadBuildError::Cursor)
        ));
    }
}

fn utxo(seed: u8, mint: Option<Address>) -> AuditedUtxo {
    AuditedUtxo {
        owner_key: [seed; 32],
        nullifier_pk: [seed + 1; 32],
        asset: [seed + 2; 32],
        mint,
        amount: u64::from(seed),
        blinding: [seed + 3; 32],
        data_hash: [seed + 4; 32],
        ring_data_hash: [seed + 5; 32],
    }
}

fn output(slot_index: u32, opening: OutputOpening) -> AuditedOutput {
    AuditedOutput {
        slot_index,
        context: OutputContext {
            hash: [0x40 + slot_index as u8; 32],
            tree_id: 4,
            leaf_index: u64::from(slot_index) + 1,
        },
        opening,
    }
}

fn page(
    audited: AuditedTransaction,
    nullifiers: Vec<[u8; 32]>,
) -> GetDecryptedTransactionsResponse {
    let withdrawal = RingWithdrawal {
        recipient: Address::new_from_array([10; 32]),
        asset: Address::new_from_array([4; 32]),
        amount: 5,
    };
    GetDecryptedTransactionsResponse {
        context: Context {
            block_time: 1,
            slot: 43,
        },
        value: DecryptedTransactionsPage {
            items: vec![ConfirmedAudit {
                audited,
                event_index: 7,
                nullifiers,
                signers: vec![Address::new_from_array([13; 32])],
                withdrawals: vec![withdrawal],
            }
            .into()],
            skipped: vec![SkippedTransaction {
                slot: 40,
                tx_signature: Signature::from([14; 64]).into(),
                event_index: 8,
                reason: SkippedReason::MissingAuditorMessage,
            }],
            cursor: Some(vec![15].into()),
        },
    }
}

/// The JSON clients parse, pinned byte for byte.
#[test]
fn a_decrypted_page_keeps_its_wire_json() {
    let audited = AuditedTransaction {
        tx_signature: Signature::from([1; 64]),
        slot: 42,
        tx_viewing_pk: ViewingKey::from_bytes(&[3; 32]).pubkey(),
        outputs: vec![
            output(
                0,
                OutputOpening::Ring {
                    utxo: utxo(0x10, Some(Address::new_from_array([4; 32]))),
                    recipient_u: [6; 32],
                    tag: None,
                },
            ),
            output(1, OutputOpening::Exit(utxo(0x20, None))),
            output(2, OutputOpening::Dummy),
        ],
        payload_errors: vec![OutputPayloadError {
            slot_index: 3,
            kind: Commitment,
        }],
        sender: None,
        inputs: Vec::new(),
    };
    let page = page(audited, vec![[12; 32]]);
    let json = serde_json::to_string(&page).expect("json");
    assert_eq!(json, include_str!("decrypted_page.json").trim_end());
    assert_eq!(
        serde_json::from_str::<GetDecryptedTransactionsResponse>(&json).expect("parses"),
        page
    );
}

/// The TypeScript decoder reads the same page.
#[test]
fn an_anonymous_decrypted_page_keeps_its_wire_json() {
    let opening = |seed: u8, ring| AuditedInputOpening {
        asset: [seed; 32],
        mint: Some(Address::new_from_array([4; 32])),
        amount: u64::from(seed),
        blinding: [seed + 1; 32],
        ring,
    };
    let audited = AuditedTransaction {
        tx_signature: Signature::from([1; 64]),
        slot: 42,
        tx_viewing_pk: ViewingKey::from_bytes(&[2; 32]).pubkey(),
        outputs: vec![
            output(
                0,
                OutputOpening::Ring {
                    utxo: AuditedUtxo {
                        data_hash: [0; 32],
                        ring_data_hash: [0; 32],
                        ..utxo(0x10, Some(Address::new_from_array([4; 32])))
                    },
                    recipient_u: [6; 32],
                    tag: Some(RingTag::from_bytes([0x31; 31])),
                },
            ),
            output(1, OutputOpening::Exit(utxo(0x20, None))),
            output(2, OutputOpening::Dummy),
        ],
        payload_errors: Vec::new(),
        sender: Some(AuditedSender {
            owner_key: [0x50; 32],
            nullifier_pk: Some([0x51; 32]),
        }),
        inputs: vec![
            AuditedInput {
                nullifier: [12; 32],
                opening: Some(opening(
                    0x60,
                    Some(InputRing::Ring {
                        commitment: [0x62; 32],
                    }),
                )),
            },
            AuditedInput {
                nullifier: [11; 32],
                opening: Some(opening(
                    0x70,
                    Some(InputRing::Unresolved {
                        ring: [0x72; 32],
                        default: [0x73; 32],
                    }),
                )),
            },
            AuditedInput {
                nullifier: [10; 32],
                opening: Some(opening(
                    0x80,
                    Some(InputRing::Default {
                        commitment: [0x82; 32],
                    }),
                )),
            },
            AuditedInput {
                nullifier: [9; 32],
                opening: Some(opening(0x90, None)),
            },
            AuditedInput {
                nullifier: [8; 32],
                opening: None,
            },
        ],
    };
    let page = page(
        audited,
        vec![[12; 32], [11; 32], [10; 32], [9; 32], [8; 32]],
    );
    let json = serde_json::to_string(&page).expect("json");
    assert_eq!(
        json,
        include_str!("decrypted_anonymous_page.json").trim_end()
    );
    assert_eq!(
        serde_json::from_str::<GetDecryptedTransactionsResponse>(&json).expect("parses"),
        page
    );
}

/// The TypeScript decoder reads the same vector.
#[test]
fn payload_errors_keep_the_encoding_of_the_shared_vector() {
    #[derive(Deserialize)]
    struct Vector {
        kinds: serde_json::Value,
        foreign_body_and_low_order_key: serde_json::Value,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/ring_rpc_payload_errors.json"
    ))
    .expect("vector");
    // A new kind fails to compile here, `kinds` and the vector must then name it.
    let named = |kind: OutputPayloadErrorKind| match kind {
        Frame | Disclosure | RecipientKey | Commitment | EscrowUnknown => kind,
    };
    let kinds = [Frame, Disclosure, RecipientKey, Commitment, EscrowUnknown].map(named);
    assert_eq!(serde_json::to_value(kinds).unwrap(), vector.kinds);
    let slots = [(2, Commitment), (5, RecipientKey)]
        .map(|(slot_index, kind)| DecryptedPayloadError { slot_index, kind });
    assert_eq!(
        serde_json::to_value(slots).unwrap(),
        vector.foreign_body_and_low_order_key
    );
}

/// A root history slot never written reads as absent.
#[test]
fn ring_status_reads_the_registry_history_and_queue() {
    let mut registry = MemberRegistry::new(7, 100);
    registry.push_root(
        [5; 32],
        custom_ring_interface::AppliedAt {
            applied: 3,
            slot: 120,
        },
    );
    registry.raise_floor();
    let mut queue = RecordQueue::new(9);
    queue.head = 3u64.to_le_bytes();
    queue.tail = 5u64.to_le_bytes();
    let status = RegistryStatus::new(&registry, &queue);
    assert_eq!(status.history.len(), custom_ring_interface::ROOT_HISTORY);
    assert_eq!(
        status.history[..3],
        [
            Some(RegistryRoot {
                root: custom_ring_interface::MEMBER_REGISTRY_EMPTY_ROOT.into(),
                applied: 0,
                slot: 100,
            }),
            Some(RegistryRoot {
                root: [5; 32].into(),
                applied: 3,
                slot: 120,
            }),
            None,
        ]
    );
    assert_eq!(
        (status.history_cursor, status.next_index),
        (1, registry.next_index())
    );
    assert_eq!(
        (status.floor, status.prior_floor, status.floor_slot),
        (3, 0, 120)
    );
    assert_eq!((status.queue_head, status.queue_tail), (3, 5));
}

#[test]
fn a_signed_read_carries_the_reader_and_the_bounds_it_signed() {
    let reader = Keypair::new();
    let request = GetDecryptedTransactionsRequest::read(target())
        .with_cursor(vec![1].into())
        .expect("cursor")
        .with_limit(Limit::new(5).expect("limit"))
        .expect("limit")
        .at(1_700_000_000)
        .sign(&reader)
        .expect("signed");
    assert_eq!(
        request.auth.reader.0,
        ReaderKey::ed25519(reader.pubkey())
            .expect("reader")
            .to_bytes()
            .to_vec()
    );
    let message = ReadAttestation {
        read: PagedRead::DecryptedTransactions,
        target: target(),
        cursor: request.cursor.clone(),
        limit: request.limit.clone(),
    }
    .message(
        1_700_000_000,
        &request.auth.nonce.0.clone().try_into().expect("nonce"),
    );
    let signature = Signature::try_from(request.auth.signature.0.as_slice()).expect("signature");
    assert!(signature.verify(reader.pubkey().as_ref(), &message));
    assert!(matches!(
        GetDecryptedTransactionsRequest::read(target()).with_cursor(Vec::new().into()),
        Err(ReadBuildError::Cursor)
    ));
}

#[test]
fn keygen_writes_a_secret_the_loader_reads_and_a_matching_public_key() {
    let dir = temp_dir("keygen");
    let secret = dir.join("auditor.key");
    let key = write_auditor_key(&secret).expect("keygen");
    assert_eq!(
        read_auditor_key(&secret, Access::OwnerOnly)
            .expect("load")
            .pubkey(),
        key.pubkey()
    );
    let public_path = public_key_path(&secret).expect("public path");
    assert_eq!(
        std::fs::read_to_string(&public_path).expect("pub file"),
        hex::encode(key.pubkey().as_bytes())
    );
    assert_eq!(
        read_auditor_pubkey(&public_path).expect("pubkey"),
        key.pubkey()
    );
    assert!(matches!(
        write_auditor_key(&secret),
        Err(KeyFileError::File(SecretFileError::Write { .. }))
    ));
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn public_key_files_round_trip_and_reject_other_lengths() {
    let dir = temp_dir("pubkey");
    let path = dir.join("nested").join("auditor.key.pub");
    let key = X25519Keypair::new();
    write_auditor_pubkey(&path, &key.pubkey()).expect("write");
    assert_eq!(read_auditor_pubkey(&path).expect("read"), key.pubkey());
    let short = dir.join("short.pub");
    std::fs::write(&short, "02ab").expect("short");
    assert!(matches!(
        read_auditor_pubkey(&short),
        Err(KeyFileError::PubkeyEncoding)
    ));
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn malformed_and_zero_auditor_secrets_are_refused() {
    let dir = temp_dir("zero");
    let zero = dir.join("zero.key");
    create_new(&zero, "00".repeat(32).as_bytes(), Visibility::Secret).expect("zero");
    assert!(matches!(
        read_auditor_key(&zero, Access::OwnerOnly),
        Err(KeyFileError::ZeroAuditorKey)
    ));
    let upper = dir.join("upper.key");
    create_new(&upper, "AA".repeat(32).as_bytes(), Visibility::Secret).expect("upper");
    assert!(matches!(
        read_auditor_key(&upper, Access::OwnerOnly),
        Err(KeyFileError::File(SecretFileError::Hex))
    ));
    std::fs::remove_dir_all(dir).expect("cleanup");
}

fn small_field(value: u8) -> [u8; 32] {
    let mut field = [0; 32];
    field[31] = value;
    field
}

/// An audited notes answer is used only where each opening rebuilds the hash it answers.
#[test]
fn audited_utxos_are_used_only_when_they_rebuild_their_hashes() {
    let ring = Address::new_from_array([7; 32]);
    let mint = Address::new_from_array([3; 32]);
    let keyed = KnownUtxo {
        owner_key: [0xa1; 32],
        owner: UtxoOwner::Keyed {
            nullifier_pk: small_field(5),
        },
        asset: zolana_hasher::primitives::hash_bytes(mint.as_array()).unwrap(),
        mint: Some(mint),
        amount: 40,
        blinding: small_field(6),
        data_hash: [0; 32],
        ring_data_hash: [0; 32],
        tree_id: 3,
    };
    let deposited = KnownUtxo {
        owner: UtxoOwner::Deposited {
            owner_hash: small_field(9),
        },
        amount: 12,
        ..keyed
    };
    let hashes = [keyed, deposited].map(|utxo| utxo.commitment(Some(ring)).unwrap());
    let hash = |index: usize| Hash(hashes[index]);
    let view = |utxo: KnownUtxo, utxo_hash: Hash| AuditedUtxoView {
        utxo_hash,
        utxo: utxo.into(),
        slot: 1,
        tx_signature: Signature::default().into(),
        event_index: 0,
        slot_index: 0,
    };
    let answer = |utxos: Vec<Option<AuditedUtxoView>>| GetAuditedUtxosResponse {
        context: Context {
            slot: 1,
            block_time: 0,
        },
        value: AuditedUtxosPage { utxos },
    };
    let full = answer(vec![
        Some(view(keyed, hash(0))),
        Some(view(deposited, hash(1))),
        None,
    ]);
    let known = full
        .known_utxos(ring, &[hash(0), hash(1), Hash([4; 32])])
        .unwrap();
    assert_eq!(
        known,
        HashMap::from([(hashes[0], keyed), (hashes[1], deposited)])
    );
    let tampered = answer(vec![Some(view(
        KnownUtxo {
            amount: 41,
            ..keyed
        },
        hash(0),
    ))]);
    assert!(matches!(
        tampered.known_utxos(ring, &[hash(0)]),
        Err(AuditError::AuditedUtxoMismatch { .. })
    ));
    let pair = answer(vec![
        Some(view(keyed, hash(0))),
        Some(view(deposited, hash(1))),
    ]);
    assert!(matches!(
        pair.known_utxos(ring, &[hash(1), hash(0)]),
        Err(AuditError::AuditedUtxoMismatch { .. })
    ));
    let mut both = DecryptedKnownUtxo::from(keyed);
    both.owner_hash = Some(Hash(small_field(9)));
    let ambiguous = answer(vec![Some(AuditedUtxoView {
        utxo: both,
        ..view(keyed, hash(0))
    })]);
    assert!(matches!(
        ambiguous.known_utxos(ring, &[hash(0)]),
        Err(AuditError::AuditedUtxoOwner)
    ));
    assert!(matches!(
        full.known_utxos(ring, &[hash(0), hash(1)]),
        Err(AuditError::AuditedUtxosCount { got: 3, want: 2 })
    ));
}
