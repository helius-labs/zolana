use solana_keypair::Keypair;
use zeroize::Zeroizing;
use zolana_keypair::ViewingKey;
use zolana_transaction::Data;

use super::*;
use crate::AuditedOutput;

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

#[test]
fn read_attestation_is_stable() {
    let message = ReadAttestation {
        ring: Address::new_from_array([7; 32]),
        cursor: Some(vec![1, 2, 3].into()),
        limit: Some(Limit::new(5).expect("in range")),
    }
    .message(1_700_000_000, &[4; 32]);
    assert_eq!(
        String::from_utf8(message).expect("text"),
        "zolana/ring-rpc-read/v1\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1700000000\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nlimit: 5\ncursor: AQID"
    );
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

/// The JSON clients parse, pinned byte for byte.
#[test]
fn a_decrypted_page_keeps_its_wire_json() {
    let viewing = ViewingKey::from_bytes(&[3; 32]).pubkey();
    let opening = zolana_client::ProofInputUtxo::new(
        [2; 32],
        &Address::new_from_array([4; 32]),
        9,
        &[5; 32],
        4,
    )
    .unwrap()
    .with_ring([0; 32], &Some(Address::new_from_array([7; 32])))
    .unwrap();
    let context = zolana_transaction::OutputContext {
        hash: opening.hash().unwrap(),
        tree_id: 4,
        leaf_index: 1,
    };
    let audited = AuditedTransaction {
        tx_signature: Signature::from([1; 64]),
        slot: 42,
        tx_viewing_pk: viewing,
        outputs: vec![AuditedOutput {
            slot_index: 0,
            recipient_viewing_pk: viewing,
            owner_tag: [2; 32],
            asset: Address::new_from_array([4; 32]),
            amount: 9,
            blinding: Zeroizing::new([5; 32]),
            ring_program_id: Some(Address::new_from_array([7; 32])),
            data: Data::default(),
        }],
        output_contexts: vec![context],
        output_openings: vec![opening],
        anonymous: None,
        payload_errors: Vec::new(),
    };
    let withdrawal = RingWithdrawal {
        recipient: Address::new_from_array([10; 32]),
        asset: Address::new_from_array([4; 32]),
        amount: 5,
    };
    let page = GetDecryptedTransactionsResponse {
        context: Context {
            block_time: 1,
            slot: 43,
        },
        value: DecryptedTransactionsPage {
            items: vec![DecryptedTransaction::new(
                audited,
                7,
                vec![[12; 32]],
                vec![Address::new_from_array([13; 32])],
                vec![withdrawal],
            )],
            skipped: vec![SkippedTransaction {
                slot: 40,
                tx_signature: Signature::from([14; 64]).into(),
                event_index: 8,
                reason: SkippedReason::MissingAuditorMessage,
            }],
            cursor: Some(vec![15].into()),
        },
    };
    let json = serde_json::to_string(&page).expect("json");
    assert_eq!(json, include_str!("decrypted_page.json").trim_end());
    assert_eq!(
        serde_json::from_str::<GetDecryptedTransactionsResponse>(&json).expect("parses"),
        page
    );
}

#[test]
fn a_signed_read_carries_the_reader_and_the_bounds_it_signed() {
    let reader = Keypair::new();
    let ring = Address::new_from_array([7; 32]);
    let request = GetDecryptedTransactionsRequest::read(ring)
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
        ring,
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
        GetDecryptedTransactionsRequest::read(ring).with_cursor(Vec::new().into()),
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
