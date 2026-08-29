use std::collections::HashMap;

#[path = "../rings_fixtures/mod.rs"]
mod rings_fixtures;

use rings_fixtures::{
    fixture_ring_program, fresh_rings_database, resolve_by_signature, resolve_by_tags,
    seed_tagged_transaction_history, signature_at, tag_page, LookupCost, PAGE_LIMIT, VIEW_TAG,
};

use photon_indexer::{
    api::{
        error::PhotonApiError,
        method::rings::{
            get_encrypted_utxos_by_tags, get_merkle_proofs, get_non_inclusion_proofs,
            get_shielded_transactions_by_signature, get_shielded_transactions_by_tags,
        },
    },
    common::rings_tree::RingsTreeKind,
    dao::generated::{
        blocks, indexed_trees, rings_output_payloads, rings_outputs, rings_transaction_payloads,
        rings_transactions, rings_tx_nullifiers, state_trees, transactions, tree_metadata,
    },
    ingester::{
        parser::{
            ring_config_parser::parse_ring_configs,
            rings_event_parser::parse_rings_events,
            state_update::{
                IndexedTreeLeafUpdate, RawIndexedElement, RingsNullifierUpdate, RingsOutputUpdate,
                StateUpdate, Transaction,
            },
            tree_info::TreeInfo,
        },
        persist::{
            indexed_merkle_tree::{
                compute_nullifier_range_node_hash,
                get_multiple_indexed_exclusion_ranges_with_custom_empty_proofs,
                get_zeroeth_nullifier_exclusion_range,
            },
            persist_state_update,
            persisted_indexed_merkle_tree::persist_indexed_tree_updates,
        },
        typedefs::block_info::parse_transaction_info,
        typedefs::block_info::{Instruction, InstructionGroup, TransactionInfo},
    },
    migration::RingsMigrator,
    monitor::tree_metadata_sync,
    snapshot::{is_rings_snapshot_transaction, is_rings_transaction},
};
use sea_orm::{
    sea_query::OnConflict, ColumnTrait, Database, DatabaseConnection, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, Set, TransactionTrait,
};
use sea_orm_migration::MigratorTrait;
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction_status_client_types::EncodedConfirmedTransactionWithStatusMeta;
use zolana_event::{
    encode_event_instruction, encode_output_data, encode_verifiably_encrypted, EventKind,
    GeneralEvent, Input, OutputUtxo, ProoflessOutput, SplTransfer,
};
use zolana_indexer_api::{
    GetMerkleProofsRequest, GetNonInclusionProofsRequest, GetRingsByTagsRequest,
    GetShieldedTransactionsBySignatureRequest, Hash, SerializablePubkey, SerializableSignature,
};
use zolana_interface::{
    instruction::{encode_instruction, tag, BatchUpdateNullifierTreeData, CompressedProof},
    pda,
    state::{address_tree_params, discriminator::TREE_ACCOUNT_DISCRIMINATOR, tree_account_size},
};
use zolana_tree::TreeAccount;

const PROOFLESS_SHIELD_SLOT: u64 = 23;
const SHIELDED_TRANSFER_SLOT: u64 = 25;
const UNSHIELD_SLOT: u64 = 28;
const ENCRYPTED_TRANSFER_SLOT: u64 = 19;
const TEST_TREE: [u8; 32] = [41; 32];

fn only<'a, T>(items: &'a [T], description: &str) -> &'a T {
    assert_eq!(items.len(), 1, "expected exactly one {description}");
    items.first().expect("length checked above")
}

fn only_mut<'a, T>(items: &'a mut [T], description: &str) -> &'a mut T {
    assert_eq!(items.len(), 1, "expected exactly one {description}");
    items.first_mut().expect("length checked above")
}

#[test]
fn parses_proofless_shield_event_with_photon_parser() {
    let state_update =
        parse_rings_update(proofless_shield_transaction_info(), PROOFLESS_SHIELD_SLOT);

    let rings_tx = only(&state_update.rings_transactions, "Rings transaction");
    assert_eq!(rings_tx.parse_version, 3);
    assert_eq!(rings_tx.source_instruction_tag, tag::DEPOSIT as i16);
    assert_eq!(rings_tx.first_output_leaf_index, 0);
    assert!(rings_tx.tx_viewing_pk.is_none());
    assert!(rings_tx.salt.is_none());
    assert!(rings_tx.proofless);
    assert!(rings_tx.nullifiers.is_empty());
    assert_eq!(rings_tx.output_tree, TEST_TREE);
    assert_eq!(
        rings_tx.outputs,
        vec![expected_output(0, 0, 1, 11, proofless_output_payload())]
    );
}

#[test]
fn parses_shielded_transfer_event_with_photon_parser() {
    let state_update =
        parse_rings_update(shielded_transfer_transaction_info(), SHIELDED_TRANSFER_SLOT);

    let rings_tx = only(&state_update.rings_transactions, "Rings transaction");
    assert_eq!(rings_tx.parse_version, 3);
    assert_eq!(rings_tx.source_instruction_tag, tag::TRANSACT as i16);
    assert_eq!(rings_tx.first_output_leaf_index, 1);
    assert!(rings_tx.tx_viewing_pk.is_none());
    assert!(rings_tx.salt.is_none());
    assert!(!rings_tx.proofless);
    assert_eq!(
        rings_tx.nullifiers,
        vec![expected_nullifier(0, 0, 21), expected_nullifier(1, 1, 22),]
    );
    assert_eq!(rings_tx.output_tree, TEST_TREE);
    assert_eq!(
        rings_tx.outputs,
        vec![
            expected_output(0, 1, 2, 12, Vec::new()),
            expected_output(1, 2, 3, 13, Vec::new()),
            expected_output(2, 3, 4, 14, Vec::new()),
        ]
    );
}

#[test]
fn parses_encrypted_transfer_event_with_photon_parser() {
    let state_update = parse_rings_update(
        encrypted_transfer_transaction_info(),
        ENCRYPTED_TRANSFER_SLOT,
    );

    let rings_tx = only(&state_update.rings_transactions, "Rings transaction");
    assert_eq!(rings_tx.parse_version, 3);
    assert_eq!(rings_tx.source_instruction_tag, tag::TRANSACT as i16);
    assert_eq!(rings_tx.first_output_leaf_index, 2);
    let tx_viewing_pk = rings_tx
        .tx_viewing_pk
        .as_ref()
        .expect("encrypted transfer should include a tx viewing key");
    assert_eq!(tx_viewing_pk, &[5; 33]);
    let salt = rings_tx
        .salt
        .as_ref()
        .expect("encrypted transfer should include a salt");
    assert_eq!(salt, &[6; 16]);
    assert!(!rings_tx.proofless);
    assert_eq!(
        rings_tx.nullifiers,
        vec![expected_nullifier(0, 4, 25), expected_nullifier(1, 5, 26),]
    );
    assert_eq!(rings_tx.output_tree, TEST_TREE);
    assert_eq!(
        rings_tx.outputs,
        vec![
            expected_output(0, 2, 8, 18, encode_verifiably_encrypted(vec![1, 2, 3]),),
            expected_output(1, 3, 9, 19, encode_verifiably_encrypted(vec![4, 5, 6]),),
            expected_output(2, 4, 10, 20, encode_verifiably_encrypted(vec![7, 8, 9]),),
        ]
    );
}

#[test]
fn parses_unshield_event_with_photon_parser() {
    let state_update = parse_rings_update(unshield_transaction_info(), UNSHIELD_SLOT);

    let rings_tx = only(&state_update.rings_transactions, "Rings transaction");
    assert_eq!(rings_tx.parse_version, 3);
    assert_eq!(rings_tx.source_instruction_tag, tag::TRANSACT as i16);
    assert_eq!(rings_tx.first_output_leaf_index, 4);
    assert!(rings_tx.tx_viewing_pk.is_none());
    assert!(rings_tx.salt.is_none());
    assert!(!rings_tx.proofless);
    assert_eq!(
        rings_tx.nullifiers,
        vec![expected_nullifier(0, 2, 23), expected_nullifier(1, 3, 24),]
    );
    assert_eq!(rings_tx.output_tree, TEST_TREE);
    assert_eq!(
        rings_tx.outputs,
        vec![
            expected_output(0, 4, 5, 15, Vec::new()),
            expected_output(1, 5, 6, 16, Vec::new()),
            expected_output(2, 6, 7, 17, Vec::new()),
        ]
    );
}

#[test]
fn rings_snapshot_filter_keeps_rings_transactions() {
    assert!(is_rings_transaction(
        &proofless_shield_transaction_info(),
        PROOFLESS_SHIELD_SLOT
    ));
    assert!(is_rings_transaction(
        &shielded_transfer_transaction_info(),
        SHIELDED_TRANSFER_SLOT
    ));
    assert!(is_rings_transaction(
        &unshield_transaction_info(),
        UNSHIELD_SLOT
    ));
    assert!(is_rings_transaction(
        &encrypted_transfer_transaction_info(),
        ENCRYPTED_TRANSFER_SLOT
    ));
}

/// Replays a real ring CPI captured from localnet by `just dump-ring-fixture`.
///
/// The ring's identity is only in the signed `ring_config` account, at a fixed
/// position in the pool instruction's account list -- the event payload does
/// not carry it and the event's parent is the pool either way. Reordering that
/// list would silently reattribute every ring transaction, which this catches
/// by deriving the expected PDA from the ring program the fixture actually
/// invoked.
#[test]
fn ring_fixture_records_the_signing_ring_config() {
    let confirmed: EncodedConfirmedTransactionWithStatusMeta =
        serde_json::from_str(include_str!("../fixtures/ring_transact.json"))
            .expect("ring_transact fixture");
    let slot = confirmed.slot;
    let tx = parse_transaction_info(confirmed.transaction).expect("fixture transaction");

    // The transaction also carries a ComputeBudget instruction, so take the
    // group that actually reached the pool.
    let ring_program = tx
        .instruction_groups
        .iter()
        .find(|group| {
            group
                .inner_instructions
                .iter()
                .any(|inner| inner.program_id == pda::shielded_pool_program_id())
        })
        .expect("group that invoked the pool")
        .outer_instruction
        .program_id;
    assert_ne!(
        ring_program,
        pda::shielded_pool_program_id(),
        "fixture must be a ring CPI, not a direct pool call"
    );

    let state_update = parse_rings_events(&tx, slot)
        .expect("parse fixture")
        .expect("fixture carries rings events");
    let [update] = state_update.rings_transactions.as_slice() else {
        panic!(
            "expected one rings transaction, got {}",
            state_update.rings_transactions.len()
        );
    };

    let (ring_auth, _) = pda::ring_auth(&ring_program);
    assert_eq!(update.ring_config, Some(ring_auth.to_bytes()));
}

/// Replays a real registration captured by `just dump-ring-fixture`. The
/// harness registers through the ring program's CPI, so the pool's instruction
/// is an inner one -- a scan that only looked at outer instructions would index
/// no rings at all.
///
/// The assertion is self-validating: the recorded config account must be the
/// `ring_auth` PDA of the recorded program id, which is exactly the identity the
/// pool checks at creation. Reading the wrong account breaks it.
#[test]
fn ring_config_fixture_records_the_registered_ring() {
    let confirmed: EncodedConfirmedTransactionWithStatusMeta =
        serde_json::from_str(include_str!("../fixtures/create_ring_config.json"))
            .expect("create_ring_config fixture");
    let slot = confirmed.slot;
    let tx = parse_transaction_info(confirmed.transaction).expect("fixture transaction");

    let state_update = parse_ring_configs(&tx, slot)
        .expect("parse fixture")
        .expect("fixture carries a registration");
    let [config] = state_update.ring_configs.as_slice() else {
        panic!(
            "expected one registration, got {}",
            state_update.ring_configs.len()
        );
    };

    let (expected, _) = pda::ring_auth(&Pubkey::from(config.program_id));
    assert_eq!(config.ring_config, expected.to_bytes());
    assert_ne!(
        config.program_id,
        pda::shielded_pool_program_id().to_bytes()
    );
    assert_eq!(config.slot, slot);
}

/// The registration and the ring it registers must agree: the transact
/// fixture's `ring_config` is the row the registry maps to a program id.
#[test]
fn the_two_fixtures_describe_the_same_ring() {
    let registration: EncodedConfirmedTransactionWithStatusMeta =
        serde_json::from_str(include_str!("../fixtures/create_ring_config.json")).expect("fixture");
    let transact: EncodedConfirmedTransactionWithStatusMeta =
        serde_json::from_str(include_str!("../fixtures/ring_transact.json")).expect("fixture");

    let registration_slot = registration.slot;
    let registered = parse_ring_configs(
        &parse_transaction_info(registration.transaction).expect("transaction"),
        registration_slot,
    )
    .expect("parse")
    .expect("registration");

    let transact_slot = transact.slot;
    let spent = parse_rings_events(
        &parse_transaction_info(transact.transaction).expect("transaction"),
        transact_slot,
    )
    .expect("parse")
    .expect("rings events");

    let registered_config = registered.ring_configs.first().expect("registration");
    let spending = spent.rings_transactions.first().expect("rings transaction");
    assert_eq!(spending.ring_config, Some(registered_config.ring_config));
}

/// Both tag endpoints share `GetRingsByTagsRequest`, so both must honour its
/// ring filter. Accepting the field and ignoring it would silently return
/// another ring's transactions to a caller who asked for one ring.
#[tokio::test]
async fn both_tag_endpoints_honour_the_ring_filter() {
    let db = fresh_rings_database().await;
    let view_tag = [7u8; 32];
    seed_tagged_transaction_history(&db, view_tag, 0..3).await;

    let ours = SerializablePubkey::from(fixture_ring_program());
    let theirs = SerializablePubkey::from(Pubkey::new_unique());

    for ring_program_id in [None, Some(ours)] {
        let request = GetRingsByTagsRequest {
            tags: vec![Hash::from(view_tag)],
            cursor: None,
            limit: None,
            ring_program_id,
        };
        let shielded = get_shielded_transactions_by_tags(&db, request.clone())
            .await
            .expect("tags lookup");
        let encrypted = get_encrypted_utxos_by_tags(&db, request)
            .await
            .expect("utxo lookup");
        assert_eq!(
            shielded.transactions.len(),
            3,
            "ring_program_id={ring_program_id:?}"
        );
        assert_eq!(
            encrypted.matches.len(),
            3,
            "ring_program_id={ring_program_id:?}"
        );
        assert!(shielded.scanned_through.is_some());
        assert!(encrypted.scanned_through.is_some());
    }

    let other_ring = GetRingsByTagsRequest {
        tags: vec![Hash::from(view_tag)],
        cursor: None,
        limit: None,
        ring_program_id: Some(theirs),
    };
    let shielded = get_shielded_transactions_by_tags(&db, other_ring.clone())
        .await
        .expect("tags lookup");
    let encrypted = get_encrypted_utxos_by_tags(&db, other_ring.clone())
        .await
        .expect("utxo lookup");
    assert!(shielded.transactions.is_empty());
    assert!(encrypted.matches.is_empty());

    let shielded_frontier = shielded
        .scanned_through
        .expect("an exhausted transaction scan reports its frontier");
    let encrypted_frontier = encrypted
        .scanned_through
        .expect("an exhausted UTXO scan reports its frontier");
    let resumed_shielded = get_shielded_transactions_by_tags(
        &db,
        GetRingsByTagsRequest {
            cursor: Some(shielded_frontier.clone()),
            ..other_ring.clone()
        },
    )
    .await
    .expect("resume transaction scan");
    let resumed_encrypted = get_encrypted_utxos_by_tags(
        &db,
        GetRingsByTagsRequest {
            cursor: Some(encrypted_frontier.clone()),
            ..other_ring
        },
    )
    .await
    .expect("resume UTXO scan");
    assert!(resumed_shielded.transactions.is_empty());
    assert!(resumed_encrypted.matches.is_empty());
    assert_eq!(resumed_shielded.scanned_through, Some(shielded_frontier));
    assert_eq!(resumed_encrypted.scanned_through, Some(encrypted_frontier));
}

#[test]
fn rings_snapshot_filter_keeps_nullifier_tree_batch_updates() {
    let tx = batch_update_transaction_info(Pubkey::new_unique());

    assert!(!is_rings_transaction(&tx, 1));
    assert!(is_rings_snapshot_transaction(&tx, 1));
}

#[tokio::test]
async fn persists_rings_events() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(
        &db,
        &[PROOFLESS_SHIELD_SLOT, SHIELDED_TRANSFER_SLOT, UNSHIELD_SLOT],
    )
    .await;

    let state_update = StateUpdate::merge_updates(vec![
        parse_ingestion_update(proofless_shield_transaction_info(), PROOFLESS_SHIELD_SLOT),
        parse_ingestion_update(shielded_transfer_transaction_info(), SHIELDED_TRANSFER_SLOT),
        parse_ingestion_update(unshield_transaction_info(), UNSHIELD_SLOT),
    ]);
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;

    let txn = db.begin().await.unwrap();
    persist_state_update(&txn, state_update).await.unwrap();
    txn.commit().await.unwrap();

    assert_eq!(transactions::Entity::find().count(&db).await.unwrap(), 3);
    assert_eq!(
        rings_transactions::Entity::find().count(&db).await.unwrap(),
        3
    );
    assert_eq!(
        rings_transaction_payloads::Entity::find()
            .count(&db)
            .await
            .unwrap(),
        3
    );
    assert_eq!(rings_outputs::Entity::find().count(&db).await.unwrap(), 7);
    assert_eq!(
        rings_output_payloads::Entity::find()
            .count(&db)
            .await
            .unwrap(),
        7
    );
    assert_eq!(
        rings_tx_nullifiers::Entity::find()
            .count(&db)
            .await
            .unwrap(),
        4
    );

    let rows = rings_transactions::Entity::find()
        .order_by_asc(rings_transactions::Column::Slot)
        .all(&db)
        .await
        .unwrap();
    // Plain DEPOSIT/TRANSACT: no ring signed, so no ring_config was passed.
    assert!(rows.iter().all(|row| row.ring_config.is_none()));
    assert_eq!(
        rows.iter()
            .map(|row| row.source_instruction_tag)
            .collect::<Vec<_>>(),
        vec![
            tag::DEPOSIT as i16,
            tag::TRANSACT as i16,
            tag::TRANSACT as i16,
        ]
    );
    assert_eq!(
        rows.iter().map(|row| row.proofless).collect::<Vec<_>>(),
        vec![true, false, false]
    );
    assert!(rows.iter().all(|row| row.tx_viewing_pk.is_none()));
    assert!(rows.iter().all(|row| row.salt.is_none()));
    assert_eq!(
        rows.iter()
            .map(|row| row.first_output_leaf_index)
            .collect::<Vec<_>>(),
        vec![0, 1, 4]
    );

    let outputs = rings_outputs::Entity::find()
        .order_by_asc(rings_outputs::Column::LeafIndex)
        .all(&db)
        .await
        .unwrap();
    assert_eq!(
        outputs.iter().map(|row| row.leaf_index).collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4, 5, 6]
    );
    assert!(outputs.iter().all(|row| row.view_tag.len() == 32));
    assert!(outputs.iter().all(|row| row.utxo_hash.len() == 32));

    let output_payloads = rings_output_payloads::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(
        output_payloads
            .iter()
            .filter(|row| !row.payload.is_empty())
            .count(),
        1
    );
    assert_eq!(
        output_payloads
            .iter()
            .filter(|row| row.payload.is_empty())
            .count(),
        6
    );

    let output = outputs
        .first()
        .expect("persisted Rings outputs should not be empty");
    assert_rings_api_exposes_output_hashes(&db, output).await;
}

#[tokio::test]
async fn signature_lookup_returns_multiple_events_in_event_order() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    let slot = SHIELDED_TRANSFER_SLOT;
    insert_test_blocks(&db, &[slot]).await;

    let mut transaction = shielded_transfer_transaction_info();
    transaction
        .instruction_groups
        .extend(proofless_shield_transaction_info().instruction_groups);
    let state_update = parse_ingestion_update(transaction.clone(), slot);
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;
    let txn = db.begin().await.unwrap();
    persist_state_update(&txn, state_update).await.unwrap();
    txn.commit().await.unwrap();

    let response = get_shielded_transactions_by_signature(
        &db,
        GetShieldedTransactionsBySignatureRequest {
            tx_signature: SerializableSignature(transaction.signature),
        },
    )
    .await
    .unwrap();

    assert_eq!(response.transactions.len(), 2);
    assert_eq!(
        response
            .transactions
            .iter()
            .map(|item| item.event_index)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert!(response
        .transactions
        .iter()
        .all(|item| item.transaction.tx_signature.0 == transaction.signature));

    let missing = get_shielded_transactions_by_signature(
        &db,
        GetShieldedTransactionsBySignatureRequest {
            tx_signature: SerializableSignature(Signature::from([99u8; 64])),
        },
    )
    .await
    .unwrap();
    assert!(missing.transactions.is_empty());
}

/// A caller that already knows its signature -- the confirmation path, or
/// anyone resolving a signature seen elsewhere -- can ask for that one
/// transaction instead of walking the view tag index.
///
/// The signature lookup is one equality on the unique `(signature,
/// event_index)` index, so it costs the same on a tag with 40 or 400
/// transactions. Reaching the same transaction through the tag index costs one
/// request per page and hydrates every older transaction it walks past, because
/// that query filters with `EXISTS` subqueries over `rings_outputs` and orders
/// by `slot ASC`. This test pins that difference so it cannot regress back into
/// a tag scan.
#[tokio::test]
async fn signature_lookup_cost_is_independent_of_view_tag_history() {
    const SHORT_HISTORY: u64 = 40;
    const LONG_HISTORY: u64 = 400;

    let db = fresh_rings_database().await;

    seed_tagged_transaction_history(&db, VIEW_TAG, 0..SHORT_HISTORY).await;
    let short_signature = signature_at(SHORT_HISTORY - 1);
    let short_by_signature = resolve_by_signature(&db, short_signature).await;
    let short_by_tags = resolve_by_tags(&db, VIEW_TAG, short_signature, PAGE_LIMIT).await;

    seed_tagged_transaction_history(&db, VIEW_TAG, SHORT_HISTORY..LONG_HISTORY).await;
    let long_signature = signature_at(LONG_HISTORY - 1);
    let long_by_signature = resolve_by_signature(&db, long_signature).await;
    let long_by_tags = resolve_by_tags(&db, VIEW_TAG, long_signature, PAGE_LIMIT).await;

    // The signature lookup does not notice that the tag grew tenfold.
    let flat = LookupCost {
        requests: 1,
        hydrated_transactions: 1,
    };
    assert_eq!(short_by_signature, flat);
    assert_eq!(long_by_signature, flat);

    // The tag walk pays for the whole history every time.
    assert_eq!(
        short_by_tags,
        LookupCost {
            requests: 1,
            hydrated_transactions: usize::try_from(SHORT_HISTORY).unwrap(),
        }
    );
    assert_eq!(
        long_by_tags,
        LookupCost {
            requests: usize::try_from(LONG_HISTORY.div_ceil(PAGE_LIMIT)).unwrap(),
            hydrated_transactions: usize::try_from(LONG_HISTORY).unwrap(),
        }
    );

    // The confirmation path on a single unpaginated page is not just slower on
    // a long tag, it never sees the transaction at all: the tag query orders by
    // `slot ASC`, so the newest transaction sits on the last page.
    let first_page = tag_page(&db, VIEW_TAG, None, PAGE_LIMIT).await;
    assert_eq!(
        usize::try_from(PAGE_LIMIT).unwrap(),
        first_page.transactions.len()
    );
    assert!(!first_page
        .transactions
        .iter()
        .any(|item| item.tx_signature.0 == long_signature));
}

#[tokio::test]
async fn rings_payloads_update_on_reprocess() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(&db, &[PROOFLESS_SHIELD_SLOT]).await;

    let state_update =
        parse_ingestion_update(proofless_shield_transaction_info(), PROOFLESS_SHIELD_SLOT);
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;

    let txn = db.begin().await.unwrap();
    persist_state_update(&txn, state_update).await.unwrap();
    txn.commit().await.unwrap();

    let mut reprocessed =
        parse_ingestion_update(proofless_shield_transaction_info(), PROOFLESS_SHIELD_SLOT);
    let rings_tx = reprocessed
        .rings_transactions
        .first_mut()
        .expect("transaction should have a Rings update");
    rings_tx.encrypted_utxos = Some(vec![1, 2, 3]);
    rings_tx.raw_event = Some(vec![4, 5, 6]);
    rings_tx.parse_version = 2;
    only_mut(&mut rings_tx.outputs, "Rings output").payload = vec![7, 8, 9];

    let txn = db.begin().await.unwrap();
    persist_state_update(&txn, reprocessed).await.unwrap();
    txn.commit().await.unwrap();

    assert_eq!(
        rings_transaction_payloads::Entity::find()
            .count(&db)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        rings_output_payloads::Entity::find()
            .count(&db)
            .await
            .unwrap(),
        1
    );

    let tx_payload = rings_transaction_payloads::Entity::find()
        .one(&db)
        .await
        .unwrap()
        .expect("transaction payload should exist");
    assert_eq!(tx_payload.encrypted_utxos, Some(vec![1, 2, 3]));
    assert_eq!(tx_payload.raw_event, Some(vec![4, 5, 6]));
    assert_eq!(tx_payload.parse_version, 2);

    let output_payload = rings_output_payloads::Entity::find()
        .one(&db)
        .await
        .unwrap()
        .expect("output payload should exist");
    assert_eq!(output_payload.payload, vec![7, 8, 9]);
}

#[tokio::test]
async fn discovers_rings_tree_account_metadata() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();

    let tree_pubkey = Pubkey::new_unique();
    let slot = 42;
    let mut data = vec![0u8; tree_account_size()];
    let (
        expected_height,
        expected_root_history_capacity,
        expected_input_queue_zkp_batch_size,
        expected_sequence_number,
        expected_next_index,
    ) = {
        let mut tree = TreeAccount::init(
            &mut data,
            TREE_ACCOUNT_DISCRIMINATOR,
            RingsTreeKind::State
                .tree_height()
                .try_into()
                .expect("Rings state tree height must fit in u8"),
            tree_pubkey.to_bytes(),
            address_tree_params(),
        )
        .unwrap();
        let nullifier = tree.nullifier_tree();
        let root_history_capacity = u64::try_from(nullifier.root_history.roots.len())
            .expect("root history length fits in u64");
        (
            nullifier.height,
            root_history_capacity,
            nullifier.queue_batches.zkp_batch_size,
            nullifier.sequence_number,
            nullifier.next_index,
        )
    };
    let mut account = Account {
        lamports: 1_000_000,
        data,
        owner: pda::shielded_pool_program_id(),
        executable: false,
        rent_epoch: 0,
    };

    let discovered = tree_metadata_sync::process_tree_account(&db, tree_pubkey, &mut account, slot)
        .await
        .unwrap();
    assert!(
        discovered,
        "initialized Rings TreeAccount should be discovered"
    );

    let row = tree_metadata::Entity::find_by_id(tree_pubkey.to_bytes().to_vec())
        .one(&db)
        .await
        .unwrap()
        .expect("tree metadata row should be inserted");
    assert_eq!(row.tree_pubkey, tree_pubkey.to_bytes().to_vec());
    assert_eq!(row.queue_pubkey, tree_pubkey.to_bytes().to_vec());
    assert_eq!(row.height, i32::try_from(expected_height).unwrap());
    assert_eq!(
        row.root_history_capacity,
        i64::try_from(expected_root_history_capacity).unwrap()
    );
    assert_eq!(
        row.input_queue_zkp_batch_size,
        i64::try_from(expected_input_queue_zkp_batch_size).unwrap()
    );
    assert_eq!(
        row.sequence_number,
        i64::try_from(expected_sequence_number).unwrap()
    );
    assert_eq!(row.next_index, i64::try_from(expected_next_index).unwrap());
    assert_eq!(row.last_synced_slot, i64::try_from(slot).unwrap());

    let tree_info =
        photon_indexer::ingester::parser::tree_info::TreeInfo::get_by_pubkey(&db, &tree_pubkey)
            .await
            .unwrap()
            .expect("discovered tree should be queryable");
    assert_eq!(tree_info.tree, tree_pubkey);
    assert_eq!(tree_info.queue, tree_pubkey);
    assert_eq!(tree_info.height, expected_height);
    assert_eq!(
        tree_info.root_history_capacity,
        expected_root_history_capacity
    );
    assert_eq!(
        tree_info.input_queue_zkp_batch_size,
        expected_input_queue_zkp_batch_size
    );
}

#[tokio::test]
async fn rings_mode_persists_output_leaf_nodes_without_zk_tables() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(&db, &[PROOFLESS_SHIELD_SLOT]).await;

    let state_update =
        parse_ingestion_update(proofless_shield_transaction_info(), PROOFLESS_SHIELD_SLOT);
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;
    let rings_tx = only(&state_update.rings_transactions, "Rings transaction");
    let output = only(&rings_tx.outputs, "Rings output").clone();

    let txn = db.begin().await.unwrap();
    persist_state_update(&txn, state_update).await.unwrap();
    txn.commit().await.unwrap();

    assert_eq!(rings_outputs::Entity::find().count(&db).await.unwrap(), 1);

    let leaf = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(output.output_tree.to_vec()))
        .filter(state_trees::Column::TreeKind.eq(i32::from(RingsTreeKind::State)))
        .filter(state_trees::Column::LeafIdx.eq(Some(output.leaf_index as i64)))
        .filter(state_trees::Column::Level.eq(0))
        .one(&db)
        .await
        .unwrap()
        .expect("rings output leaf should be persisted to state_trees");
    assert_eq!(leaf.hash, output.utxo_hash.to_vec());

    state_trees::Entity::insert(state_trees::ActiveModel {
        tree: Set(vec![42; 32]),
        tree_kind: Set(i32::from(RingsTreeKind::State)),
        node_idx: Set(42),
        leaf_idx: Set(Some(output.leaf_index as i64)),
        level: Set(0),
        hash: Set(output.utxo_hash.to_vec()),
        seq: Set(Some(0)),
    })
    .exec(&db)
    .await
    .unwrap();

    let response = merkle_proofs_for_test(
        &db,
        GetMerkleProofsRequest {
            tree_account: SerializablePubkey::from(output.output_tree),
            leaves: vec![Hash::from(output.utxo_hash)],
        },
    )
    .await
    .expect("Rings output should return an inclusion proof");
    assert_eq!(response.context.block_time, PROOFLESS_SHIELD_SLOT as i64);
    let proof = only(&response.proofs, "inclusion proof");
    assert_eq!(proof.leaf, Hash::from(output.utxo_hash));
    assert_eq!(proof.leaf_index, output.leaf_index);
    assert_eq!(
        proof.merkle_context.tree,
        SerializablePubkey::from(output.output_tree)
    );
    assert_eq!(
        proof.merkle_context.tree_type,
        u16::from(RingsTreeKind::State)
    );
}

#[tokio::test]
async fn rings_merkle_proofs_reject_duplicate_output_hashes() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(&db, &[PROOFLESS_SHIELD_SLOT]).await;

    let state_update =
        parse_ingestion_update(proofless_shield_transaction_info(), PROOFLESS_SHIELD_SLOT);
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;
    let rings_tx = only(&state_update.rings_transactions, "Rings transaction");
    let output = only(&rings_tx.outputs, "Rings output").clone();

    let txn = db.begin().await.unwrap();
    persist_state_update(&txn, state_update).await.unwrap();
    txn.commit().await.unwrap();

    let rings_tx = rings_transactions::Entity::find()
        .one(&db)
        .await
        .unwrap()
        .expect("rings transaction should be persisted");
    rings_outputs::Entity::insert(rings_outputs::ActiveModel {
        output_id: Default::default(),
        rings_tx_id: Set(rings_tx.rings_tx_id),
        slot: Set(i64::try_from(PROOFLESS_SHIELD_SLOT).unwrap()),
        output_index: Set(1),
        output_tree: Set(output.output_tree.to_vec()),
        leaf_index: Set(i64::try_from(output.leaf_index + 1).unwrap()),
        view_tag: Set(output.view_tag.to_vec()),
        utxo_hash: Set(output.utxo_hash.to_vec()),
        // Copied from the transaction this output belongs to, as the ingester
        // does.
        signature: Set(Some(rings_tx.signature.clone())),
        event_index: Set(Some(rings_tx.event_index)),
    })
    .exec(&db)
    .await
    .unwrap();

    let err = merkle_proofs_for_test(
        &db,
        GetMerkleProofsRequest {
            tree_account: SerializablePubkey::from(output.output_tree),
            leaves: vec![Hash::from(output.utxo_hash)],
        },
    )
    .await
    .expect_err("duplicate output hashes must not produce an ambiguous merkle proof");

    assert!(matches!(
        err,
        PhotonApiError::ValidationError(message)
            if message.contains("is not unique in tree")
    ));
}

#[tokio::test]
async fn rings_merkle_proofs_error_when_output_leaf_node_is_missing() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(&db, &[PROOFLESS_SHIELD_SLOT]).await;

    let state_update =
        parse_ingestion_update(proofless_shield_transaction_info(), PROOFLESS_SHIELD_SLOT);
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;
    let rings_tx = only(&state_update.rings_transactions, "Rings transaction");
    let output = only(&rings_tx.outputs, "Rings output").clone();

    let txn = db.begin().await.unwrap();
    persist_state_update(&txn, state_update).await.unwrap();
    txn.commit().await.unwrap();

    state_trees::Entity::delete_many()
        .filter(state_trees::Column::Tree.eq(output.output_tree.to_vec()))
        .filter(state_trees::Column::TreeKind.eq(i32::from(RingsTreeKind::State)))
        .filter(state_trees::Column::LeafIdx.eq(Some(output.leaf_index as i64)))
        .filter(state_trees::Column::Level.eq(0))
        .exec(&db)
        .await
        .unwrap();

    let err = merkle_proofs_for_test(
        &db,
        GetMerkleProofsRequest {
            tree_account: SerializablePubkey::from(output.output_tree),
            leaves: vec![Hash::from(output.utxo_hash)],
        },
    )
    .await
    .expect_err("known output without state-tree leaf must not return a zero-leaf proof");

    assert!(matches!(
        err,
        PhotonApiError::UnexpectedError(message)
            if message.contains("Missing state-tree leaf for expected leaf index")
    ));
}

#[tokio::test]
async fn rings_merkle_proofs_error_when_state_leaf_hash_diverges_from_output_hash() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(&db, &[PROOFLESS_SHIELD_SLOT]).await;

    let state_update =
        parse_ingestion_update(proofless_shield_transaction_info(), PROOFLESS_SHIELD_SLOT);
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;
    let rings_tx = only(&state_update.rings_transactions, "Rings transaction");
    let output = only(&rings_tx.outputs, "Rings output").clone();

    let txn = db.begin().await.unwrap();
    persist_state_update(&txn, state_update).await.unwrap();
    txn.commit().await.unwrap();

    let state_leaf = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(output.output_tree.to_vec()))
        .filter(state_trees::Column::TreeKind.eq(i32::from(RingsTreeKind::State)))
        .filter(state_trees::Column::LeafIdx.eq(Some(output.leaf_index as i64)))
        .filter(state_trees::Column::Level.eq(0))
        .one(&db)
        .await
        .unwrap()
        .expect("state leaf should exist before corruption");
    let mut state_leaf: state_trees::ActiveModel = state_leaf.into();
    state_leaf.hash = Set([42u8; 32].to_vec());
    state_trees::Entity::update(state_leaf)
        .exec(&db)
        .await
        .unwrap();

    let err = merkle_proofs_for_test(
        &db,
        GetMerkleProofsRequest {
            tree_account: SerializablePubkey::from(output.output_tree),
            leaves: vec![Hash::from(output.utxo_hash)],
        },
    )
    .await
    .expect_err("state-tree hash divergence must not return proof for requested output hash");

    assert!(matches!(
        err,
        PhotonApiError::UnexpectedError(message)
            if message.contains("did not match requested leaf")
    ));
}

#[tokio::test]
async fn rings_non_inclusion_accepts_known_tree_account_from_outputs() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(&db, &[PROOFLESS_SHIELD_SLOT]).await;

    let state_update =
        parse_ingestion_update(proofless_shield_transaction_info(), PROOFLESS_SHIELD_SLOT);
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;
    let rings_tx = only(&state_update.rings_transactions, "Rings transaction");
    let output_tree = only(&rings_tx.outputs, "Rings output").output_tree;

    let txn = db.begin().await.unwrap();
    persist_state_update(&txn, state_update).await.unwrap();
    txn.commit().await.unwrap();

    let response = get_non_inclusion_proofs(
        &db,
        GetNonInclusionProofsRequest {
            tree_account: SerializablePubkey::from(output_tree),
            leaves: vec![Hash::from([9u8; 32])],
        },
    )
    .await
    .expect("known Rings TreeAccount should support nullifier empty-tree proofs");

    assert_eq!(response.context.block_time, PROOFLESS_SHIELD_SLOT as i64);
    let proof = only(&response.proofs, "non-inclusion proof");
    assert_eq!(
        proof.merkle_context.tree,
        SerializablePubkey::from(output_tree)
    );
    assert_eq!(
        proof.merkle_context.tree_type,
        u16::from(RingsTreeKind::Nullifier)
    );
    assert_eq!(
        proof.path.len(),
        RingsTreeKind::Nullifier.tree_height() as usize
    );
    assert_eq!(proof.low_element_index, 0);
    assert_eq!(proof.high_element_index, 0);
    assert_eq!(proof.root_seq, 0);
    assert_eq!(proof.root_index, 0);
}

#[tokio::test]
async fn rings_state_and_nullifier_nodes_do_not_collide_for_same_tree_account() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(&db, &[SHIELDED_TRANSFER_SLOT]).await;

    let state_update =
        parse_ingestion_update(shielded_transfer_transaction_info(), SHIELDED_TRANSFER_SLOT);
    let tx = only(&state_update.rings_transactions, "Rings transaction");
    let tree = Pubkey::from(tx.output_tree);
    assert!(tx
        .outputs
        .iter()
        .all(|output| output.output_tree == tree.to_bytes()));
    assert!(tx
        .nullifiers
        .iter()
        .all(|nullifier| nullifier.nullifier_tree == tree.to_bytes()));

    let nullifier = tx
        .nullifiers
        .first()
        .expect("Rings transaction should have a queued nullifier")
        .nullifier;
    let expected_zeroeth = get_zeroeth_nullifier_exclusion_range(tree.to_bytes().to_vec());
    let zeroeth_leaf = RawIndexedElement {
        value: expected_zeroeth.value.clone().try_into().unwrap(),
        next_index: 1,
        next_value: nullifier,
        index: 0,
    };
    let zeroeth_leaf_model = indexed_trees::Model {
        tree: tree.to_bytes().to_vec(),
        leaf_index: zeroeth_leaf.index as i64,
        value: zeroeth_leaf.value.to_vec(),
        next_index: zeroeth_leaf.next_index as i64,
        next_value: zeroeth_leaf.next_value.to_vec(),
        seq: Some(1),
    };
    let zeroeth_leaf_hash = compute_nullifier_range_node_hash(&zeroeth_leaf_model).unwrap();
    let indexed_leaf = RawIndexedElement {
        value: nullifier,
        next_index: 0,
        next_value: expected_zeroeth.next_value.clone().try_into().unwrap(),
        index: 1,
    };
    let indexed_leaf_model = indexed_trees::Model {
        tree: tree.to_bytes().to_vec(),
        leaf_index: indexed_leaf.index as i64,
        value: indexed_leaf.value.to_vec(),
        next_index: indexed_leaf.next_index as i64,
        next_value: indexed_leaf.next_value.to_vec(),
        seq: Some(2),
    };
    let indexed_leaf_hash = compute_nullifier_range_node_hash(&indexed_leaf_model).unwrap();

    let mut indexed_updates = HashMap::new();
    indexed_updates.insert(
        (tree, zeroeth_leaf.index as u64),
        IndexedTreeLeafUpdate {
            tree,
            tree_kind: RingsTreeKind::Nullifier,
            leaf: zeroeth_leaf,
            hash: zeroeth_leaf_hash.0,
            seq: 1,
            signature: Signature::default(),
        },
    );
    indexed_updates.insert(
        (tree, indexed_leaf.index as u64),
        IndexedTreeLeafUpdate {
            tree,
            tree_kind: RingsTreeKind::Nullifier,
            leaf: indexed_leaf,
            hash: indexed_leaf_hash.0,
            seq: 2,
            signature: Signature::default(),
        },
    );

    insert_known_rings_tree_account(&db, tree.to_bytes()).await;
    let output = tx
        .outputs
        .first()
        .expect("Rings transaction should have an output")
        .clone();

    let txn = db.begin().await.unwrap();
    persist_state_update(&txn, state_update).await.unwrap();
    persist_indexed_tree_updates(&txn, indexed_updates, &test_tree_info_cache(tree))
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let raw_tree = tree.to_bytes().to_vec();
    let raw_tree_nodes = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(raw_tree.clone()))
        .all(&db)
        .await
        .unwrap();
    assert!(!raw_tree_nodes.is_empty());
    assert!(raw_tree_nodes
        .iter()
        .any(|node| node.tree_kind == i32::from(RingsTreeKind::State)));
    assert!(raw_tree_nodes
        .iter()
        .any(|node| node.tree_kind == i32::from(RingsTreeKind::Nullifier)));

    let state_leaf = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(raw_tree.clone()))
        .filter(state_trees::Column::TreeKind.eq(i32::from(RingsTreeKind::State)))
        .filter(state_trees::Column::LeafIdx.eq(Some(output.leaf_index as i64)))
        .filter(state_trees::Column::Level.eq(0))
        .one(&db)
        .await
        .unwrap()
        .expect("state leaf should be stored under state storage key");
    assert_eq!(state_leaf.hash, output.utxo_hash.to_vec());

    let nullifier_leaf = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(raw_tree.clone()))
        .filter(state_trees::Column::TreeKind.eq(i32::from(RingsTreeKind::Nullifier)))
        .filter(state_trees::Column::LeafIdx.eq(Some(indexed_leaf_model.leaf_index)))
        .filter(state_trees::Column::Level.eq(0))
        .one(&db)
        .await
        .unwrap()
        .expect("nullifier leaf should be stored under nullifier storage key");
    assert_eq!(nullifier_leaf.hash, indexed_leaf_hash.to_vec());

    let state_root = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(raw_tree.clone()))
        .filter(state_trees::Column::TreeKind.eq(i32::from(RingsTreeKind::State)))
        .filter(state_trees::Column::NodeIdx.eq(1))
        .one(&db)
        .await
        .unwrap()
        .expect("state root should be stored");
    let nullifier_root = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(raw_tree))
        .filter(state_trees::Column::TreeKind.eq(i32::from(RingsTreeKind::Nullifier)))
        .filter(state_trees::Column::NodeIdx.eq(1))
        .one(&db)
        .await
        .unwrap()
        .expect("nullifier root should be stored");
    assert_ne!(state_root.hash, nullifier_root.hash);

    let inclusion_response = merkle_proofs_for_test(
        &db,
        GetMerkleProofsRequest {
            tree_account: SerializablePubkey::from(tree),
            leaves: vec![Hash::from(output.utxo_hash)],
        },
    )
    .await
    .expect("state inclusion proof should use state storage key");
    let inclusion_proof = only(&inclusion_response.proofs, "inclusion proof");
    assert_eq!(
        inclusion_proof.merkle_context.tree,
        SerializablePubkey::from(tree)
    );
    assert_eq!(
        inclusion_proof.merkle_context.tree_type,
        u16::from(RingsTreeKind::State)
    );

    let mut proof_leaf = nullifier.to_vec();
    for byte in proof_leaf.iter_mut().rev() {
        if *byte < u8::MAX {
            *byte += 1;
            break;
        }
    }
    let non_inclusion_response = get_non_inclusion_proofs(
        &db,
        GetNonInclusionProofsRequest {
            tree_account: SerializablePubkey::from(tree),
            leaves: vec![Hash::try_from(proof_leaf).unwrap()],
        },
    )
    .await
    .expect("nullifier non-inclusion proof should use nullifier storage key");
    let non_inclusion_proof = only(&non_inclusion_response.proofs, "non-inclusion proof");
    assert_eq!(
        non_inclusion_proof.merkle_context.tree,
        SerializablePubkey::from(tree)
    );
    assert_eq!(
        non_inclusion_proof.merkle_context.tree_type,
        u16::from(RingsTreeKind::Nullifier)
    );

    let present_value_error = get_non_inclusion_proofs(
        &db,
        GetNonInclusionProofsRequest {
            tree_account: SerializablePubkey::from(tree),
            leaves: vec![Hash::from(nullifier)],
        },
    )
    .await
    .expect_err("present nullifier should not return a non-inclusion proof");
    assert!(matches!(
        present_value_error,
        PhotonApiError::ValidationError(message)
            if message.contains("already used or queued")
    ));
}

#[tokio::test]
async fn rings_api_returns_empty_non_inclusion_proofs_for_known_nullifier_tree() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(&db, &[SHIELDED_TRANSFER_SLOT]).await;

    let state_update =
        parse_ingestion_update(shielded_transfer_transaction_info(), SHIELDED_TRANSFER_SLOT);
    let rings_tx = only(&state_update.rings_transactions, "Rings transaction");
    let nullifier = rings_tx
        .nullifiers
        .first()
        .expect("Rings transaction should have a queued nullifier");
    let nullifier_tree = nullifier.nullifier_tree;
    let queued_nullifier = nullifier.nullifier;
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;

    let txn = db.begin().await.unwrap();
    persist_state_update(&txn, state_update).await.unwrap();
    txn.commit().await.unwrap();
    insert_known_rings_tree_account(&db, nullifier_tree).await;

    let queued_value_error = get_non_inclusion_proofs(
        &db,
        GetNonInclusionProofsRequest {
            tree_account: SerializablePubkey::from(nullifier_tree),
            leaves: vec![Hash::from(queued_nullifier)],
        },
    )
    .await
    .expect_err("known nullifier should not return a non-inclusion proof");
    assert!(matches!(
        queued_value_error,
        PhotonApiError::ValidationError(message)
            if message.contains("already used or queued")
    ));

    let leaves = vec![Hash::from([9u8; 32]), Hash::from([10u8; 32])];
    let response = get_non_inclusion_proofs(
        &db,
        GetNonInclusionProofsRequest {
            tree_account: SerializablePubkey::from(nullifier_tree),
            leaves: leaves.clone(),
        },
    )
    .await
    .expect("known Rings nullifier tree should return empty-tree proofs");

    assert_eq!(response.context.block_time, SHIELDED_TRANSFER_SLOT as i64);
    assert_eq!(response.proofs.len(), leaves.len());
    assert_eq!(
        response
            .proofs
            .iter()
            .map(|proof| proof.leaf.clone())
            .collect::<Vec<_>>(),
        leaves
    );
    for proof in response.proofs {
        assert_eq!(
            proof.merkle_context.tree,
            SerializablePubkey::from(nullifier_tree)
        );
        assert_eq!(
            proof.merkle_context.tree_type,
            u16::from(RingsTreeKind::Nullifier)
        );
        assert_eq!(proof.path.len(), 40);
        assert_eq!(proof.low_element_index, 0);
        assert_eq!(proof.high_element_index, 0);
        assert_eq!(proof.root_seq, 0);
        assert_eq!(proof.root_index, 0);
    }
}

#[tokio::test]
async fn rings_api_returns_empty_non_inclusion_proofs_before_any_nullifier_rows() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(&db, &[SHIELDED_TRANSFER_SLOT]).await;

    let nullifier_tree = Pubkey::new_unique();
    insert_known_rings_tree_account(&db, nullifier_tree.to_bytes()).await;

    assert_eq!(
        rings_tx_nullifiers::Entity::find()
            .filter(
                rings_tx_nullifiers::Column::NullifierTree.eq(nullifier_tree.to_bytes().to_vec())
            )
            .count(&db)
            .await
            .unwrap(),
        0
    );

    let leaves = vec![Hash::from([11u8; 32]), Hash::from([12u8; 32])];
    let response = get_non_inclusion_proofs(
        &db,
        GetNonInclusionProofsRequest {
            tree_account: SerializablePubkey::from(nullifier_tree),
            leaves: leaves.clone(),
        },
    )
    .await
    .expect("known empty Rings nullifier tree should return empty-tree proofs");

    assert_eq!(response.context.block_time, SHIELDED_TRANSFER_SLOT as i64);
    assert_eq!(response.proofs.len(), leaves.len());
    for proof in response.proofs {
        assert_eq!(
            proof.merkle_context.tree,
            SerializablePubkey::from(nullifier_tree)
        );
        assert_eq!(
            proof.merkle_context.tree_type,
            u16::from(RingsTreeKind::Nullifier)
        );
        assert_eq!(
            proof.path.len(),
            RingsTreeKind::Nullifier.tree_height() as usize
        );
        assert_eq!(proof.root_seq, 0);
    }
}

#[tokio::test]
async fn rings_mode_persists_non_empty_nullifier_tree_with_proof_layout() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(&db, &[SHIELDED_TRANSFER_SLOT]).await;

    let nullifier_tree = [
        176, 13, 46, 20, 237, 226, 238, 163, 75, 77, 142, 112, 107, 92, 140, 192, 97, 37, 8, 160,
        74, 94, 83, 128, 126, 112, 192, 111, 142, 125, 179, 137,
    ];
    insert_known_rings_tree_account(&db, nullifier_tree).await;
    let expected_zeroeth = get_zeroeth_nullifier_exclusion_range(nullifier_tree.to_vec());
    let next_value: [u8; 32] = expected_zeroeth.next_value.clone().try_into().unwrap();
    let indexed_leaf = RawIndexedElement {
        value: [5; 32],
        next_index: 0,
        next_value,
        index: 1,
    };
    let indexed_leaf_model = indexed_trees::Model {
        tree: nullifier_tree.to_vec(),
        leaf_index: indexed_leaf.index as i64,
        value: indexed_leaf.value.to_vec(),
        next_index: indexed_leaf.next_index as i64,
        next_value: indexed_leaf.next_value.to_vec(),
        seq: Some(1),
    };
    let indexed_leaf_hash = compute_nullifier_range_node_hash(&indexed_leaf_model).unwrap();
    let tree = Pubkey::from(nullifier_tree);
    let indexed_updates = HashMap::from([(
        (tree, indexed_leaf.index as u64),
        IndexedTreeLeafUpdate {
            tree,
            tree_kind: RingsTreeKind::Nullifier,
            leaf: indexed_leaf,
            hash: indexed_leaf_hash.0,
            seq: 1,
            signature: Signature::default(),
        },
    )]);

    let txn = db.begin().await.unwrap();
    persist_indexed_tree_updates(&txn, indexed_updates, &test_tree_info_cache(tree))
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let zeroeth = indexed_trees::Entity::find()
        .filter(indexed_trees::Column::Tree.eq(nullifier_tree.to_vec()))
        .filter(indexed_trees::Column::LeafIndex.eq(0))
        .one(&db)
        .await
        .unwrap()
        .expect("nullifier zeroeth range should be persisted");
    assert_eq!(zeroeth.value, expected_zeroeth.value);
    assert_eq!(zeroeth.next_index, expected_zeroeth.next_index);
    assert_eq!(zeroeth.next_value, expected_zeroeth.next_value);

    let indexed_leaf = indexed_trees::Entity::find()
        .filter(indexed_trees::Column::Tree.eq(nullifier_tree.to_vec()))
        .filter(indexed_trees::Column::LeafIndex.gt(0))
        .order_by_asc(indexed_trees::Column::LeafIndex)
        .one(&db)
        .await
        .unwrap()
        .expect("non-empty nullifier range should be persisted");
    let state_leaf = state_trees::Entity::find()
        .filter(
            state_trees::Column::Tree
                .eq(nullifier_tree.to_vec())
                .and(state_trees::Column::TreeKind.eq(i32::from(RingsTreeKind::Nullifier))),
        )
        .filter(state_trees::Column::LeafIdx.eq(Some(indexed_leaf.leaf_index)))
        .filter(state_trees::Column::Level.eq(0))
        .one(&db)
        .await
        .unwrap()
        .expect("nullifier range leaf should be persisted to state_trees");
    let expected_node_idx =
        2_i64.pow(RingsTreeKind::Nullifier.tree_height()) + indexed_leaf.leaf_index;
    assert_eq!(state_leaf.node_idx, expected_node_idx);

    let proof_txn = db.begin().await.unwrap();
    let proof_leaf = vec![6; 32];
    let proof_map = get_multiple_indexed_exclusion_ranges_with_custom_empty_proofs(
        &proof_txn,
        nullifier_tree.to_vec(),
        RingsTreeKind::Nullifier.tree_height() + 1,
        vec![proof_leaf.clone()],
        RingsTreeKind::Nullifier,
        Some(expected_zeroeth),
    )
    .await
    .expect("known non-empty Rings nullifier tree should return a proof");
    proof_txn.commit().await.unwrap();
    let (range, proof) = proof_map
        .get(&proof_leaf)
        .expect("proof should be returned for requested leaf");
    assert_eq!(range.leaf_index, indexed_leaf.leaf_index);
    assert_eq!(proof.proof.len(), 40);
    proof.validate().unwrap();
}

async fn assert_rings_api_exposes_output_hashes(
    db: &DatabaseConnection,
    output: &rings_outputs::Model,
) {
    let payload = rings_output_payloads::Entity::find_by_id(output.output_id)
        .one(db)
        .await
        .unwrap()
        .expect("output payload should exist");
    let request = GetRingsByTagsRequest {
        tags: vec![Hash::try_from(output.view_tag.clone()).unwrap()],
        cursor: None,
        limit: None,
        ring_program_id: None,
    };

    let shielded = get_shielded_transactions_by_tags(db, request.clone())
        .await
        .unwrap();
    assert_eq!(shielded.context.block_time, UNSHIELD_SLOT as i64);
    // A non-empty page carries the position of its last row even when it is
    // short, so a client can resume from the tip rather than rescan. The stream
    // ends on the next page, which comes back empty.
    assert!(shielded.next_cursor.is_some());
    assert!(!shielded.transactions.is_empty());
    let output_slot = shielded
        .transactions
        .iter()
        .flat_map(|tx| tx.output_slots.iter())
        .find(|slot| slot.output_context.hash.to_vec() == output.utxo_hash)
        .expect("matched output slot should be returned");
    assert_eq!(output_slot.view_tag.to_vec(), output.view_tag);
    assert_eq!(
        output_slot.output_context.tree.to_bytes_vec(),
        output.output_tree
    );
    assert_eq!(
        output_slot.output_context.leaf_index,
        output.leaf_index as u64
    );
    assert_eq!(output_slot.payload.0, payload.payload);

    let rings_tx = rings_transactions::Entity::find_by_id(output.rings_tx_id)
        .one(db)
        .await
        .unwrap()
        .expect("rings transaction should exist");

    // The tag queries ORDER BY these copies. The columns are nullable, so an
    // ingester that stopped writing them would leave rows sorting last and
    // paging in an order the cursor cannot follow, with nothing else failing.
    assert_eq!(
        output.signature.as_deref(),
        Some(rings_tx.signature.as_slice()),
        "the output must carry its transaction's signature"
    );
    assert_eq!(
        output.event_index,
        Some(rings_tx.event_index),
        "the output must carry its transaction's event index"
    );

    let signature = Signature::from(
        <[u8; 64]>::try_from(rings_tx.signature.as_slice()).expect("stored signature length"),
    );
    let direct = get_shielded_transactions_by_signature(
        db,
        GetShieldedTransactionsBySignatureRequest {
            tx_signature: SerializableSignature(signature),
        },
    )
    .await
    .unwrap();
    let indexed = direct
        .transactions
        .first()
        .expect("one indexed Rings event for the signature");
    assert_eq!(direct.transactions.len(), 1);
    assert_eq!(
        indexed.event_index,
        u16::try_from(rings_tx.event_index).expect("event index is non-negative")
    );
    assert_eq!(indexed.transaction.tx_signature.0, signature);

    let encrypted = get_encrypted_utxos_by_tags(db, request).await.unwrap();
    assert_eq!(encrypted.context.block_time, UNSHIELD_SLOT as i64);
    assert!(encrypted.next_cursor.is_some());
    assert!(!encrypted.matches.is_empty());
    let encrypted_match = encrypted
        .matches
        .iter()
        .find(|match_| match_.output_slot.view_tag.to_vec() == output.view_tag)
        .expect("matched encrypted UTXO should be returned");
    assert_eq!(
        encrypted_match.output_slot.view_tag.to_vec(),
        output.view_tag
    );
    assert_eq!(
        encrypted_match.output_slot.output_context.hash.to_vec(),
        output.utxo_hash
    );
    assert_eq!(
        encrypted_match
            .output_slot
            .output_context
            .tree
            .to_bytes_vec(),
        output.output_tree
    );
    assert_eq!(
        encrypted_match.output_slot.output_context.leaf_index,
        output.leaf_index as u64
    );
    assert_eq!(encrypted_match.output_slot.payload.0, payload.payload);
}

async fn insert_test_blocks(db: &sea_orm::DatabaseConnection, slots: &[u64]) {
    let block_models = slots
        .iter()
        .map(|slot| blocks::ActiveModel {
            slot: Set(*slot as i64),
            parent_slot: Set(*slot as i64 - 1),
            parent_blockhash: Set(vec![0; 32]),
            blockhash: Set(vec![*slot as u8; 32]),
            block_height: Set(*slot as i64),
            block_time: Set(*slot as i64),
        })
        .collect::<Vec<_>>();

    blocks::Entity::insert_many(block_models)
        .exec(db)
        .await
        .unwrap();
}

async fn insert_known_rings_tree_accounts_from_outputs(
    db: &DatabaseConnection,
    state_update: &StateUpdate,
) {
    let trees = state_update
        .rings_transactions
        .iter()
        .flat_map(|tx| tx.outputs.iter().map(|output| output.output_tree))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter();

    insert_known_rings_tree_accounts(db, trees).await;
}

async fn insert_known_rings_tree_account(db: &DatabaseConnection, tree: [u8; 32]) {
    insert_known_rings_tree_accounts(db, [tree]).await;
}

async fn insert_known_rings_tree_accounts(
    db: &DatabaseConnection,
    trees: impl IntoIterator<Item = [u8; 32]>,
) {
    let rows = trees
        .into_iter()
        .map(known_rings_tree_account_metadata)
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return;
    }

    tree_metadata::Entity::insert_many(rows)
        .on_conflict(
            OnConflict::column(tree_metadata::Column::TreePubkey)
                .update_columns([
                    tree_metadata::Column::QueuePubkey,
                    tree_metadata::Column::Height,
                    tree_metadata::Column::RootHistoryCapacity,
                    tree_metadata::Column::InputQueueZkpBatchSize,
                    tree_metadata::Column::SequenceNumber,
                    tree_metadata::Column::NextIndex,
                    tree_metadata::Column::LastSyncedSlot,
                ])
                .to_owned(),
        )
        .exec(db)
        .await
        .unwrap();
}

fn known_rings_tree_account_metadata(tree: [u8; 32]) -> tree_metadata::ActiveModel {
    tree_metadata::ActiveModel {
        tree_pubkey: Set(tree.to_vec()),
        queue_pubkey: Set(tree.to_vec()),
        height: Set(RingsTreeKind::Nullifier.tree_height() as i32),
        root_history_capacity: Set(RingsTreeKind::Nullifier.root_history_capacity() as i64),
        input_queue_zkp_batch_size: Set(i64::try_from(
            zolana_interface::state::ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
        )
        .unwrap()),
        sequence_number: Set(0),
        next_index: Set(0),
        last_synced_slot: Set(0),
    }
}

fn test_tree_info_cache(tree: Pubkey) -> HashMap<Pubkey, TreeInfo> {
    HashMap::from([(
        tree,
        TreeInfo {
            tree,
            queue: tree,
            height: RingsTreeKind::Nullifier.tree_height(),
            root_history_capacity: RingsTreeKind::Nullifier.root_history_capacity(),
            input_queue_zkp_batch_size:
                zolana_interface::state::ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
        },
    )])
}

fn parse_rings_update(tx_info: TransactionInfo, slot: u64) -> StateUpdate {
    parse_rings_events(&tx_info, slot)
        .expect("rings parser should not fail")
        .expect("transaction should contain a rings event")
}

fn parse_ingestion_update(tx_info: TransactionInfo, slot: u64) -> StateUpdate {
    let mut state_update = parse_rings_events(&tx_info, slot)
        .expect("rings parser should not fail")
        .expect("transaction should contain a rings event");
    state_update.transactions.insert(Transaction {
        signature: tx_info.signature,
        slot,
        error: tx_info.error,
    });
    state_update
}

fn proofless_shield_transaction_info() -> TransactionInfo {
    rings_transaction_info(
        1,
        tag::DEPOSIT,
        EventKind::Deposit,
        GeneralEvent {
            inputs: Vec::new(),
            outputs: vec![test_output(1, 11, proofless_output_payload())],
            messages: Vec::new(),
            tx_viewing_pk: [0; 33],
            salt: [0; 16],
            first_output_leaf_index: 0,
            output_tree: TEST_TREE,
            spl_transfers: vec![SplTransfer {
                is_deposit: true,
                amount: 100,
                asset: None,
            }],
        },
    )
}

fn proofless_output_payload() -> Vec<u8> {
    encode_output_data(ProoflessOutput {
        owner: [1; 32],
        blinding: {
            let mut blinding = [2; 32];
            blinding[0] = 0;
            blinding
        },
        asset: [0; 32],
        amount: 100,
        data_hash: None,
        utxo_data: None,
        ring_program_id: None,
        ring_data_hash: None,
        ring_data: None,
        memo: None,
    })
}

fn shielded_transfer_transaction_info() -> TransactionInfo {
    rings_transaction_info(
        2,
        tag::TRANSACT,
        EventKind::Transact,
        GeneralEvent {
            inputs: vec![test_input(0, 21), test_input(1, 22)],
            outputs: vec![
                test_output(2, 12, Vec::new()),
                test_output(3, 13, Vec::new()),
                test_output(4, 14, Vec::new()),
            ],
            messages: Vec::new(),
            tx_viewing_pk: [0; 33],
            salt: [0; 16],
            first_output_leaf_index: 1,
            output_tree: TEST_TREE,
            spl_transfers: Vec::new(),
        },
    )
}

fn unshield_transaction_info() -> TransactionInfo {
    rings_transaction_info(
        3,
        tag::TRANSACT,
        EventKind::Transact,
        GeneralEvent {
            inputs: vec![test_input(2, 23), test_input(3, 24)],
            outputs: vec![
                test_output(5, 15, Vec::new()),
                test_output(6, 16, Vec::new()),
                test_output(7, 17, Vec::new()),
            ],
            messages: Vec::new(),
            tx_viewing_pk: [0; 33],
            salt: [0; 16],
            first_output_leaf_index: 4,
            output_tree: TEST_TREE,
            spl_transfers: vec![SplTransfer {
                is_deposit: false,
                amount: 40,
                asset: None,
            }],
        },
    )
}

fn encrypted_transfer_transaction_info() -> TransactionInfo {
    rings_transaction_info(
        4,
        tag::TRANSACT,
        EventKind::Transact,
        GeneralEvent {
            inputs: vec![test_input(4, 25), test_input(5, 26)],
            outputs: vec![
                test_output(8, 18, encode_verifiably_encrypted(vec![1, 2, 3])),
                test_output(9, 19, encode_verifiably_encrypted(vec![4, 5, 6])),
                test_output(10, 20, encode_verifiably_encrypted(vec![7, 8, 9])),
            ],
            messages: Vec::new(),
            tx_viewing_pk: [5; 33],
            salt: [6; 16],
            first_output_leaf_index: 2,
            output_tree: TEST_TREE,
            spl_transfers: Vec::new(),
        },
    )
}

fn rings_transaction_info(
    signature_byte: u8,
    source_instruction_tag: u8,
    event_kind: EventKind,
    event: GeneralEvent,
) -> TransactionInfo {
    let program_id = pda::shielded_pool_program_id();
    TransactionInfo {
        instruction_groups: vec![InstructionGroup {
            outer_instruction: Instruction {
                program_id,
                accounts: Vec::new(),
                data: vec![source_instruction_tag],
                stack_height: Some(1),
            },
            inner_instructions: vec![Instruction {
                program_id,
                accounts: Vec::new(),
                data: encode_event_instruction(event_kind, event),
                stack_height: Some(2),
            }],
        }],
        signature: Signature::from([signature_byte; 64]),
        error: None,
    }
}

fn test_input(input_queue_seq: u64, nullifier_byte: u8) -> Input {
    Input {
        tree: TEST_TREE,
        input_queue_seq,
        nullifier: [nullifier_byte; 32],
    }
}

fn test_output(view_tag_byte: u8, utxo_hash_byte: u8, data: Vec<u8>) -> OutputUtxo {
    OutputUtxo {
        view_tag: [view_tag_byte; 32],
        utxo_hash: [utxo_hash_byte; 32],
        data,
    }
}

fn expected_output(
    output_index: i16,
    leaf_index: u64,
    view_tag_byte: u8,
    utxo_hash_byte: u8,
    payload: Vec<u8>,
) -> RingsOutputUpdate {
    RingsOutputUpdate {
        output_index,
        output_tree: TEST_TREE,
        leaf_index,
        view_tag: [view_tag_byte; 32],
        utxo_hash: [utxo_hash_byte; 32],
        payload,
    }
}

fn expected_nullifier(
    input_index: i16,
    input_queue_seq: u64,
    nullifier_byte: u8,
) -> RingsNullifierUpdate {
    RingsNullifierUpdate {
        input_index,
        nullifier_tree: TEST_TREE,
        input_queue_seq,
        nullifier: [nullifier_byte; 32],
    }
}

fn batch_update_transaction_info(tree: Pubkey) -> TransactionInfo {
    let data = BatchUpdateNullifierTreeData {
        new_root: [9; 32],
        old_root: [8; 32],
        zkp_batch_index: 0,
        compressed_proof: CompressedProof {
            a: [1; 32],
            b: [2; 64],
            c: [3; 32],
        },
    };
    let instruction = Instruction {
        program_id: pda::shielded_pool_program_id(),
        accounts: vec![Pubkey::new_unique(), pda::protocol_config(), tree],
        data: encode_instruction(tag::BATCH_UPDATE_NULLIFIER_TREE, &data),
        stack_height: None,
    };

    TransactionInfo {
        instruction_groups: vec![InstructionGroup {
            outer_instruction: instruction,
            inner_instructions: Vec::new(),
        }],
        signature: Signature::from([7; 64]),
        error: None,
    }
}

/// Proof helper for tests: seeds the root-index cache from the tree photon just
/// built, so the proof path resolves an index without an RPC endpoint. The
/// index itself is not what these tests are about.
async fn merkle_proofs_for_test(
    db: &sea_orm::DatabaseConnection,
    request: GetMerkleProofsRequest,
) -> Result<zolana_indexer_api::GetMerkleProofsResponse, photon_indexer::api::error::PhotonApiError>
{
    use photon_indexer::api::root_index_cache::RootIndexCache;
    use photon_indexer::dao::generated::state_trees;

    let tree = solana_pubkey::Pubkey::from(request.tree_account.0.to_bytes());
    let roots = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(tree.to_bytes().to_vec()))
        .filter(state_trees::Column::NodeIdx.eq(1))
        .all(db)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|node| <[u8; 32]>::try_from(node.hash.as_slice()).ok())
        .enumerate()
        .filter_map(|(index, root)| u16::try_from(index).ok().map(|index| (index, root)))
        .collect::<Vec<_>>();

    let cache = RootIndexCache::with_roots(tree, roots);
    let rpc = photon_indexer::rpc::RpcClient::new("http://127.0.0.1:1".to_string());
    get_merkle_proofs(db, &rpc, &cache, request).await
}
