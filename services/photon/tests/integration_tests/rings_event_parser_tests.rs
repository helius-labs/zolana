use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use photon_indexer::{
    api::{
        error::PhotonApiError,
        method::rings::{
            get_encrypted_utxos_by_tags, get_merkle_proofs, get_non_inclusion_proofs,
            get_shielded_transactions_by_tags,
        },
    },
    common::rings_tree::RingsTreeKind,
    dao::generated::{
        blocks, indexed_trees, rings_output_payloads, rings_outputs, rings_transaction_payloads,
        rings_transactions, rings_tx_nullifiers, state_trees, transactions, tree_metadata,
    },
    ingester::{
        parser::{
            rings_event_parser::parse_rings_events,
            state_update::{IndexedTreeLeafUpdate, RawIndexedElement, StateUpdate, Transaction},
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
use serde_json::Value;
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_indexer_api::{
    GetMerkleProofsRequest, GetNonInclusionProofsRequest, GetRingsByTagsRequest, Hash,
    SerializablePubkey,
};
use zolana_interface::{
    instruction::{encode_instruction, tag, BatchUpdateNullifierTreeData, CompressedProof},
    pda,
    state::{address_tree_params, discriminator::TREE_ACCOUNT_DISCRIMINATOR, tree_account_size},
};
use zolana_tree::TreeAccount;

const PROOFLESS_SHIELD_SIGNATURE: &str =
    "3JAHH578NVLSh6Z3x2tXnNV4U9digpQb5CsFLrfac6fRNRCNQaRVsWNNrdQUT8PzUEw2MH78MkuKCZxqDoLKqNcX";
const SHIELDED_TRANSFER_SIGNATURE: &str =
    "qjZhjGetrXJi74X726iYy773k4F5mZn4LymuywQi16FrqmZnRLcDNG7QyMgKps5jQwUUtk3JUsU5krji8iQX5oG";
const UNSHIELD_SIGNATURE: &str =
    "5irBHErycm6bDSSa8pi3HBJLYBBScsAkvYBq6UZNH2U5eGCFb4vVqnNDKPdWkEWRwWSXC5jvoNrQSca1ckJipriB";
const ENCRYPTED_TRANSFER_SIGNATURE: &str =
    "4FyvNoXWBkJp7Paf63aWpQRWR4jeEZAHYW86akuTxzSxcdA15DJTtJsAbHeRm821b73cd1zQvmiwxueeQPZn3GHd";
const PROOFLESS_SHIELD_SLOT: u64 = 23;
const SHIELDED_TRANSFER_SLOT: u64 = 25;
const UNSHIELD_SLOT: u64 = 28;
const ENCRYPTED_TRANSFER_SLOT: u64 = 19;

#[test]
fn parses_dumped_proofless_shield_event_with_photon_parser() {
    let state_update = parse_dumped_rings_update(PROOFLESS_SHIELD_SIGNATURE, PROOFLESS_SHIELD_SLOT);

    assert_eq!(state_update.rings_transactions.len(), 1);
    let rings_tx = &state_update.rings_transactions[0];
    assert_eq!(rings_tx.source_instruction_tag, tag::DEPOSIT as i16);
    assert_eq!(rings_tx.first_output_leaf_index, 0);
    assert!(rings_tx.tx_viewing_pk.is_none());
    assert!(rings_tx.salt.is_none());
    assert!(rings_tx.proofless);
    assert!(rings_tx.nullifiers.is_empty());
    assert_eq!(rings_tx.outputs.len(), 1);
    assert_eq!(rings_tx.outputs[0].leaf_index, 0);
    assert_eq!(rings_tx.outputs[0].view_tag.len(), 32);
    assert_eq!(rings_tx.outputs[0].utxo_hash.len(), 32);
    assert!(!rings_tx.outputs[0].payload.is_empty());
}

#[test]
fn parses_dumped_shielded_transfer_event_with_photon_parser() {
    let state_update =
        parse_dumped_rings_update(SHIELDED_TRANSFER_SIGNATURE, SHIELDED_TRANSFER_SLOT);

    assert_eq!(state_update.rings_transactions.len(), 1);
    let rings_tx = &state_update.rings_transactions[0];
    assert_eq!(rings_tx.source_instruction_tag, tag::TRANSACT as i16);
    assert_eq!(rings_tx.first_output_leaf_index, 1);
    assert!(rings_tx.tx_viewing_pk.is_none());
    assert!(rings_tx.salt.is_none());
    assert!(!rings_tx.proofless);
    assert_eq!(rings_tx.nullifiers.len(), 2);
    assert_eq!(rings_tx.outputs.len(), 3);
    assert_eq!(
        rings_tx
            .outputs
            .iter()
            .map(|output| output.leaf_index)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(rings_tx
        .outputs
        .iter()
        .all(|output| output.view_tag.len() == 32));
    assert!(rings_tx
        .outputs
        .iter()
        .all(|output| output.utxo_hash.len() == 32));
}

#[test]
fn parses_dumped_encrypted_transfer_event_with_photon_parser() {
    let state_update =
        parse_dumped_rings_update(ENCRYPTED_TRANSFER_SIGNATURE, ENCRYPTED_TRANSFER_SLOT);

    assert_eq!(state_update.rings_transactions.len(), 1);
    let rings_tx = &state_update.rings_transactions[0];
    assert_eq!(rings_tx.source_instruction_tag, tag::TRANSACT as i16);
    assert_eq!(rings_tx.first_output_leaf_index, 2);
    let tx_viewing_pk = rings_tx
        .tx_viewing_pk
        .as_ref()
        .expect("encrypted transfer should include a tx viewing key");
    assert_eq!(tx_viewing_pk.len(), 33);
    assert!(tx_viewing_pk.iter().any(|byte| *byte != 0));
    let salt = rings_tx
        .salt
        .as_ref()
        .expect("encrypted transfer should include a salt");
    assert_eq!(salt.len(), 16);
    assert!(salt.iter().any(|byte| *byte != 0));
    assert!(!rings_tx.proofless);
    assert_eq!(rings_tx.nullifiers.len(), 2);
    assert_eq!(rings_tx.outputs.len(), 3);
    assert_eq!(
        rings_tx
            .outputs
            .iter()
            .map(|output| output.leaf_index)
            .collect::<Vec<_>>(),
        vec![2, 3, 4]
    );
    assert!(rings_tx
        .outputs
        .iter()
        .any(|output| !output.payload.is_empty()));
}

#[test]
fn parses_dumped_unshield_event_with_photon_parser() {
    let state_update = parse_dumped_rings_update(UNSHIELD_SIGNATURE, UNSHIELD_SLOT);

    assert_eq!(state_update.rings_transactions.len(), 1);
    let rings_tx = &state_update.rings_transactions[0];
    assert_eq!(rings_tx.source_instruction_tag, tag::TRANSACT as i16);
    assert_eq!(rings_tx.first_output_leaf_index, 4);
    assert!(rings_tx.tx_viewing_pk.is_none());
    assert!(rings_tx.salt.is_none());
    assert!(!rings_tx.proofless);
    assert_eq!(rings_tx.nullifiers.len(), 2);
    assert_eq!(rings_tx.outputs.len(), 3);
    assert_eq!(
        rings_tx
            .outputs
            .iter()
            .map(|output| output.leaf_index)
            .collect::<Vec<_>>(),
        vec![4, 5, 6]
    );
}

#[test]
fn rings_snapshot_filter_keeps_dumped_rings_transactions() {
    assert!(is_rings_transaction(
        &transaction_info(PROOFLESS_SHIELD_SIGNATURE),
        PROOFLESS_SHIELD_SLOT
    ));
    assert!(is_rings_transaction(
        &transaction_info(SHIELDED_TRANSFER_SIGNATURE),
        SHIELDED_TRANSFER_SLOT
    ));
    assert!(is_rings_transaction(
        &transaction_info(UNSHIELD_SIGNATURE),
        UNSHIELD_SLOT
    ));
    assert!(is_rings_transaction(
        &transaction_info(ENCRYPTED_TRANSFER_SIGNATURE),
        ENCRYPTED_TRANSFER_SLOT
    ));
}

#[test]
fn rings_snapshot_filter_keeps_nullifier_tree_batch_updates() {
    let tx = batch_update_transaction_info(Pubkey::new_unique());

    assert!(!is_rings_transaction(&tx, 1));
    assert!(is_rings_snapshot_transaction(&tx, 1));
}

#[tokio::test]
async fn persists_dumped_rings_events() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(
        &db,
        &[PROOFLESS_SHIELD_SLOT, SHIELDED_TRANSFER_SLOT, UNSHIELD_SLOT],
    )
    .await;

    let state_update = StateUpdate::merge_updates(vec![
        parse_dumped_ingestion_update(PROOFLESS_SHIELD_SIGNATURE, PROOFLESS_SHIELD_SLOT),
        parse_dumped_ingestion_update(SHIELDED_TRANSFER_SIGNATURE, SHIELDED_TRANSFER_SLOT),
        parse_dumped_ingestion_update(UNSHIELD_SIGNATURE, UNSHIELD_SLOT),
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
    let rings_program_id = pda::shielded_pool_program_id().to_bytes().to_vec();
    assert!(rows
        .iter()
        .all(|row| row.rings_program_id == rings_program_id));
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

    assert_rings_api_exposes_output_hashes(&db, &outputs[0]).await;
}

#[tokio::test]
async fn rings_payloads_update_on_reprocess() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(&db, &[PROOFLESS_SHIELD_SLOT]).await;

    let state_update =
        parse_dumped_ingestion_update(PROOFLESS_SHIELD_SIGNATURE, PROOFLESS_SHIELD_SLOT);
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;

    let txn = db.begin().await.unwrap();
    persist_state_update(&txn, state_update).await.unwrap();
    txn.commit().await.unwrap();

    let mut reprocessed =
        parse_dumped_ingestion_update(PROOFLESS_SHIELD_SIGNATURE, PROOFLESS_SHIELD_SLOT);
    let rings_tx = reprocessed
        .rings_transactions
        .first_mut()
        .expect("dumped transaction should have a Rings update");
    rings_tx.encrypted_utxos = Some(vec![1, 2, 3]);
    rings_tx.raw_event = Some(vec![4, 5, 6]);
    rings_tx.parse_version = 2;
    rings_tx.outputs[0].payload = vec![7, 8, 9];

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
            pda::shielded_pool_program_id().to_bytes(),
            tree_pubkey.to_bytes(),
            address_tree_params(),
        )
        .unwrap();
        let metadata = *tree.nullifer_tree().get_metadata();
        (
            metadata.height,
            u64::from(metadata.root_history_capacity),
            metadata.queue_batches.zkp_batch_size,
            metadata.sequence_number,
            metadata.next_index,
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
        parse_dumped_ingestion_update(PROOFLESS_SHIELD_SIGNATURE, PROOFLESS_SHIELD_SLOT);
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;
    let output = state_update.rings_transactions[0].outputs[0].clone();

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

    let response = get_merkle_proofs(
        &db,
        GetMerkleProofsRequest {
            tree_account: SerializablePubkey::from(output.output_tree),
            leaves: vec![Hash::from(output.utxo_hash)],
        },
    )
    .await
    .expect("Rings output should return an inclusion proof");
    assert_eq!(response.context.slot, PROOFLESS_SHIELD_SLOT);
    assert_eq!(response.proofs.len(), 1);
    assert_eq!(response.proofs[0].leaf, Hash::from(output.utxo_hash));
    assert_eq!(response.proofs[0].leaf_index, output.leaf_index);
    assert_eq!(
        response.proofs[0].merkle_context.tree,
        SerializablePubkey::from(output.output_tree)
    );
    assert_eq!(
        response.proofs[0].merkle_context.tree_type,
        u16::from(RingsTreeKind::State)
    );
}

#[tokio::test]
async fn rings_merkle_proofs_reject_duplicate_output_hashes() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(&db, &[PROOFLESS_SHIELD_SLOT]).await;

    let state_update =
        parse_dumped_ingestion_update(PROOFLESS_SHIELD_SIGNATURE, PROOFLESS_SHIELD_SLOT);
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;
    let output = state_update.rings_transactions[0].outputs[0].clone();

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
    })
    .exec(&db)
    .await
    .unwrap();

    let err = get_merkle_proofs(
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
        parse_dumped_ingestion_update(PROOFLESS_SHIELD_SIGNATURE, PROOFLESS_SHIELD_SLOT);
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;
    let output = state_update.rings_transactions[0].outputs[0].clone();

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

    let err = get_merkle_proofs(
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
        parse_dumped_ingestion_update(PROOFLESS_SHIELD_SIGNATURE, PROOFLESS_SHIELD_SLOT);
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;
    let output = state_update.rings_transactions[0].outputs[0].clone();

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

    let err = get_merkle_proofs(
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
        parse_dumped_ingestion_update(PROOFLESS_SHIELD_SIGNATURE, PROOFLESS_SHIELD_SLOT);
    insert_known_rings_tree_accounts_from_outputs(&db, &state_update).await;
    let output_tree = state_update.rings_transactions[0].outputs[0].output_tree;

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

    assert_eq!(response.context.slot, PROOFLESS_SHIELD_SLOT);
    assert_eq!(response.proofs.len(), 1);
    assert_eq!(
        response.proofs[0].merkle_context.tree,
        SerializablePubkey::from(output_tree)
    );
    assert_eq!(
        response.proofs[0].merkle_context.tree_type,
        u16::from(RingsTreeKind::Nullifier)
    );
    assert_eq!(
        response.proofs[0].path.len(),
        RingsTreeKind::Nullifier.tree_height() as usize
    );
    assert_eq!(response.proofs[0].low_element_index, 0);
    assert_eq!(response.proofs[0].high_element_index, 0);
    assert_eq!(response.proofs[0].root_seq, 0);
    assert_eq!(response.proofs[0].root_index, 0);
}

#[tokio::test]
async fn rings_state_and_nullifier_nodes_do_not_collide_for_same_tree_account() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_test_blocks(&db, &[SHIELDED_TRANSFER_SLOT]).await;

    let state_update =
        parse_dumped_ingestion_update(SHIELDED_TRANSFER_SIGNATURE, SHIELDED_TRANSFER_SLOT);
    let tx = &state_update.rings_transactions[0];
    let tree = Pubkey::from(tx.output_tree);
    assert!(tx
        .outputs
        .iter()
        .all(|output| output.output_tree == tree.to_bytes()));
    assert!(tx
        .nullifiers
        .iter()
        .all(|nullifier| nullifier.nullifier_tree == tree.to_bytes()));

    let nullifier = tx.nullifiers[0].nullifier;
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
    let output = state_update.rings_transactions[0].outputs[0].clone();

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

    let inclusion_response = get_merkle_proofs(
        &db,
        GetMerkleProofsRequest {
            tree_account: SerializablePubkey::from(tree),
            leaves: vec![Hash::from(output.utxo_hash)],
        },
    )
    .await
    .expect("state inclusion proof should use state storage key");
    assert_eq!(inclusion_response.proofs.len(), 1);
    assert_eq!(
        inclusion_response.proofs[0].merkle_context.tree,
        SerializablePubkey::from(tree)
    );
    assert_eq!(
        inclusion_response.proofs[0].merkle_context.tree_type,
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
    assert_eq!(non_inclusion_response.proofs.len(), 1);
    assert_eq!(
        non_inclusion_response.proofs[0].merkle_context.tree,
        SerializablePubkey::from(tree)
    );
    assert_eq!(
        non_inclusion_response.proofs[0].merkle_context.tree_type,
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
        parse_dumped_ingestion_update(SHIELDED_TRANSFER_SIGNATURE, SHIELDED_TRANSFER_SLOT);
    let nullifier_tree = state_update.rings_transactions[0].nullifiers[0].nullifier_tree;
    let queued_nullifier = state_update.rings_transactions[0].nullifiers[0].nullifier;
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

    assert_eq!(response.context.slot, SHIELDED_TRANSFER_SLOT);
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

    assert_eq!(response.context.slot, SHIELDED_TRANSFER_SLOT);
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
    };

    let shielded = get_shielded_transactions_by_tags(db, request.clone())
        .await
        .unwrap();
    assert_eq!(shielded.context.slot, UNSHIELD_SLOT);
    assert!(shielded.next_cursor.is_none());
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

    let encrypted = get_encrypted_utxos_by_tags(db, request).await.unwrap();
    assert_eq!(encrypted.context.slot, UNSHIELD_SLOT);
    assert!(encrypted.next_cursor.is_none());
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

fn parse_dumped_rings_update(signature: &str, slot: u64) -> StateUpdate {
    let tx_info = transaction_info(signature);
    parse_rings_events(&tx_info, slot)
        .expect("rings parser should not fail")
        .expect("dumped transaction should contain a rings event")
}

fn parse_dumped_ingestion_update(signature: &str, slot: u64) -> StateUpdate {
    let tx_info = transaction_info(signature);
    let mut state_update = parse_rings_events(&tx_info, slot)
        .expect("rings parser should not fail")
        .expect("dumped transaction should contain a rings event");
    state_update.transactions.insert(Transaction {
        signature: tx_info.signature,
        slot,
        error: tx_info.error,
    });
    state_update
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

fn transaction_info(signature: &str) -> TransactionInfo {
    let tx = load_transaction(signature);
    let account_keys = account_keys(&tx);
    let inner_by_outer = inner_instructions_by_outer_index(&tx, &account_keys);
    let outer_instructions = tx["transaction"]["message"]["instructions"]
        .as_array()
        .expect("outer instructions");

    let instruction_groups = outer_instructions
        .iter()
        .enumerate()
        .map(|(index, instruction)| InstructionGroup {
            outer_instruction: parsed_instruction(instruction, &account_keys),
            inner_instructions: inner_by_outer.get(&index).cloned().unwrap_or_default(),
        })
        .collect();

    TransactionInfo {
        instruction_groups,
        signature: Signature::from_str(signature).expect("valid signature"),
        error: if tx["meta"]["err"].is_null() {
            None
        } else {
            Some(tx["meta"]["err"].to_string())
        },
    }
}

fn load_transaction(signature: &str) -> Value {
    let path = format!(
        "{}/tests/data/transactions/rings_e2e/{signature}",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("failed to read {path}: {err}");
    });
    serde_json::from_str(&data).unwrap_or_else(|err| {
        panic!("failed to parse {path}: {err}");
    })
}

fn account_keys(tx: &Value) -> Vec<Pubkey> {
    tx["transaction"]["message"]["accountKeys"]
        .as_array()
        .expect("account keys")
        .iter()
        .map(|value| {
            Pubkey::from_str(value.as_str().expect("account key string"))
                .expect("valid account key")
        })
        .collect()
}

fn inner_instructions_by_outer_index(
    tx: &Value,
    account_keys: &[Pubkey],
) -> BTreeMap<usize, Vec<Instruction>> {
    let Some(groups) = tx["meta"]["innerInstructions"].as_array() else {
        return BTreeMap::new();
    };

    groups
        .iter()
        .map(|group| {
            let outer_index = group["index"].as_u64().expect("inner group index") as usize;
            let instructions = group["instructions"]
                .as_array()
                .expect("inner instructions")
                .iter()
                .map(|instruction| parsed_instruction(instruction, account_keys))
                .collect::<Vec<_>>();
            (outer_index, instructions)
        })
        .collect()
}

fn parsed_instruction(instruction: &Value, account_keys: &[Pubkey]) -> Instruction {
    let program_id_index = instruction["programIdIndex"]
        .as_u64()
        .expect("program id index") as usize;
    let accounts = instruction["accounts"]
        .as_array()
        .expect("instruction accounts")
        .iter()
        .map(|value| {
            let index = value.as_u64().expect("account index") as usize;
            account_keys[index]
        })
        .collect::<Vec<_>>();
    let data = bs58::decode(instruction["data"].as_str().expect("instruction data"))
        .into_vec()
        .expect("base58 instruction data");
    let stack_height = instruction["stackHeight"]
        .as_u64()
        .map(|height| height as u32);

    Instruction {
        program_id: account_keys[program_id_index],
        data,
        accounts,
        stack_height,
    }
}
