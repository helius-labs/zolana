use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    str::FromStr,
};

use photon_indexer::rpc::RpcClient;
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
        blocks, indexed_trees, rings_output_payloads, rings_outputs, rings_transactions,
        rings_tx_nullifiers, state_trees, tree_metadata,
    },
    ingester::{
        index_block_batch,
        typedefs::block_info::{
            BlockInfo, BlockMetadata, Instruction, InstructionGroup, TransactionInfo,
        },
    },
    migration::RingsMigrator,
    snapshot::{is_rings_snapshot_transaction, is_rings_transaction},
};
use sea_orm::{
    sea_query::OnConflict, ColumnTrait, ConnectionTrait, Database, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, QueryTrait, Set,
};
use sea_orm_migration::MigratorTrait;
use serde::Deserialize;
use serde_json::Value;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_indexer_api::{
    Base64String, GetMerkleProofsRequest, GetNonInclusionProofsRequest, GetRingsByTagsRequest,
    Hash, Limit, RingsOutputContext, RingsOutputSlot, SerializablePubkey, SerializableSignature,
    ShieldedTransaction,
};

const NULLIFIER_FORESTER_FIXTURE: &str = "nullifier_forester_20_batches";

#[tokio::test]
async fn snapshot_fixture_replays_twenty_nullifier_batches() {
    let fixture = load_snapshot_fixture(NULLIFIER_FORESTER_FIXTURE);
    assert_eq!(fixture.manifest.version, 1);
    assert_eq!(fixture.manifest.seed_deposit_count, 2);
    assert_eq!(fixture.manifest.queue_tx_count, 100);
    assert_eq!(fixture.manifest.batch_update_count, 20);
    assert_eq!(fixture.manifest.nullifier_zkp_batch_size, 10);
    assert_eq!(
        fixture.manifest.transactions.len(),
        (fixture.manifest.seed_deposit_count
            + fixture.manifest.queue_tx_count
            + fixture.manifest.batch_update_count) as usize
    );
    assert_eq!(
        fixture.manifest.nullifiers.len(),
        (fixture.manifest.queue_tx_count * 2) as usize
    );
    assert_eq!(
        fixture.batch_only_snapshot_transactions,
        fixture.manifest.batch_update_count as usize
    );

    let tree = Pubkey::from_str(&fixture.manifest.tree).expect("fixture tree pubkey");
    let tree_bytes = tree.to_bytes().to_vec();
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    insert_known_rings_tree_account(
        &db,
        tree,
        fixture.manifest.nullifier_zkp_batch_size,
        fixture.first_slot(),
    )
    .await;
    let queue_tx_count = fixture.manifest.queue_tx_count;

    let rpc_client = RpcClient::new("http://127.0.0.1:0".to_string());
    for block in fixture.blocks {
        index_block_batch(&db, &vec![block], &rpc_client)
            .await
            .expect("fixture block should replay through Photon ingestion");
    }

    assert_eq!(
        blocks::Entity::find().count(&db).await.unwrap(),
        fixture.distinct_slot_count
    );
    assert_eq!(
        rings_transactions::Entity::find().count(&db).await.unwrap(),
        fixture.manifest.seed_deposit_count + fixture.manifest.queue_tx_count
    );
    assert_confidential_queue_outputs(&db, queue_tx_count).await;

    let nullifier_rows = rings_tx_nullifiers::Entity::find()
        .filter(rings_tx_nullifiers::Column::NullifierTree.eq(tree_bytes.clone()))
        .order_by_asc(rings_tx_nullifiers::Column::InputQueueSeq)
        .all(&db)
        .await
        .unwrap();
    assert_eq!(
        nullifier_rows.len(),
        fixture.manifest.nullifiers.len(),
        "all queued nullifiers should be persisted"
    );
    for (expected_seq, row) in nullifier_rows.iter().enumerate() {
        assert_eq!(row.input_queue_seq, expected_seq as i64);
    }

    assert_eq!(
        indexed_trees::Entity::find()
            .filter(indexed_trees::Column::Tree.eq(tree_bytes.clone()))
            .count(&db)
            .await
            .unwrap(),
        fixture.manifest.nullifiers.len() as u64 + 1,
        "indexed tree should contain zeroeth range plus all nullifiers"
    );

    let current_root = state_trees::Entity::find()
        .filter(state_trees::Column::Tree.eq(tree_bytes.clone()))
        .filter(state_trees::Column::TreeKind.eq(i32::from(RingsTreeKind::Nullifier)))
        .filter(state_trees::Column::NodeIdx.eq(1))
        .one(&db)
        .await
        .unwrap()
        .expect("nullifier root should be reconstructed");
    assert_eq!(
        current_root.seq,
        Some(fixture.manifest.batch_update_count as i64)
    );

    let used_nullifier = Hash::from(hex_32(&fixture.manifest.nullifiers[0]));
    let used_error = get_non_inclusion_proofs(
        &db,
        GetNonInclusionProofsRequest {
            tree_account: SerializablePubkey::from(tree),
            leaves: vec![used_nullifier],
        },
    )
    .await
    .expect_err("queued/inserted nullifier should not return a non-inclusion proof");
    assert!(matches!(
        used_error,
        PhotonApiError::ValidationError(message)
            if message.contains("already used or queued")
    ));

    let fresh_nullifier = Hash::from(u64_leaf(9_000));
    let proof_response = get_non_inclusion_proofs(
        &db,
        GetNonInclusionProofsRequest {
            tree_account: SerializablePubkey::from(tree),
            leaves: vec![fresh_nullifier.clone()],
        },
    )
    .await
    .expect("fresh nullifier should return a non-inclusion proof");
    assert_eq!(proof_response.proofs.len(), 1);
    let proof = &proof_response.proofs[0];
    assert_eq!(proof.leaf, fresh_nullifier);
    assert_eq!(proof.merkle_context.tree, SerializablePubkey::from(tree));
    assert_eq!(
        proof.merkle_context.tree_type,
        u16::from(RingsTreeKind::Nullifier)
    );
    assert_eq!(proof.root_seq, fixture.manifest.batch_update_count);
    assert_eq!(proof.root_index, fixture.manifest.batch_update_count as u16);
    assert_eq!(
        proof.path.len(),
        RingsTreeKind::Nullifier.tree_height() as usize
    );

    assert_rings_api_contract(&db, tree, &fixture.manifest).await;
}

struct LoadedSnapshotFixture {
    manifest: SnapshotFixtureManifest,
    blocks: Vec<BlockInfo>,
    batch_only_snapshot_transactions: usize,
    distinct_slot_count: u64,
}

impl LoadedSnapshotFixture {
    fn first_slot(&self) -> u64 {
        self.blocks
            .first()
            .map(|block| block.metadata.slot)
            .unwrap_or(0)
    }
}

async fn assert_confidential_queue_outputs(db: &sea_orm::DatabaseConnection, queue_tx_count: u64) {
    assert_eq!(
        rings_transactions::Entity::find()
            .filter(rings_transactions::Column::TxViewingPk.is_not_null())
            .count(db)
            .await
            .unwrap(),
        queue_tx_count,
        "every queue-fill tx in the fixture should be a confidential transfer"
    );
    assert_eq!(
        rings_transactions::Entity::find()
            .filter(rings_transactions::Column::Salt.is_not_null())
            .count(db)
            .await
            .unwrap(),
        queue_tx_count,
        "every confidential queue-fill tx should carry an encryption salt"
    );

    let tx = rings_transactions::Entity::find()
        .filter(rings_transactions::Column::TxViewingPk.is_not_null())
        .order_by_asc(rings_transactions::Column::Slot)
        .one(db)
        .await
        .unwrap()
        .expect("fixture should contain at least one confidential queue tx");
    let tx_viewing_pk = tx
        .tx_viewing_pk
        .clone()
        .expect("confidential tx should carry tx_viewing_pk");
    assert_eq!(tx_viewing_pk.len(), 33);
    assert!(tx_viewing_pk.iter().any(|byte| *byte != 0));
    let salt = tx.salt.clone().expect("confidential tx should carry salt");
    assert_eq!(salt.len(), 16);
    assert!(salt.iter().any(|byte| *byte != 0));

    let outputs = rings_outputs::Entity::find()
        .filter(rings_outputs::Column::RingsTxId.eq(tx.rings_tx_id))
        .order_by_asc(rings_outputs::Column::OutputIndex)
        .all(db)
        .await
        .unwrap();
    assert_eq!(outputs.len(), 3);

    let output_ids = outputs
        .iter()
        .map(|output| output.output_id)
        .collect::<Vec<_>>();
    let payloads = rings_output_payloads::Entity::find()
        .filter(rings_output_payloads::Column::OutputId.is_in(output_ids))
        .all(db)
        .await
        .unwrap()
        .into_iter()
        .map(|payload| (payload.output_id, payload.payload))
        .collect::<BTreeMap<_, _>>();

    assert!(
        !payloads
            .get(&outputs[0].output_id)
            .expect("sender bundle payload should exist")
            .is_empty(),
        "output 0 should carry the encrypted sender bundle"
    );
    assert!(
        payloads
            .get(&outputs[1].output_id)
            .expect("SOL change payload should exist")
            .is_empty(),
        "output 1 is SOL change and should be covered by the sender bundle"
    );
    let recipient_output = outputs
        .iter()
        .find(|output| output.output_index == 2)
        .expect("fixture tx should include a recipient output");
    let recipient_payload = payloads
        .get(&recipient_output.output_id)
        .expect("recipient payload should exist");
    assert!(
        !recipient_payload.is_empty(),
        "recipient output should carry an encrypted UTXO payload"
    );

    let encrypted = get_encrypted_utxos_by_tags(
        db,
        GetRingsByTagsRequest {
            tags: vec![Hash::try_from(recipient_output.view_tag.clone()).unwrap()],
            cursor: None,
            limit: None,
        },
    )
    .await
    .unwrap();
    let encrypted_match = encrypted
        .matches
        .iter()
        .find(|match_| {
            match_.output_slot.output_context.hash.to_vec() == recipient_output.utxo_hash
        })
        .expect("encrypted UTXO API should return the recipient output");
    assert_eq!(
        encrypted_match
            .tx_viewing_pk
            .as_ref()
            .expect("API match should include tx_viewing_pk")
            .0,
        tx_viewing_pk
    );
    assert_eq!(
        encrypted_match
            .salt
            .as_ref()
            .expect("API match should include salt")
            .0,
        salt
    );
    assert_eq!(encrypted_match.output_slot.payload.0, *recipient_payload);
}

async fn assert_rings_api_contract(
    db: &sea_orm::DatabaseConnection,
    tree: Pubkey,
    manifest: &SnapshotFixtureManifest,
) {
    let context_slot = blocks::Entity::find()
        .order_by_desc(blocks::Column::Slot)
        .one(db)
        .await
        .unwrap()
        .expect("fixture should persist at least one block")
        .slot as u64;
    let deposit_tx = rings_tx_by_fixture_kind(db, manifest, "deposit", 0).await;
    let queue_tx = rings_tx_by_fixture_kind(db, manifest, "queue", 0).await;
    let deposit_outputs = outputs_for_tx(db, deposit_tx.rings_tx_id).await;
    let queue_outputs = outputs_for_tx(db, queue_tx.rings_tx_id).await;
    assert_eq!(deposit_outputs.len(), 1);
    assert_eq!(queue_outputs.len(), 3);

    assert_shielded_transaction_api_match(
        db,
        context_slot,
        &deposit_tx,
        &deposit_outputs,
        "deposit",
    )
    .await;
    assert_shielded_transaction_api_match(db, context_slot, &queue_tx, &queue_outputs, "queue")
        .await;

    assert_encrypted_utxo_api_match(
        db,
        context_slot,
        &deposit_tx,
        deposit_outputs
            .first()
            .expect("deposit should have an output"),
        "deposit",
    )
    .await;
    assert_encrypted_utxo_api_match(
        db,
        context_slot,
        &queue_tx,
        queue_outputs
            .iter()
            .find(|output| output.output_index == 2)
            .expect("queue tx should have recipient output"),
        "queue recipient",
    )
    .await;

    assert_encrypted_utxo_pagination(db, context_slot, &queue_outputs).await;
    assert_merkle_proof_api_match(
        db,
        tree,
        context_slot,
        &deposit_outputs[0],
        &queue_outputs[2],
    )
    .await;
    assert_non_inclusion_api_contract(db, tree, manifest).await;
}

async fn assert_shielded_transaction_api_match(
    db: &sea_orm::DatabaseConnection,
    context_slot: u64,
    tx: &rings_transactions::Model,
    outputs: &[rings_outputs::Model],
    label: &str,
) {
    let request = GetRingsByTagsRequest {
        tags: vec![Hash::try_from(outputs[0].view_tag.clone()).unwrap()],
        cursor: None,
        limit: None,
    };
    let response = get_shielded_transactions_by_tags(db, request)
        .await
        .unwrap_or_else(|err| panic!("{label} shielded transaction API failed: {err:?}"));
    assert_eq!(response.context.slot, context_slot);
    assert!(response.next_cursor.is_none());
    let expected_signature = signature_from_db(&tx.signature);
    let api_tx = response
        .transactions
        .iter()
        .find(|api_tx| api_tx.tx_signature.0 == expected_signature)
        .unwrap_or_else(|| panic!("{label} API response missing requested transaction"));

    let payloads = payloads_by_output_id(db, outputs).await;
    let nullifiers = nullifiers_for_tx(db, tx.rings_tx_id).await;
    assert_eq!(
        api_tx,
        &expected_shielded_transaction(tx, outputs, &payloads, &nullifiers)
    );
}

async fn assert_encrypted_utxo_api_match(
    db: &sea_orm::DatabaseConnection,
    context_slot: u64,
    tx: &rings_transactions::Model,
    output: &rings_outputs::Model,
    label: &str,
) {
    let payload = rings_output_payloads::Entity::find_by_id(output.output_id)
        .one(db)
        .await
        .unwrap()
        .expect("output payload should exist");
    let response = get_encrypted_utxos_by_tags(
        db,
        GetRingsByTagsRequest {
            tags: vec![Hash::try_from(output.view_tag.clone()).unwrap()],
            cursor: None,
            limit: None,
        },
    )
    .await
    .unwrap_or_else(|err| panic!("{label} encrypted UTXO API failed: {err:?}"));
    assert_eq!(response.context.slot, context_slot);
    assert!(response.next_cursor.is_none());
    let api_match = response
        .matches
        .iter()
        .find(|match_| match_.output_slot.output_context.hash.to_vec() == output.utxo_hash)
        .unwrap_or_else(|| panic!("{label} encrypted UTXO API response missing requested output"));
    assert_eq!(api_match.slot, tx.slot as u64);
    assert_eq!(&api_match.tx_signature.0, &signature_from_db(&tx.signature));
    assert_eq!(
        api_match.tx_viewing_pk.as_ref().map(|value| &value.0),
        tx.tx_viewing_pk.as_ref()
    );
    assert_eq!(
        api_match.salt.as_ref().map(|value| &value.0),
        tx.salt.as_ref()
    );
    assert_eq!(api_match.output_slot.payload.0, payload.payload);
    assert_output_slot_matches_row(
        &api_match.output_slot,
        output,
        &BTreeMap::from([(output.output_id, payload.payload)]),
    );
}

async fn assert_encrypted_utxo_pagination(
    db: &sea_orm::DatabaseConnection,
    context_slot: u64,
    _queue_outputs: &[rings_outputs::Model],
) {
    let outputs = rings_outputs::Entity::find()
        .filter(rings_outputs::Column::OutputIndex.eq(2))
        .order_by_asc(rings_outputs::Column::Slot)
        .limit(3)
        .all(db)
        .await
        .unwrap();
    assert_eq!(outputs.len(), 3);
    let tags = outputs
        .iter()
        .map(|output| Hash::try_from(output.view_tag.clone()).unwrap())
        .collect::<Vec<_>>();
    // The three sampled view tags can be shared by many outputs across the
    // twenty batches, so the total match count is data-dependent. Fetch the full
    // set first (1000 is the max page limit), then assert pagination walks it:
    // page one returns a single match plus a cursor, and the cursor page returns
    // the remainder and terminates.
    let all_matches = get_encrypted_utxos_by_tags(
        db,
        GetRingsByTagsRequest {
            tags: tags.clone(),
            cursor: None,
            limit: Some(Limit::new(1000).unwrap()),
        },
    )
    .await
    .expect("full encrypted UTXO query should succeed");
    let total_matches = all_matches.matches.len();
    assert!(
        total_matches >= 2,
        "fixture should yield at least two encrypted UTXO matches to paginate"
    );

    let first_page = get_encrypted_utxos_by_tags(
        db,
        GetRingsByTagsRequest {
            tags: tags.clone(),
            cursor: None,
            limit: Some(Limit::new(1).unwrap()),
        },
    )
    .await
    .expect("first encrypted UTXO API page should succeed");
    assert_eq!(first_page.context.slot, context_slot);
    assert_eq!(first_page.matches.len(), 1);
    let cursor = first_page
        .next_cursor
        .clone()
        .expect("first page should expose a cursor");

    let second_page = get_encrypted_utxos_by_tags(
        db,
        GetRingsByTagsRequest {
            tags,
            cursor: Some(cursor),
            limit: Some(Limit::new(1000).unwrap()),
        },
    )
    .await
    .expect("second encrypted UTXO API page should succeed");
    assert_eq!(second_page.context.slot, context_slot);
    assert_eq!(second_page.matches.len(), total_matches - 1);
    assert!(second_page.next_cursor.is_none());
    let first_hash = first_page.matches[0]
        .output_slot
        .output_context
        .hash
        .clone();
    assert!(
        second_page
            .matches
            .iter()
            .all(|match_| match_.output_slot.output_context.hash != first_hash),
        "cursor should advance past the first encrypted UTXO match"
    );
}

async fn assert_merkle_proof_api_match(
    db: &sea_orm::DatabaseConnection,
    tree: Pubkey,
    context_slot: u64,
    deposit_output: &rings_outputs::Model,
    queue_output: &rings_outputs::Model,
) {
    let response = get_merkle_proofs(
        db,
        GetMerkleProofsRequest {
            tree_account: SerializablePubkey::from(tree),
            leaves: vec![
                Hash::try_from(deposit_output.utxo_hash.clone()).unwrap(),
                Hash::try_from(queue_output.utxo_hash.clone()).unwrap(),
            ],
        },
    )
    .await
    .expect("state output merkle proofs should succeed");
    assert_eq!(response.context.slot, context_slot);
    assert_eq!(response.proofs.len(), 2);

    for (proof, output) in response.proofs.iter().zip([deposit_output, queue_output]) {
        assert_eq!(proof.leaf.to_vec(), output.utxo_hash);
        assert_eq!(proof.merkle_context.tree, SerializablePubkey::from(tree));
        assert_eq!(
            proof.merkle_context.tree_type,
            u16::from(RingsTreeKind::State)
        );
        assert_eq!(proof.leaf_index, output.leaf_index as u64);
        assert_eq!(
            proof.path.len(),
            RingsTreeKind::State.tree_height() as usize
        );
    }
}

async fn assert_non_inclusion_api_contract(
    db: &sea_orm::DatabaseConnection,
    tree: Pubkey,
    manifest: &SnapshotFixtureManifest,
) {
    for index in [
        0,
        manifest.nullifiers.len() / 2,
        manifest.nullifiers.len() - 1,
    ] {
        let nullifier = Hash::from(hex_32(&manifest.nullifiers[index]));
        let err = get_non_inclusion_proofs(
            db,
            GetNonInclusionProofsRequest {
                tree_account: SerializablePubkey::from(tree),
                leaves: vec![nullifier],
            },
        )
        .await
        .expect_err("used fixture nullifier should not return a non-inclusion proof");
        assert!(matches!(
            err,
            PhotonApiError::ValidationError(message)
                if message.contains("already used or queued")
        ));
    }

    let leaves = vec![Hash::from(u64_leaf(9_001)), Hash::from(u64_leaf(9_002))];
    let response = get_non_inclusion_proofs(
        db,
        GetNonInclusionProofsRequest {
            tree_account: SerializablePubkey::from(tree),
            leaves: leaves.clone(),
        },
    )
    .await
    .expect("fresh fixture nullifiers should return non-inclusion proofs");
    assert_eq!(response.proofs.len(), leaves.len());
    for (proof, leaf) in response.proofs.iter().zip(leaves) {
        assert_eq!(proof.leaf, leaf);
        assert_eq!(proof.merkle_context.tree, SerializablePubkey::from(tree));
        assert_eq!(
            proof.merkle_context.tree_type,
            u16::from(RingsTreeKind::Nullifier)
        );
        assert_eq!(proof.root_seq, manifest.batch_update_count);
        assert_eq!(proof.root_index, manifest.batch_update_count as u16);
        assert_eq!(
            proof.path.len(),
            RingsTreeKind::Nullifier.tree_height() as usize
        );
    }
}

async fn rings_tx_by_fixture_kind(
    db: &sea_orm::DatabaseConnection,
    manifest: &SnapshotFixtureManifest,
    kind: &str,
    order: u64,
) -> rings_transactions::Model {
    let signature = manifest
        .transactions
        .iter()
        .find(|tx| tx.kind == kind && tx.order == order)
        .unwrap_or_else(|| panic!("fixture should contain {kind} tx order {order}"))
        .signature_bytes();
    rings_transactions::Entity::find()
        .filter(rings_transactions::Column::Signature.eq(signature))
        .one(db)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{kind} tx order {order} should be persisted"))
}

async fn outputs_for_tx(
    db: &sea_orm::DatabaseConnection,
    rings_tx_id: i64,
) -> Vec<rings_outputs::Model> {
    rings_outputs::Entity::find()
        .filter(rings_outputs::Column::RingsTxId.eq(rings_tx_id))
        .order_by_asc(rings_outputs::Column::OutputIndex)
        .all(db)
        .await
        .unwrap()
}

async fn nullifiers_for_tx(
    db: &sea_orm::DatabaseConnection,
    rings_tx_id: i64,
) -> Vec<rings_tx_nullifiers::Model> {
    rings_tx_nullifiers::Entity::find()
        .filter(rings_tx_nullifiers::Column::RingsTxId.eq(rings_tx_id))
        .order_by_asc(rings_tx_nullifiers::Column::InputIndex)
        .all(db)
        .await
        .unwrap()
}

async fn payloads_by_output_id(
    db: &sea_orm::DatabaseConnection,
    outputs: &[rings_outputs::Model],
) -> BTreeMap<i64, Vec<u8>> {
    let output_ids = outputs
        .iter()
        .map(|output| output.output_id)
        .collect::<Vec<_>>();
    rings_output_payloads::Entity::find()
        .filter(rings_output_payloads::Column::OutputId.is_in(output_ids))
        .all(db)
        .await
        .unwrap()
        .into_iter()
        .map(|payload| (payload.output_id, payload.payload))
        .collect()
}

fn assert_output_slot_matches_row(
    slot: &RingsOutputSlot,
    output: &rings_outputs::Model,
    payloads: &BTreeMap<i64, Vec<u8>>,
) {
    assert_eq!(slot.view_tag.to_vec(), output.view_tag);
    assert_eq!(slot.output_context.hash.to_vec(), output.utxo_hash);
    assert_eq!(slot.output_context.tree.to_bytes_vec(), output.output_tree);
    assert_eq!(slot.output_context.leaf_index, output.leaf_index as u64);
    assert_eq!(
        slot.payload.0,
        *payloads
            .get(&output.output_id)
            .expect("output payload should be present")
    );
}

fn expected_shielded_transaction(
    tx: &rings_transactions::Model,
    outputs: &[rings_outputs::Model],
    payloads: &BTreeMap<i64, Vec<u8>>,
    nullifiers: &[rings_tx_nullifiers::Model],
) -> ShieldedTransaction {
    ShieldedTransaction {
        slot: tx.slot as u64,
        tx_signature: SerializableSignature(signature_from_db(&tx.signature)),
        tx_viewing_pk: tx.tx_viewing_pk.clone().map(Base64String),
        salt: tx.salt.clone().map(Base64String),
        output_slots: outputs
            .iter()
            .map(|output| expected_output_slot(output, payloads))
            .collect(),
        nullifiers: nullifiers
            .iter()
            .map(|row| Hash::try_from(row.nullifier.clone()).unwrap())
            .collect(),
        proofless: tx.proofless,
    }
}

fn expected_output_slot(
    output: &rings_outputs::Model,
    payloads: &BTreeMap<i64, Vec<u8>>,
) -> RingsOutputSlot {
    RingsOutputSlot {
        view_tag: Hash::try_from(output.view_tag.clone()).unwrap(),
        output_context: RingsOutputContext {
            hash: Hash::try_from(output.utxo_hash.clone()).unwrap(),
            tree: SerializablePubkey::try_from(output.output_tree.clone()).unwrap(),
            leaf_index: output.leaf_index as u64,
        },
        payload: Base64String(
            payloads
                .get(&output.output_id)
                .expect("output payload should be present")
                .clone(),
        ),
    }
}

#[derive(Deserialize)]
struct SnapshotFixtureManifest {
    version: u8,
    tree: String,
    seed_deposit_count: u64,
    queue_tx_count: u64,
    batch_update_count: u64,
    nullifier_zkp_batch_size: u64,
    nullifiers: Vec<String>,
    transactions: Vec<SnapshotFixtureManifestTx>,
}

#[derive(Deserialize)]
struct SnapshotFixtureManifestTx {
    signature: String,
    slot: u64,
    kind: String,
    order: u64,
}

impl SnapshotFixtureManifestTx {
    fn signature_bytes(&self) -> Vec<u8> {
        Into::<[u8; 64]>::into(
            Signature::from_str(&self.signature).expect("fixture signature should be valid"),
        )
        .to_vec()
    }
}

fn signature_from_db(bytes: &[u8]) -> Signature {
    Signature::from(<[u8; 64]>::try_from(bytes).expect("DB signature should be 64 bytes"))
}

fn load_snapshot_fixture(name: &str) -> LoadedSnapshotFixture {
    let root = fixture_root(name);
    let manifest_path = root.join("manifest.json");
    let manifest: SnapshotFixtureManifest = read_json(&manifest_path);
    let mut blocks_by_slot = BTreeMap::<u64, Vec<TransactionInfo>>::new();
    let mut batch_only_snapshot_transactions = 0usize;

    for expected_order in 0..manifest.transactions.len() {
        let tx = &manifest.transactions[expected_order];
        assert_eq!(
            tx.order as usize,
            expected_order_for_kind(&manifest.transactions, tx)
        );
        let path = root.join("transactions").join(&tx.signature);
        let raw: Value = read_json(&path);
        assert_eq!(
            raw["slot"].as_u64(),
            Some(tx.slot),
            "fixture tx {} slot should match manifest",
            tx.signature
        );
        let tx_info = transaction_info_from_json(&raw, &tx.signature);

        assert!(
            is_rings_snapshot_transaction(&tx_info, tx.slot),
            "fixture tx {} should be retained by snapshot filtering",
            tx.signature
        );

        if tx.kind == "batch_update" {
            assert!(
                !is_rings_transaction(&tx_info, tx.slot),
                "batch tx {} should be batch-only, not a GeneralEvent transaction",
                tx.signature
            );
            batch_only_snapshot_transactions += 1;
        } else {
            assert!(
                tx.kind == "deposit" || tx.kind == "queue",
                "unexpected fixture transaction kind {}",
                tx.kind
            );
        }

        blocks_by_slot.entry(tx.slot).or_default().push(tx_info);
    }

    let distinct_slot_count = blocks_by_slot.len() as u64;
    let mut previous_slot = None;
    let blocks = blocks_by_slot
        .into_iter()
        .map(|(slot, transactions)| {
            let parent_slot = previous_slot.unwrap_or_else(|| slot.saturating_sub(1));
            previous_slot = Some(slot);
            BlockInfo {
                metadata: BlockMetadata {
                    slot,
                    parent_slot,
                    block_time: i64::try_from(slot).expect("slot should fit block_time"),
                    blockhash: hash_for_slot(slot, 1),
                    parent_blockhash: hash_for_slot(parent_slot, 0),
                    block_height: slot,
                },
                transactions,
            }
        })
        .collect();

    LoadedSnapshotFixture {
        manifest,
        blocks,
        batch_only_snapshot_transactions,
        distinct_slot_count,
    }
}

fn expected_order_for_kind(
    transactions: &[SnapshotFixtureManifestTx],
    tx: &SnapshotFixtureManifestTx,
) -> usize {
    transactions
        .iter()
        .filter(|candidate| candidate.kind == tx.kind)
        .take_while(|candidate| candidate.signature != tx.signature)
        .count()
}

fn fixture_root(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("snapshots")
        .join(name)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let data = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&data)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn transaction_info_from_json(tx: &Value, signature: &str) -> TransactionInfo {
    let account_keys = account_keys(tx);
    let inner_by_outer = inner_instructions_by_outer_index(tx, &account_keys);
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

fn account_keys(tx: &Value) -> Vec<Pubkey> {
    let mut keys = tx["transaction"]["message"]["accountKeys"]
        .as_array()
        .expect("account keys")
        .iter()
        .map(|value| {
            Pubkey::from_str(value.as_str().expect("account key string"))
                .expect("valid account key")
        })
        .collect::<Vec<_>>();

    if let Some(loaded_addresses) = tx["meta"]["loadedAddresses"].as_object() {
        for key in ["writable", "readonly"] {
            if let Some(addresses) = loaded_addresses.get(key).and_then(Value::as_array) {
                keys.extend(addresses.iter().map(|value| {
                    Pubkey::from_str(value.as_str().expect("loaded account key string"))
                        .expect("valid loaded account key")
                }));
            }
        }
    }

    keys
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

fn hash_for_slot(slot: u64, salt: u8) -> Hash {
    let mut bytes = [salt; 32];
    bytes[24..].copy_from_slice(&slot.to_be_bytes());
    Hash::from(bytes)
}

fn hex_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64, "fixture nullifier should be 32-byte hex");
    let mut bytes = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let hex = std::str::from_utf8(chunk).expect("hex should be utf8");
        bytes[index] = u8::from_str_radix(hex, 16).expect("valid hex byte");
    }
    bytes
}

fn u64_leaf(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

async fn insert_known_rings_tree_account(
    db: &sea_orm::DatabaseConnection,
    tree: Pubkey,
    nullifier_zkp_batch_size: u64,
    last_synced_slot: u64,
) {
    let row = tree_metadata::ActiveModel {
        tree_pubkey: Set(tree.to_bytes().to_vec()),
        queue_pubkey: Set(tree.to_bytes().to_vec()),
        height: Set(RingsTreeKind::Nullifier.tree_height() as i32),
        root_history_capacity: Set(RingsTreeKind::Nullifier.root_history_capacity() as i64),
        input_queue_zkp_batch_size: Set(nullifier_zkp_batch_size as i64),
        sequence_number: Set(0),
        next_index: Set(0),
        last_synced_slot: Set(last_synced_slot as i64),
    };
    let query = tree_metadata::Entity::insert(row)
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
        .build(db.get_database_backend());
    db.execute(query).await.unwrap();
}
