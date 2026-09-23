use super::{
    parser::{self, Rail, SuccessorContext},
    *,
};
use crate::{
    ingester::{
        parser::state_update::{RingsMessageUpdate, RingsOutputUpdate, RingsTransactionUpdate},
        typedefs::block_info::{
            BlockInfo, BlockMetadata, Instruction, InstructionGroup, TransactionInfo,
        },
    },
    migration::{MigratorTrait, RingsMigrator},
    ring_projection::{
        storage::{BlockJournal, BlockUndo},
        tests::{field, member, projector},
        Invocations, ProjectionKind, StartSlot,
    },
};
use jsonrpsee::server::ServerHandle;
use sea_orm::Database;
use serde_json::json;
use solana_pubkey::Pubkey;
use zolana_indexer_api::Hash;
use zolana_ring_policy::{
    spend_record_message_tag, ListNamespace, Member, SpendCounters, SpendRecord,
};

const PROGRAM: [u8; 32] = [11; 32];

async fn fixture() -> (DatabaseConnection, ProjectionCursor) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    let cursor = ProjectionCursor::new(0);
    storage::save_cursor(&db, &cursor).await.unwrap();
    SpendStore::new(&db, PROGRAM).open().await.unwrap();
    (db, cursor)
}

fn row(seed: u8, version: u8) -> RecordRow {
    let mut nullifier = field(version);
    nullifier[0] = seed;
    RecordRow {
        member: member(seed),
        nullifier,
        signature: Signature::from([version; 64]).into(),
        event_index: 0,
        output_index: u16::from(version),
        slot: u64::from(version),
    }
}

fn block(slot: u64) -> BlockMetadata {
    BlockMetadata {
        slot,
        blockhash: Hash(field(slot as u8)),
        block_time: 90,
        ..Default::default()
    }
}

#[tokio::test]
async fn register_then_transfers_keep_only_the_latest_record_until_rollback() {
    let (db, mut cursor) = fixture().await;
    let tx = db.begin().await.unwrap();
    let store = SpendStore::new(&tx, PROGRAM);
    let mut undo = vec![Update::Register(row(5, 0))
        .apply(&store)
        .await
        .unwrap()
        .unwrap()];
    for version in 1..=2 {
        let current = row(5, version - 1);
        let spent = store
            .spent_by(&[field(99), current.nullifier])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(spent, current);
        undo.push(
            Update::Transfer {
                spent,
                successor: row(5, version),
            }
            .apply(&store)
            .await
            .unwrap()
            .unwrap(),
        );
    }
    assert_eq!(store.record(&member(5)).await.unwrap(), Some(row(5, 2)));
    // A replayed transfer spends a record the projection no longer holds.
    for version in 0..2 {
        assert!(store
            .spent_by(&[row(5, version).nullifier])
            .await
            .unwrap()
            .is_none());
    }
    storage::save_journal(
        &tx,
        &BlockJournal {
            metadata: block(3),
            previous_tip: None,
            undo: BlockUndo {
                spend_records: undo,
                key_registry: vec![],
            },
        },
    )
    .await
    .unwrap();
    cursor.tip = Some(block(3));
    cursor.scanned_slot = 3;
    storage::save_cursor(&tx, &cursor).await.unwrap();
    tx.commit().await.unwrap();

    let mut restarted = storage::cursor(&db).await.unwrap().unwrap();
    let tx = db.begin().await.unwrap();
    storage::rollback(&tx, &mut restarted).await.unwrap();
    tx.commit().await.unwrap();
    let store = SpendStore::new(&db, PROGRAM);
    assert!(store.record(&member(5)).await.unwrap().is_none());
    assert!(store.ring().await.unwrap().is_some());
    assert!(restarted.tip.is_none());
}

#[tokio::test]
async fn a_replayed_registration_is_idempotent_and_a_second_one_is_refused() {
    let (db, _) = fixture().await;
    let tx = db.begin().await.unwrap();
    let store = SpendStore::new(&tx, PROGRAM);
    assert!(Update::Register(row(5, 0))
        .apply(&store)
        .await
        .unwrap()
        .is_some());
    assert!(Update::Register(row(5, 0))
        .apply(&store)
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        Update::Register(row(5, 1)).apply(&store).await,
        Err(ProjectError::Fault(_))
    ));
    assert_eq!(store.record(&member(5)).await.unwrap(), Some(row(5, 0)));
}

#[tokio::test]
async fn a_transfer_cannot_move_another_members_record_or_spend_two() {
    let (db, _) = fixture().await;
    let tx = db.begin().await.unwrap();
    let store = SpendStore::new(&tx, PROGRAM);
    for seed in [5, 6] {
        Update::Register(row(seed, 0)).apply(&store).await.unwrap();
    }
    assert!(matches!(
        Update::Transfer {
            spent: row(5, 0),
            successor: row(6, 1),
        }
        .apply(&store)
        .await,
        Err(ProjectError::Fault(_))
    ));
    assert!(matches!(
        store
            .spent_by(&[row(5, 0).nullifier, row(6, 0).nullifier])
            .await,
        Err(ProjectError::Fault(_))
    ));
    // Records are scoped to their ring.
    assert!(SpendStore::new(&tx, [12; 32])
        .spent_by(&[row(5, 0).nullifier])
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_malformed_record_update_quarantines_only_its_ring_until_rollback() {
    let (db, mut cursor) = fixture().await;
    let healthy = [12; 32];
    SpendStore::new(&db, healthy).open().await.unwrap();
    let garbage = |program: [u8; 32], error: Option<String>| TransactionInfo {
        signature: Signature::from([1; 64]),
        error,
        instruction_groups: vec![InstructionGroup {
            outer_instruction: Instruction {
                program_id: Pubkey::new_from_array(program),
                data: vec![tag::REGISTER_SPEND, 1, 2, 3],
                accounts: vec![],
                stack_height: Some(1),
            },
            inner_instructions: vec![],
        }],
    };
    let block = BlockInfo {
        metadata: block(3),
        transactions: vec![
            garbage(PROGRAM, None),
            garbage(healthy, Some("failed".into())),
        ],
    };
    let projector = projector(&db, StartSlot::Derived(0));
    let tx = db.begin().await.unwrap();
    projector
        .apply_block(&tx, &block, &mut cursor)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(fault_of(&db, PROGRAM).await.is_some());
    assert!(fault_of(&db, healthy).await.is_none());
    cursor.resume(&db).await.unwrap();
    assert!(matches!(
        lookup(&db, &projector.rpc, request(PROGRAM, 4)).await,
        Err(PhotonApiError::RingProjection(
            RingProjectionError::SpendRecordOutOfSync(_)
        ))
    ));

    let mut restarted = storage::cursor(&db).await.unwrap().unwrap();
    let tx = db.begin().await.unwrap();
    storage::rollback(&tx, &mut restarted).await.unwrap();
    tx.commit().await.unwrap();
    assert!(fault_of(&db, PROGRAM).await.is_none());
}

async fn fault_of(db: &DatabaseConnection, program: [u8; 32]) -> Option<String> {
    SpendStore::new(db, program)
        .ring()
        .await
        .unwrap()
        .unwrap()
        .fault
}

fn request(program: [u8; 32], seed: u8) -> RingSpendRecordRequest {
    RingSpendRecordRequest {
        ring_program_id: Pubkey::new_from_array(program).into(),
        member: Hash(member(seed)),
    }
}

async fn chain_at(tip: BlockMetadata) -> (RpcClient, ServerHandle) {
    let server = jsonrpsee::server::ServerBuilder::default()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let mut module = jsonrpsee::RpcModule::new(tip);
    module
        .register_method("getBlock", |_, tip, _| {
            json!({"blockhash": tip.blockhash.to_string(),
                "previousBlockhash": Hash(field(0)).to_string(), "parentSlot": 0,
                "blockTime": tip.block_time, "blockHeight": tip.slot, "transactions": []})
        })
        .unwrap();
    (
        RpcClient::new(format!("http://{address}")),
        server.start(module),
    )
}

#[tokio::test]
async fn lookups_report_the_projection_tip_and_refuse_unindexed_state() {
    let (db, mut cursor) = fixture().await;
    let (rpc, handle) = chain_at(block(7)).await;
    assert!(matches!(
        lookup(&db, &rpc, request(PROGRAM, 4)).await,
        Err(PhotonApiError::RingProjection(
            RingProjectionError::SpendRecordOutOfSync(_)
        ))
    ));
    cursor.tip = Some(block(7));
    cursor.resume(&db).await.unwrap();
    let unregistered = lookup(&db, &rpc, request(PROGRAM, 4)).await.unwrap();
    assert!(unregistered.record.is_none());
    assert_eq!(unregistered.context.slot, 7);
    assert_eq!(unregistered.context.block_time, 90);
    assert!(lookup(&db, &rpc, request([13; 32], 4))
        .await
        .unwrap()
        .record
        .is_none());
    SpendStore::new(&db, PROGRAM)
        .save(&row(4, 0))
        .await
        .unwrap();
    assert!(matches!(
        lookup(&db, &rpc, request(PROGRAM, 4)).await,
        Err(PhotonApiError::RingProjection(
            RingProjectionError::SpendRecordOutOfSync(_)
        ))
    ));
    assert!(matches!(
        lookup(
            &db,
            &rpc,
            RingSpendRecordRequest {
                member: Hash([0; 32]),
                ..request(PROGRAM, 4)
            }
        )
        .await,
        Err(PhotonApiError::ValidationError(_))
    ));
    handle.stop().unwrap();
    handle.stopped().await;
}

#[test]
fn projection_errors_keep_their_wire_codes() {
    for (error, code) in [
        (
            RingProjectionError::OutOfSync {
                kind: ProjectionKind::KeyRegistry,
                reason: String::new(),
            },
            -32074,
        ),
        (
            RingProjectionError::RootChanged(ProjectionKind::KeyRegistry),
            -32075,
        ),
        (
            RingProjectionError::MemberUnregistered(ProjectionKind::KeyRegistry),
            -32076,
        ),
        (
            RingProjectionError::MemberAlreadyRegistered(ProjectionKind::KeyRegistry),
            -32077,
        ),
        (
            RingProjectionError::SpendRecordOutOfSync(String::new()),
            -32078,
        ),
    ] {
        assert_eq!(
            jsonrpsee::types::ErrorObjectOwned::from(PhotonApiError::from(error)).code(),
            code
        );
    }
}

#[test]
fn invocation_subtree_excludes_sibling_emissions() {
    let ix = |program, tag, depth| Instruction {
        program_id: Pubkey::new_from_array([program; 32]),
        data: vec![tag],
        accounts: vec![],
        stack_height: Some(depth),
    };
    let transaction = TransactionInfo {
        signature: Signature::from([1; 64]),
        error: None,
        instruction_groups: vec![InstructionGroup {
            outer_instruction: ix(1, 99, 1),
            inner_instructions: vec![
                ix(2, tag::TRANSACT, 2),
                ix(3, 77, 3),
                ix(4, 88, 2),
                ix(5, 77, 3),
            ],
        }],
    };
    let invocations = Invocations::new(&transaction, 1);
    let invocation = invocations.invocation(1).unwrap();
    assert_eq!(
        invocation.instruction.program_id,
        Pubkey::new_from_array([2; 32])
    );
    let children = &invocation.subtree.instruction_groups[0].inner_instructions;
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].program_id, Pubkey::new_from_array([3; 32]));
}

fn spend_fixture() -> (RingsTransactionUpdate, [u8; 32], SpendRecord) {
    let namespace = Pubkey::new_from_array([9; 32]).to_bytes();
    let entries_tree = zolana_interface::pda::tree(7).to_bytes();
    let record = SpendRecord {
        member: Member::owner_tag(&[5; 32]).unwrap(),
        version: 1,
        window: 2,
        counters_commitment: SpendCounters::EMPTY.commitment().unwrap(),
        blinding: field(13),
    };
    let owner = ListNamespace::new(&namespace).unwrap();
    let address = owner.spend_address(&record.member, 7).unwrap();
    let event = RingsTransactionUpdate {
        signature: Signature::from([1; 64]),
        event_index: 0,
        slot: 1,
        ring_config: None,
        source_instruction_tag: i16::from(zolana_event::tag::RING_TRANSACT),
        output_tree: entries_tree,
        first_output_leaf_index: 0,
        tx_viewing_pk: None,
        salt: None,
        proofless: false,
        encrypted_utxos: None,
        raw_event: None,
        parse_version: 1,
        outputs: vec![RingsOutputUpdate {
            output_index: 0,
            output_tree: entries_tree,
            leaf_index: 0,
            view_tag: namespace,
            utxo_hash: record.utxo_hash(&owner, &address, 7).unwrap(),
            payload: vec![zolana_event::OutputDataEncoding::ENCRYPTED_TAG],
        }],
        messages: vec![RingsMessageUpdate {
            message_index: 0,
            view_tag: spend_record_message_tag(&namespace).unwrap(),
            payload: record.to_output_data().to_vec(),
        }],
        nullifiers: vec![],
    };
    (event, namespace, record)
}

fn context<'a>(namespace: [u8; 32], rail: &'a Rail) -> SuccessorContext<'a> {
    SuccessorContext {
        namespace,
        rail,
        entries_tree: zolana_interface::pda::tree(7).to_bytes(),
        entries_tree_id: 7,
    }
}

#[test]
fn record_message_opens_the_confidential_successor_and_registration_stays_plaintext() {
    let (mut event, namespace, record) = spend_fixture();
    assert_eq!(
        parser::successor(&event, &context(namespace, &Rail::Transfer)).unwrap(),
        record
    );
    event.messages.clear();
    event.outputs[0].payload = record.to_output_data().to_vec();
    let registration = Rail::Register { blinding: field(2) };
    assert_eq!(
        parser::successor(&event, &context(namespace, &registration)).unwrap(),
        record
    );
}

fn transfer_refusal(event: &RingsTransactionUpdate, namespace: [u8; 32]) -> String {
    parser::successor(event, &context(namespace, &Rail::Transfer))
        .unwrap_err()
        .to_string()
}

#[test]
fn missing_duplicate_foreign_and_malformed_record_messages_are_refused() {
    let (event, namespace, _) = spend_fixture();
    let mut changed = event.clone();
    changed.messages.clear();
    assert_eq!(
        transfer_refusal(&changed, namespace),
        "spend-record message missing"
    );
    let mut changed = event.clone();
    changed.messages.push(changed.messages[0].clone());
    assert_eq!(
        transfer_refusal(&changed, namespace),
        "duplicate spend-record messages"
    );
    let mut changed = event.clone();
    changed.messages[0].view_tag = namespace;
    assert_eq!(
        transfer_refusal(&changed, namespace),
        "spend-record message missing"
    );
    let mut changed = event;
    changed.messages[0].payload.pop();
    assert_eq!(
        transfer_refusal(&changed, namespace),
        "malformed spend-record message"
    );
}

#[test]
fn a_record_message_cannot_be_associated_with_another_output_or_tree() {
    let (event, namespace, record) = spend_fixture();
    let unopened = "spend-record message does not open its successor output";
    let mut changed = event.clone();
    changed.outputs[0].utxo_hash = [0; 32];
    assert_eq!(transfer_refusal(&changed, namespace), unopened);
    let mut changed = event.clone();
    changed.outputs[0].output_tree = [0; 32];
    assert_eq!(transfer_refusal(&changed, namespace), unopened);
    let mut changed = event.clone();
    changed.outputs[0].view_tag = [0; 32];
    assert_eq!(
        transfer_refusal(&changed, namespace),
        "spend-record output belongs to another namespace"
    );
    let mut changed = event;
    changed.outputs[0].payload = record.to_output_data().to_vec();
    assert_eq!(
        transfer_refusal(&changed, namespace),
        "transfer spend-record output is not confidential"
    );
}

#[test]
fn an_emit_event_without_an_spp_parent_cannot_update_a_record() {
    let mut data = vec![tag::REGISTER_SPEND];
    data.extend(
        wincode::serialize(&custom_ring_interface::RegisterSpendIxData {
            blinding: field(2),
            private_tx_blinding: field(3),
            nullifier_tree_root_index: 0,
            utxo_tree_root_index: 0,
            proof: zolana_interface::instruction::instruction_data::transact::TransactProof::zeroed(
            ),
        })
        .unwrap(),
    );
    let instruction = Instruction {
        program_id: Pubkey::new_from_array(PROGRAM),
        data,
        accounts: vec![Pubkey::new_from_array([2; 32]); 10],
        stack_height: Some(1),
    };
    let transaction = TransactionInfo {
        signature: Signature::from([1; 64]),
        error: None,
        instruction_groups: vec![InstructionGroup {
            outer_instruction: instruction.clone(),
            inner_instructions: vec![Instruction {
                program_id: zolana_interface::pda::shielded_pool_program_id(),
                data: vec![zolana_event::tag::EMIT_EVENT, 0, 0],
                accounts: vec![],
                stack_height: Some(2),
            }],
        }],
    };
    let invocations = Invocations::new(&transaction, 1);
    let invocation = invocations.invocation(0).unwrap();
    assert!(matches!(
        parser::decode(&instruction).unwrap(),
        Some(Rail::Register { .. })
    ));
    assert!(parser::event(&invocation).is_err());
}
