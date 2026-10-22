use super::*;
use crate::{
    api::error::{CustomRingError, PhotonApiError},
    ingester::typedefs::block_info::{BlockMetadata, InstructionGroup, TransactionInfo},
    migration::{MigratorTrait, RingsMigrator},
};
use custom_ring_interface::{instruction::tag, MEMBER_REGISTRY_EMPTY_ROOT};
use sea_orm::Database;
use solana_signature::Signature;
use std::sync::atomic::{AtomicUsize, Ordering};
use zolana_indexer_api::{GetRingMemberRecordRequest, GetRingMemberRecordsRequest, Hash};

pub(super) fn field(value: u8) -> [u8; 32] {
    let mut field = [0; 32];
    field[31] = value;
    field
}

pub(super) async fn database() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    db
}

pub(super) async fn fixture() -> (DatabaseConnection, RegistryState, CustomRingCursor) {
    let db = database().await;
    let cursor = CustomRingCursor::new(0);
    let state = create_registry(&db, [11; 32]).await;
    storage::save_cursor(&db, &cursor).await.unwrap();
    (db, state, cursor)
}

pub(super) async fn create_registry(db: &DatabaseConnection, program: [u8; 32]) -> RegistryState {
    let state = member_registry::created(program, 0);
    let tx = db.begin().await.unwrap();
    member_registry::create(&RegistryStore::new(&tx, program), &state)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    state
}

pub(super) fn indexer(db: &DatabaseConnection, start: StartSlot) -> CustomRingIndexer {
    CustomRingIndexer {
        db: Arc::new(db.clone()),
        rpc: Arc::new(RpcClient::new("http://127.0.0.1:1".into())),
        start,
        block_fetches: 4,
    }
}

fn record_request(state: &RegistryState, root: [u8; 32]) -> GetRingMemberRecordRequest {
    GetRingMemberRecordRequest {
        ring_program_id: Pubkey::new_from_array(state.program).into(),
        member: Hash(field(4)),
        expected_root: Hash(root),
        expected_next_index: 1,
    }
}

#[tokio::test]
async fn member_page_reports_a_missing_leaf_instead_of_skipping_it() {
    let (db, mut state, mut cursor) = fixture().await;
    state.registry.next_index = 2u32.to_le_bytes();
    RegistryStore::new(&db, state.program)
        .save_state(&state)
        .await
        .unwrap();
    cursor.resume(&db).await.unwrap();
    let request = GetRingMemberRecordsRequest {
        ring_program_id: Pubkey::new_from_array(state.program).into(),
        expected_root: Hash(MEMBER_REGISTRY_EMPTY_ROOT),
        expected_next_index: 2,
        start_index: 1,
        limit: 1,
    };
    let rpc = indexer(&db, StartSlot::Derived(0)).rpc;
    assert!(matches!(
        member_registry::member_records(&db, rpc.as_ref(), request).await,
        Err(PhotonApiError::CustomRing(CustomRingError::PageGap))
    ));
}

#[tokio::test]
async fn reads_fail_closed_before_rpc_while_catching_up_or_off_the_history() {
    let (db, state, mut cursor) = fixture().await;
    let rpc = indexer(&db, StartSlot::Derived(0)).rpc;
    let read = |request| member_registry::member_record(&db, rpc.as_ref(), request);
    let request = record_request(&state, MEMBER_REGISTRY_EMPTY_ROOT);
    let catching_up = CustomRingError::OutOfSync("indexer is catching up or recovering".into());
    assert_eq!(read(request.clone()).await, Err(catching_up.into()));
    cursor.resume(&db).await.unwrap();
    let off_history = record_request(&state, field(9));
    assert_eq!(
        read(off_history).await,
        Err(CustomRingError::RootChanged.into())
    );
    let mut stale = request.clone();
    stale.expected_next_index = 2;
    assert_eq!(read(stale).await, Err(CustomRingError::RootChanged.into()));
    // A held root passes every projection check and stops at the chain confirmation.
    let unconfirmed = CustomRingError::OutOfSync("cursor has no canonical block".into());
    assert_eq!(read(request).await, Err(unconfirmed.into()));
}

#[test]
fn parent_links_require_both_slot_and_hash() {
    let parent = BlockMetadata {
        slot: 17,
        blockhash: Hash(field(1)),
        ..Default::default()
    };
    let mut child = BlockMetadata {
        slot: 19,
        parent_slot: 17,
        parent_blockhash: parent.blockhash.clone(),
        ..Default::default()
    };
    assert!(parent.is_parent_of(&child));
    child.parent_blockhash = Hash(field(2));
    assert!(!parent.is_parent_of(&child));
    child.parent_blockhash = parent.blockhash.clone();
    child.parent_slot = 18;
    assert!(!parent.is_parent_of(&child));
}

#[tokio::test]
async fn block_batches_cross_skipped_pages_without_skipping_live_blocks() {
    let server = jsonrpsee::server::ServerBuilder::default()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_method("getBlocks", |params, _, _| {
            let (start, end, commitment): (u64, u64, serde_json::Value) = params.parse()?;
            assert_eq!(commitment["commitment"], "confirmed");
            Ok::<_, jsonrpsee::types::ErrorObjectOwned>(
                (5000..=5040)
                    .filter(|slot| (start..=end).contains(slot))
                    .collect::<Vec<_>>(),
            )
        })
        .unwrap();
    let handle = server.start(module);
    let rpc = RpcClient::new(format!("http://{address}"));
    let first = block_batch(&rpc, 1..=5100, MIN_BLOCK_BATCH).await.unwrap();
    assert_eq!(first.slots, (5000..=5031).collect::<Vec<_>>());
    assert_eq!(first.scanned_slot, 5031);
    let second = block_batch(&rpc, 5032..=5100, MIN_BLOCK_BATCH)
        .await
        .unwrap();
    assert_eq!(second.slots, (5032..=5040).collect::<Vec<_>>());
    assert_eq!(second.scanned_slot, 5100);
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn an_explicit_start_slot_must_match_the_stored_cursor() {
    let (db, _, _) = fixture().await;
    assert!(indexer(&db, StartSlot::Explicit(5)).cursor().await.is_err());
    assert_eq!(
        indexer(&db, StartSlot::Explicit(0))
            .cursor()
            .await
            .unwrap()
            .start_slot,
        0
    );
    assert_eq!(
        indexer(&db, StartSlot::Derived(9))
            .cursor()
            .await
            .unwrap()
            .start_slot,
        0
    );
}

#[tokio::test]
async fn an_invalid_instruction_quarantines_only_its_ring_until_rollback() {
    let (db, faulty, mut cursor) = fixture().await;
    let healthy = create_registry(&db, [12; 32]).await;
    let garbage = |program: [u8; 32], error: Option<String>| TransactionInfo {
        signature: Signature::from([1; 64]),
        error,
        instruction_groups: vec![InstructionGroup {
            outer_instruction: Instruction {
                program_id: Pubkey::new_from_array(program),
                data: vec![tag::REGISTER_KEY, 1, 2, 3],
                accounts: vec![],
                stack_height: Some(1),
            },
            inner_instructions: vec![],
        }],
    };
    let block = BlockInfo {
        metadata: BlockMetadata {
            slot: 3,
            blockhash: Hash(field(3)),
            ..Default::default()
        },
        transactions: vec![
            garbage(faulty.program, None),
            garbage(healthy.program, Some("failed".into())),
        ],
    };
    let indexer = indexer(&db, StartSlot::Derived(0));
    let tx = db.begin().await.unwrap();
    indexer.apply_block(&tx, &block, &mut cursor).await.unwrap();
    tx.commit().await.unwrap();

    let fault = |program: [u8; 32]| {
        let db = &db;
        async move {
            RegistryStore::new(db, program)
                .state()
                .await
                .unwrap()
                .unwrap()
                .fault
        }
    };
    assert!(fault(faulty.program).await.is_some());
    assert!(fault(healthy.program).await.is_none());
    cursor.resume(&db).await.unwrap();
    let read = |state: &RegistryState| {
        member_registry::member_record(
            &db,
            indexer.rpc.as_ref(),
            record_request(state, MEMBER_REGISTRY_EMPTY_ROOT),
        )
    };
    assert!(matches!(
        read(&faulty).await,
        Err(PhotonApiError::CustomRing(CustomRingError::OutOfSync(reason))) if reason.contains("quarantined")
    ));
    // The healthy ring serves the read up to the chain confirmation at the dead RPC.
    assert!(matches!(
        read(&healthy).await,
        Err(PhotonApiError::CustomRing(CustomRingError::OutOfSync(_)))
    ));

    let mut restarted = storage::cursor(&db).await.unwrap().unwrap();
    let tx = db.begin().await.unwrap();
    storage::rollback(&tx, &mut restarted).await.unwrap();
    tx.commit().await.unwrap();
    assert!(fault(faulty.program).await.is_none());
    assert!(restarted.tip.is_none());
}

#[tokio::test]
async fn record_shaped_instructions_of_other_programs_cost_no_queries() {
    let mut db = database().await;
    let statements = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&statements);
    db.set_metric_callback(move |_| {
        counted.fetch_add(1, Ordering::Relaxed);
    });
    create_registry(&db, [11; 32]).await;
    let foreign = Pubkey::new_from_array([0x55; 32]);
    let record_tags = [
        tag::CREATE_MEMBER_REGISTRY,
        tag::REGISTER_KEY,
        tag::WRITE_RECORDS,
        tag::AUTHORITY_WRITE_RECORDS,
        tag::APPLY_RECORDS,
    ];
    let shaped = record_tags
        .into_iter()
        .map(|tag| TransactionInfo {
            signature: Signature::from([1; 64]),
            error: None,
            instruction_groups: vec![InstructionGroup {
                outer_instruction: Instruction {
                    program_id: foreign,
                    data: vec![tag, 1, 2, 3],
                    accounts: vec![],
                    stack_height: Some(1),
                },
                inner_instructions: vec![],
            }],
        })
        .collect();
    let indexer = indexer(&db, StartSlot::Derived(0));
    let mut cursor = CustomRingCursor::new(0);
    let mut costs = Vec::new();
    for (slot, transactions) in [(3, Vec::new()), (4, shaped)] {
        let block = BlockInfo {
            metadata: BlockMetadata {
                slot,
                blockhash: Hash(field(slot as u8)),
                ..Default::default()
            },
            transactions,
        };
        let before = statements.load(Ordering::Relaxed);
        let tx = db.begin().await.unwrap();
        indexer.apply_block(&tx, &block, &mut cursor).await.unwrap();
        tx.commit().await.unwrap();
        costs.push(statements.load(Ordering::Relaxed) - before);
    }
    assert_eq!(costs[0], costs[1]);
}
