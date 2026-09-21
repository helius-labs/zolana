use super::*;
use crate::{
    api::error::{PhotonApiError, RingProjectionError},
    ingester::typedefs::block_info::{BlockMetadata, InstructionGroup, TransactionInfo},
    migration::{MigratorTrait, RingsMigrator},
};
use key_registry::KeyRegistry;
use sea_orm::Database;
use solana_signature::Signature;
use zolana_indexer_api::{Hash, RingMemberProofRequest};

pub(super) fn field(value: u8) -> [u8; 32] {
    let mut field = [0; 32];
    field[31] = value;
    field
}

pub(super) fn member(value: u8) -> [u8; 32] {
    *zolana_ring_policy::Member::owner_tag(&[value; 32])
        .unwrap()
        .as_bytes()
}

pub(super) async fn fixture<P: Projection>() -> (DatabaseConnection, RingRoot, ProjectionCursor) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    let mut cursor = ProjectionCursor::new(0);
    let root = initialize_root::<P>(&db, &mut cursor, [11; 32]).await;
    storage::save_cursor(&db, &cursor).await.unwrap();
    (db, root, cursor)
}

pub(super) async fn initialize_root<P: Projection>(
    db: &DatabaseConnection,
    cursor: &mut ProjectionCursor,
    program: [u8; 32],
) -> RingRoot {
    let root = RingRoot {
        program,
        address: P::root_address(&Pubkey::new_from_array(program))
            .0
            .to_bytes(),
        root: EMPTY_ROOT,
        next_index: 1,
        fault: None,
    };
    let sentinel = P::Leaf::sentinel();
    let tx = db.begin().await.unwrap();
    let store = RingStore::<_, P>::new(&tx, program);
    let computed = store
        .write_leaves(
            &root.address,
            &[LeafWrite {
                index: 0,
                hash: sentinel.hash().unwrap(),
            }],
            cursor.advance_revision().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(computed, root.root);
    store.save_root(&root).await.unwrap();
    store.save_member(&sentinel).await.unwrap();
    tx.commit().await.unwrap();
    root
}

pub(super) fn projector(db: &DatabaseConnection, start: StartSlot) -> Projector {
    Projector {
        db: Arc::new(db.clone()),
        rpc: Arc::new(RpcClient::new("http://127.0.0.1:1".into())),
        start,
    }
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
    let first = block_batch(&rpc, 1..=5100).await.unwrap();
    assert_eq!(first.slots, (5000..=5031).collect::<Vec<_>>());
    assert_eq!(first.scanned_slot, 5031);
    let second = block_batch(&rpc, 5032..=5100).await.unwrap();
    assert_eq!(second.slots, (5032..=5040).collect::<Vec<_>>());
    assert_eq!(second.scanned_slot, 5100);
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn an_explicit_start_slot_must_match_the_stored_cursor() {
    let (db, _, _) = fixture::<KeyRegistry>().await;
    assert!(projector(&db, StartSlot::Explicit(5))
        .cursor()
        .await
        .is_err());
    assert_eq!(
        projector(&db, StartSlot::Explicit(0))
            .cursor()
            .await
            .unwrap()
            .start_slot,
        0
    );
    assert_eq!(
        projector(&db, StartSlot::Derived(9))
            .cursor()
            .await
            .unwrap()
            .start_slot,
        0
    );
}

#[tokio::test]
async fn an_invalid_instruction_quarantines_only_its_ring_until_rollback() {
    let (db, faulty, mut cursor) = fixture::<KeyRegistry>().await;
    let healthy = initialize_root::<KeyRegistry>(&db, &mut cursor, [12; 32]).await;
    let garbage = |program: [u8; 32], error: Option<String>| TransactionInfo {
        signature: Signature::from([1; 64]),
        error,
        instruction_groups: vec![InstructionGroup {
            outer_instruction: Instruction {
                program_id: Pubkey::new_from_array(program),
                data: vec![
                    custom_ring_interface::instruction::tag::REGISTER_KEY,
                    1,
                    2,
                    3,
                ],
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
    let projector = projector(&db, StartSlot::Derived(0));
    let tx = db.begin().await.unwrap();
    projector
        .apply_block(&tx, &block, &mut cursor)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let faulted = RingStore::<_, KeyRegistry>::new(&db, faulty.program)
        .root()
        .await
        .unwrap()
        .unwrap();
    assert!(faulted.fault.is_some());
    assert!(RingStore::<_, KeyRegistry>::new(&db, healthy.program)
        .root()
        .await
        .unwrap()
        .unwrap()
        .fault
        .is_none());
    cursor.resume(&db).await.unwrap();
    let request = |program: [u8; 32]| RingMemberProofRequest {
        ring_program_id: Pubkey::new_from_array(program).into(),
        member: Hash(member(4)),
        expected_root: Hash(EMPTY_ROOT),
        expected_next_index: 1,
    };
    assert!(matches!(
        key_registry::lookup(&db, &projector.rpc, request(faulty.program)).await,
        Err(PhotonApiError::RingProjection(
            RingProjectionError::OutOfSync { .. }
        ))
    ));
    assert_eq!(
        key_registry::lookup(&db, &projector.rpc, request(healthy.program)).await,
        Err(RingProjectionError::MemberUnregistered(ProjectionKind::KeyRegistry).into())
    );

    let mut restarted = storage::cursor(&db).await.unwrap().unwrap();
    let tx = db.begin().await.unwrap();
    storage::rollback(&tx, &mut restarted).await.unwrap();
    tx.commit().await.unwrap();
    assert!(RingStore::<_, KeyRegistry>::new(&db, faulty.program)
        .root()
        .await
        .unwrap()
        .unwrap()
        .fault
        .is_none());
    assert!(restarted.tip.is_none());
}
