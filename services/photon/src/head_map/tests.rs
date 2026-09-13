use super::*;
use crate::{
    ingester::typedefs::block_info::{
        BlockMetadata, Instruction, InstructionGroup, TransactionInfo,
    },
    migration::{MigratorTrait, RingsMigrator},
};
use sea_orm::Database;
use solana_signature::Signature;
use zolana_indexer_api::{Hash, RingHeadRecord, ShieldedTransaction};

fn field(value: u8) -> [u8; 32] {
    let mut field = [0; 32];
    field[31] = value;
    field
}
fn member(value: u8) -> [u8; 32] {
    *zolana_ring_policy::Member::owner_tag(&[value; 32])
        .unwrap()
        .as_bytes()
}
fn record() -> RingHeadRecord {
    RingHeadRecord {
        output_index: 0,
        transaction: ShieldedTransaction {
            slot: 1,
            tx_signature: Signature::from([1; 64]).into(),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![],
            messages: vec![],
            nullifiers: vec![],
            proofless: false,
            ring_config: None,
            ring_program_id: None,
        },
    }
}

#[test]
fn production_parent_links_require_both_slot_and_hash() {
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
    assert!(linked(&parent, &child));
    child.parent_blockhash = Hash(field(2));
    assert!(!linked(&parent, &child));
    child.parent_blockhash = parent.blockhash.clone();
    child.parent_slot = 18;
    assert!(!linked(&parent, &child));
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

async fn fixture() -> (DatabaseConnection, Map, Cursor) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    let program = [11; 32];
    let map = Map {
        program,
        address: parser::root_address(&Pubkey::new_from_array(program)).to_bytes(),
        root: custom_ring_interface::HEAD_MAP_EMPTY_ROOT,
        next_index: 1,
    };
    let sentinel = Member {
        member: [0; 32],
        index: 0,
        next: zolana_ring_head_map::FIELD_MAX,
        nullifier: [0; 32],
        record: None,
    };
    let cursor = Cursor {
        start_slot: 0,
        scanned_slot: 0,
        tip: None,
        revision: 1,
        ready: false,
    };
    let tx = db.begin().await.unwrap();
    assert_eq!(
        storage::write_leaves(&tx, &map, &[(0, sentinel.hash().unwrap())], 1)
            .await
            .unwrap(),
        map.root
    );
    storage::save_map(&tx, &map).await.unwrap();
    storage::save_member(&tx, &program, &sentinel)
        .await
        .unwrap();
    storage::save_cursor(&tx, &cursor).await.unwrap();
    tx.commit().await.unwrap();
    (db, map, cursor)
}

#[tokio::test]
async fn persistent_insert_path_matches_reference_without_mutating_reads() {
    let (db, mut map, mut cursor) = fixture().await;
    let mut reference = zolana_ring_head_map::HeadMap::new().unwrap();
    for seed in [5, 9, 2, 8] {
        let subject = member(seed);
        let tx = db.begin().await.unwrap();
        let low = storage::predecessor(&tx, &map.program, &subject)
            .await
            .unwrap();
        let (_, low_proof) = proof::path(&tx, &map, low.index).await.unwrap();
        let (empty, mut new_proof) = proof::path(&tx, &map, map.next_index).await.unwrap();
        assert_eq!(empty, [0; 32]);
        let changed =
            custom_ring_interface::head_map_leaf(&low.member, &subject, &low.nullifier).unwrap();
        proof::after_update(
            low.index,
            changed,
            &low_proof,
            map.next_index,
            &mut new_proof,
        )
        .unwrap();
        let witness = reference.register(subject, field(seed)).unwrap();
        assert_eq!(low_proof, witness.low_proof);
        assert_eq!(new_proof, witness.new_proof);
        assert_eq!(
            storage::map(&tx, &map.program).await.unwrap().unwrap().root,
            map.root
        );
        let transition = Transition::Register {
            old_root: map.root,
            new_root: witness.new_root,
            next_index: map.next_index,
            member: subject,
            nullifier: field(seed),
            record: record(),
        };
        apply_transition(&tx, &map, transition, cursor.advance_revision().unwrap())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        map = storage::map(&db, &map.program).await.unwrap().unwrap();
        assert_eq!(map.root, reference.root());
    }
}

#[tokio::test]
async fn failed_transition_rolls_back_and_committed_block_rewinds_and_replays() {
    let (db, map, mut cursor) = fixture().await;
    let subject = member(8);
    let mut reference = zolana_ring_head_map::HeadMap::new().unwrap();
    let registration = reference.register(subject, field(8)).unwrap();
    let tx = db.begin().await.unwrap();
    assert!(apply_transition(
        &tx,
        &map,
        Transition::Register {
            old_root: map.root,
            new_root: field(99),
            next_index: 1,
            member: subject,
            nullifier: field(8),
            record: record()
        },
        2
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    assert!(storage::member(&db, &map.program, &subject)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        storage::map(&db, &map.program).await.unwrap().unwrap().root,
        map.root
    );

    let tx = db.begin().await.unwrap();
    let registered = apply_transition(
        &tx,
        &map,
        Transition::Register {
            old_root: map.root,
            new_root: registration.new_root,
            next_index: 1,
            member: subject,
            nullifier: field(8),
            record: record(),
        },
        cursor.advance_revision().unwrap(),
    )
    .await
    .unwrap();
    let registered_map = storage::map(&tx, &map.program).await.unwrap().unwrap();
    let next = reference.transfer(&subject, &field(8), field(9)).unwrap();
    let moved = apply_transition(
        &tx,
        &registered_map,
        Transition::Transfer {
            old_root: next.old_root,
            new_root: next.new_root,
            member: subject,
            spent: field(8),
            nullifier: field(9),
            record: record(),
        },
        cursor.advance_revision().unwrap(),
    )
    .await
    .unwrap();
    let metadata = BlockMetadata {
        slot: 3,
        blockhash: Hash(field(3)),
        ..Default::default()
    };
    storage::save_journal(
        &tx,
        &BlockJournal {
            metadata: metadata.clone(),
            previous_tip: None,
            undo: vec![registered, moved],
        },
    )
    .await
    .unwrap();
    cursor.tip = Some(metadata);
    cursor.scanned_slot = 3;
    storage::save_cursor(&tx, &cursor).await.unwrap();
    tx.commit().await.unwrap();

    let mut restarted = storage::cursor(&db).await.unwrap().unwrap();
    let tx = db.begin().await.unwrap();
    storage::rollback(&tx, &mut restarted).await.unwrap();
    tx.commit().await.unwrap();
    assert!(storage::member(&db, &map.program, &subject)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        storage::map(&db, &map.program).await.unwrap().unwrap().root,
        map.root
    );
    assert!(restarted.tip.is_none());
    assert!(!restarted.ready);
    let tx = db.begin().await.unwrap();
    let (_, proof) = proof::path(&tx, &map, 0).await.unwrap();
    let sentinel = storage::member(&tx, &map.program, &[0; 32])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        super::proof::root(sentinel.hash().unwrap(), 0, &proof).unwrap(),
        map.root
    );
    apply_transition(
        &tx,
        &map,
        Transition::Register {
            old_root: map.root,
            new_root: registration.new_root,
            next_index: 1,
            member: subject,
            nullifier: field(8),
            record: record(),
        },
        restarted.advance_revision().unwrap(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        storage::map(&db, &map.program).await.unwrap().unwrap().root,
        registration.new_root
    );
}

#[test]
fn invocation_subtree_excludes_sibling_emissions_and_failed_transactions() {
    let ix = |program, tag, depth| Instruction {
        program_id: Pubkey::new_from_array([program; 32]),
        data: vec![tag],
        accounts: vec![],
        stack_height: Some(depth),
    };
    let mut transaction = TransactionInfo {
        signature: Signature::from([1; 64]),
        error: None,
        instruction_groups: vec![InstructionGroup {
            outer_instruction: ix(1, 99, 1),
            inner_instructions: vec![
                ix(2, custom_ring_interface::instruction::tag::TRANSACT, 2),
                ix(3, 77, 3),
                ix(4, 88, 2),
                ix(5, 77, 3),
            ],
        }],
    };
    let invocations = parser::invocations(&transaction).unwrap();
    assert_eq!(invocations.len(), 1);
    assert_eq!(
        invocations[0].1.instruction_groups[0]
            .inner_instructions
            .len(),
        1
    );
    assert_eq!(
        invocations[0].1.instruction_groups[0].inner_instructions[0].program_id,
        Pubkey::new_from_array([3; 32])
    );
    transaction.error = Some("failed".into());
    assert!(parser::invocations(&transaction).unwrap().is_empty());
}

#[test]
fn path_indices_cannot_alias_above_the_circuit_height() {
    assert!(proof::root([0; 32], proof::CAPACITY, &[[0; 32]; proof::HEIGHT]).is_err());
    assert!(proof::after_update(
        proof::CAPACITY,
        [0; 32],
        &[[0; 32]; proof::HEIGHT],
        1,
        &mut [[0; 32]; proof::HEIGHT]
    )
    .is_err());
}

#[test]
fn an_emit_event_without_an_spp_transition_parent_cannot_advance_a_head() {
    use custom_ring_interface::{instruction::tag, PlainGroth16Proof, RegisterSpendIxData};
    let program = Pubkey::new_from_array([11; 32]);
    let wire = RegisterSpendIxData {
        blinding: field(2),
        private_tx_blinding: field(3),
        nullifier_tree_root_index: 0,
        utxo_tree_root_index: 0,
        proof: zolana_interface::instruction::instruction_data::transact::TransactProof::zeroed(),
        head_old_root: custom_ring_interface::HEAD_MAP_EMPTY_ROOT,
        head_new_root: field(7),
        head_next_index: 1,
        head_proof: PlainGroth16Proof {
            proof_a: [0; 32],
            proof_b: [0; 64],
            proof_c: [0; 32],
        },
    };
    let mut data = vec![tag::REGISTER_SPEND];
    data.extend(wincode::serialize(&wire).unwrap());
    let mut accounts = vec![Pubkey::new_from_array([2; 32]); 10];
    accounts[9] = parser::root_address(&program);
    let instruction = Instruction {
        program_id: program,
        data,
        accounts,
        stack_height: Some(1),
    };
    let subtree = TransactionInfo {
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
    assert!(parser::transition(
        &instruction,
        &subtree,
        parser::TransitionContext {
            slot: 1,
            entries_tree: [0; 32],
            entries_tree_id: 0,
        },
    )
    .is_err());
}

#[tokio::test]
async fn witness_requests_fail_closed_before_rpc_when_projection_or_root_is_stale() {
    use crate::api::error::PhotonApiError;
    use zolana_indexer_api::GetRingHeadProofRequest;
    let (db, map, mut cursor) = fixture().await;
    let rpc = RpcClient::new("http://127.0.0.1:1".into());
    let request = GetRingHeadProofRequest {
        ring_program_id: Pubkey::new_from_array(map.program).into(),
        member: Hash(member(4)),
        expected_root: Hash(map.root),
        expected_next_index: 1,
    };
    assert!(matches!(
        api::register(&db, &rpc, request.clone()).await,
        Err(PhotonApiError::HeadMapOutOfSync(_))
    ));
    cursor.ready = true;
    storage::save_cursor(&db, &cursor).await.unwrap();
    let mut stale = request;
    stale.expected_next_index = 2;
    assert_eq!(
        api::transfer(&db, &rpc, stale).await,
        Err(PhotonApiError::HeadRootChanged)
    );
    for (error, code) in [
        (PhotonApiError::HeadRootChanged, -32071),
        (PhotonApiError::HeadMemberUnregistered, -32072),
        (PhotonApiError::HeadMemberAlreadyRegistered, -32073),
    ] {
        assert_eq!(jsonrpsee::types::ErrorObjectOwned::from(error).code(), code);
    }
}
