use super::{
    parser::{self, Decoded, Rail, SuccessorContext},
    *,
};
use crate::{
    api::error::RingProjectionError,
    ingester::{
        parser::state_update::{RingsMessageUpdate, RingsOutputUpdate, RingsTransactionUpdate},
        typedefs::block_info::{BlockMetadata, Instruction, InstructionGroup, TransactionInfo},
    },
    ring_projection::{
        proof::{self, PathOverlay},
        storage::{self, BlockJournal, BlockUndo},
        tests::{field, fixture, member},
        Invocations, EMPTY_ROOT,
    },
};
use custom_ring_interface::{instruction::tag, PlainGroth16Proof, RegisterSpendIxData};
use sea_orm::TransactionTrait;
use solana_signature::Signature;
use zolana_indexer_api::RingHeadRecord;
use zolana_indexer_api::ShieldedTransaction;
use zolana_ring_head_map::{HeadMap as ReferenceHeadMap, HeadTransfer};
use zolana_ring_policy::{
    spend_record_message_tag, ListNamespace, Member, SpendCounters, SpendRecord,
};

fn record() -> RingHeadRecord {
    RingHeadRecord {
        output_index: 0,
        transaction: ShieldedTransaction {
            slot: 1,
            tx_signature: Signature::from([1; 64]).into(),
            event_index: Some(0),
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

fn registration(root: &RingRoot, seed: u8, new_root: [u8; 32]) -> Transition {
    Transition::Register(Registration {
        old_root: root.root,
        new_root,
        next_index: root.next_index,
        member: member(seed),
        nullifier: field(seed),
        record: record(),
    })
}

fn registration_wire() -> RegisterSpendIxData {
    RegisterSpendIxData {
        blinding: field(2),
        private_tx_blinding: field(3),
        nullifier_tree_root_index: 0,
        utxo_tree_root_index: 0,
        proof: zolana_interface::instruction::instruction_data::transact::TransactProof::zeroed(),
        head_old_root: EMPTY_ROOT,
        head_new_root: field(7),
        head_next_index: 1,
        head_proof: PlainGroth16Proof {
            proof_a: [0; 32],
            proof_b: [0; 64],
            proof_c: [0; 32],
        },
    }
}

#[tokio::test]
async fn head_insert_path_matches_reference_without_mutating_reads() {
    let (db, mut root, mut cursor) = fixture::<HeadMap>().await;
    let mut reference = ReferenceHeadMap::new().unwrap();
    for seed in [5, 9, 2, 8] {
        let subject = member(seed);
        let tx = db.begin().await.unwrap();
        let store = RingStore::<_, HeadMap>::new(&tx, root.program);
        let low = store.predecessor(&subject).await.unwrap();
        let low_path = proof::path::<HeadMap>(&tx, &root, low.index())
            .await
            .unwrap();
        let mut new_path = proof::path::<HeadMap>(&tx, &root, root.next_index)
            .await
            .unwrap();
        assert_eq!(new_path.leaf, [0; 32]);
        let mut spliced = low.clone();
        spliced.set_next(subject);
        PathOverlay {
            updated_index: low.index(),
            updated_leaf: spliced.hash().unwrap(),
            updated_path: &low_path.siblings,
        }
        .apply(root.next_index, &mut new_path)
        .unwrap();
        let inputs = reference
            .register(zolana_ring_head_map::Registration {
                member: subject,
                genesis: field(seed),
            })
            .unwrap();
        assert_eq!(low_path.siblings, inputs.low_proof);
        assert_eq!(new_path.siblings, inputs.new_proof);
        assert_eq!(store.root().await.unwrap().unwrap().root, root.root);
        HeadMap::apply(
            &store,
            Step {
                root: &root,
                transition: registration(&root, seed, inputs.new_root),
                revision: cursor.advance_revision().unwrap(),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        root = RingStore::<_, HeadMap>::new(&db, root.program)
            .root()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(root.root, reference.root());
    }
}

#[tokio::test]
async fn failed_head_transition_rolls_back_and_committed_block_rewinds_and_replays() {
    let (db, root, mut cursor) = fixture::<HeadMap>().await;
    let subject = member(8);
    let mut reference = ReferenceHeadMap::new().unwrap();
    let registered = reference
        .register(zolana_ring_head_map::Registration {
            member: subject,
            genesis: field(8),
        })
        .unwrap();
    let tx = db.begin().await.unwrap();
    assert!(HeadMap::apply(
        &RingStore::new(&tx, root.program),
        Step {
            root: &root,
            transition: registration(&root, 8, field(99)),
            revision: 2,
        },
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    let store = RingStore::<_, HeadMap>::new(&db, root.program);
    assert!(store.member(&subject).await.unwrap().is_none());
    assert_eq!(store.root().await.unwrap().unwrap().root, root.root);

    let tx = db.begin().await.unwrap();
    let added = HeadMap::apply(
        &RingStore::new(&tx, root.program),
        Step {
            root: &root,
            transition: registration(&root, 8, registered.new_root),
            revision: cursor.advance_revision().unwrap(),
        },
    )
    .await
    .unwrap();
    let registered_root = RingStore::<_, HeadMap>::new(&tx, root.program)
        .root()
        .await
        .unwrap()
        .unwrap();
    let next = reference
        .transfer(HeadTransfer {
            member: subject,
            spent: field(8),
            successor: field(9),
        })
        .unwrap();
    let moved = HeadMap::apply(
        &RingStore::new(&tx, root.program),
        Step {
            root: &registered_root,
            transition: Transition::Transfer(Transfer {
                old_root: next.old_root,
                new_root: next.new_root,
                member: subject,
                nullifiers: vec![field(1), field(8)],
                nullifier: field(9),
                record: record(),
            }),
            revision: cursor.advance_revision().unwrap(),
        },
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
            undo: BlockUndo {
                head_map: vec![added, moved],
                key_registry: vec![],
            },
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
    assert!(store.member(&subject).await.unwrap().is_none());
    assert_eq!(store.root().await.unwrap().unwrap().root, root.root);
    assert!(restarted.tip.is_none());
    assert!(!restarted.is_ready());

    let tx = db.begin().await.unwrap();
    let path = proof::path::<HeadMap>(&tx, &root, 0).await.unwrap();
    let sentinel = RingStore::<_, HeadMap>::new(&tx, root.program)
        .member(&[0; 32])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sentinel.hash().unwrap(), path.leaf);
    assert_eq!(path.root(0).unwrap(), root.root);
    HeadMap::apply(
        &RingStore::new(&tx, root.program),
        Step {
            root: &root,
            transition: registration(&root, 8, registered.new_root),
            revision: restarted.advance_revision().unwrap(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        store.root().await.unwrap().unwrap().root,
        registered.new_root
    );
}

#[tokio::test]
async fn a_transfer_must_consume_the_member_head() {
    let (db, root, mut cursor) = fixture::<HeadMap>().await;
    let subject = member(8);
    let mut reference = ReferenceHeadMap::new().unwrap();
    let registered = reference
        .register(zolana_ring_head_map::Registration {
            member: subject,
            genesis: field(8),
        })
        .unwrap();
    let tx = db.begin().await.unwrap();
    HeadMap::apply(
        &RingStore::new(&tx, root.program),
        Step {
            root: &root,
            transition: registration(&root, 8, registered.new_root),
            revision: cursor.advance_revision().unwrap(),
        },
    )
    .await
    .unwrap();
    let registered_root = RingStore::<_, HeadMap>::new(&tx, root.program)
        .root()
        .await
        .unwrap()
        .unwrap();
    let next = reference
        .transfer(HeadTransfer {
            member: subject,
            spent: field(8),
            successor: field(9),
        })
        .unwrap();
    let transfer = |nullifiers: Vec<[u8; 32]>| {
        Transition::Transfer(Transfer {
            old_root: next.old_root,
            new_root: next.new_root,
            member: subject,
            nullifiers,
            nullifier: field(9),
            record: record(),
        })
    };
    assert!(matches!(
        HeadMap::apply(
            &RingStore::new(&tx, root.program),
            Step {
                root: &registered_root,
                transition: transfer(vec![field(1)]),
                revision: cursor.advance_revision().unwrap(),
            },
        )
        .await,
        Err(ProjectError::Fault(_))
    ));
    HeadMap::apply(
        &RingStore::new(&tx, root.program),
        Step {
            root: &registered_root,
            transition: transfer(vec![field(1), field(8)]),
            revision: cursor.advance_revision().unwrap(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
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
    let registration = Rail::Register {
        blinding: field(2),
        next_index: 1,
    };
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
fn an_emit_event_without_an_spp_transition_parent_cannot_advance_a_head() {
    let program = Pubkey::new_from_array([11; 32]);
    let mut data = vec![tag::REGISTER_SPEND];
    data.extend(wincode::serialize(&registration_wire()).unwrap());
    let mut accounts = vec![Pubkey::new_from_array([2; 32]); 10];
    accounts[accounts::REGISTER_SPEND_HEAD_ROOT] = HeadMap::root_address(&program).0;
    let instruction = Instruction {
        program_id: program,
        data,
        accounts,
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
    let Decoded {
        rail,
        old_root,
        new_root,
    } = parser::decode(&instruction).unwrap().unwrap();
    assert!(matches!(rail, Rail::Register { .. }));
    let decoded = Decoded {
        rail,
        old_root,
        new_root,
    };
    let policy = bytemuck::Zeroable::zeroed();
    assert!(parser::reconstruct(&invocation, decoded, &policy).is_err());
}

#[tokio::test]
async fn head_proof_requests_fail_closed_before_rpc_when_projection_or_root_is_stale() {
    let (db, root, mut cursor) = fixture::<HeadMap>().await;
    let rpc = RpcClient::new("http://127.0.0.1:1".into());
    let request = RingMemberProofRequest {
        ring_program_id: Pubkey::new_from_array(root.program).into(),
        member: Hash(member(4)),
        expected_root: Hash(root.root),
        expected_next_index: 1,
    };
    assert!(matches!(
        register(&db, &rpc, request.clone()).await,
        Err(PhotonApiError::RingProjection(
            RingProjectionError::OutOfSync {
                kind: ProjectionKind::HeadMap,
                ..
            }
        ))
    ));
    cursor.resume(&db).await.unwrap();
    let mut stale = request;
    stale.expected_next_index = 2;
    assert_eq!(
        transfer(&db, &rpc, stale).await,
        Err(RingProjectionError::RootChanged(ProjectionKind::HeadMap).into())
    );
    for (error, code) in [
        (
            RingProjectionError::OutOfSync {
                kind: ProjectionKind::HeadMap,
                reason: String::new(),
            },
            -32070,
        ),
        (
            RingProjectionError::RootChanged(ProjectionKind::HeadMap),
            -32071,
        ),
        (
            RingProjectionError::MemberUnregistered(ProjectionKind::HeadMap),
            -32072,
        ),
        (
            RingProjectionError::MemberAlreadyRegistered(ProjectionKind::HeadMap),
            -32073,
        ),
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
    ] {
        assert_eq!(
            jsonrpsee::types::ErrorObjectOwned::from(PhotonApiError::from(error)).code(),
            code
        );
    }
}
