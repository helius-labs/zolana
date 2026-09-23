use super::tests::{field, initialize_root, member};
use super::*;
use crate::migration::{MigratorTrait, RingsMigrator};
use base64::{engine::general_purpose::STANDARD, Engine};
use custom_ring_interface::{
    instruction::tag, CustomRingProof, KeyRegistryRoot, RegisterKeyIxData, RegisteredKey,
};
use jsonrpsee::{server::ServerHandle, types::ErrorObjectOwned};
use sea_orm::Database;
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Mutex};
use zolana_indexer_api::{Hash, RingMemberProofRequest};

/// Mutable confirmed RPC history, including failures between replay commits.
#[derive(Default)]
struct Chain {
    blocks: BTreeMap<u64, Value>,
    accounts: HashMap<String, Value>,
    failed_block: Option<u64>,
}

async fn rpc(chain: Arc<Mutex<Chain>>) -> (Arc<RpcClient>, ServerHandle) {
    let server = jsonrpsee::server::ServerBuilder::default()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let mut module = jsonrpsee::RpcModule::new(chain);
    module
        .register_method("getSlot", |_, chain, _| {
            *chain.lock().unwrap().blocks.last_key_value().unwrap().0
        })
        .unwrap();
    module
        .register_method("getBlocks", |params, chain, _| {
            let (start, end, _): (u64, u64, Value) = params.parse()?;
            Ok::<_, ErrorObjectOwned>(
                chain
                    .lock()
                    .unwrap()
                    .blocks
                    .range(start..=end)
                    .map(|(slot, _)| *slot)
                    .collect::<Vec<_>>(),
            )
        })
        .unwrap();
    module
        .register_method("getBlock", |params, chain, _| {
            let (slot, options): (u64, Value) = params.parse()?;
            let chain = chain.lock().unwrap();
            if chain.failed_block == Some(slot) && options["transactionDetails"] == "full" {
                return Err(ErrorObjectOwned::owned(
                    -32000,
                    "temporary archive failure",
                    None::<()>,
                ));
            }
            chain
                .blocks
                .get(&slot)
                .cloned()
                .ok_or_else(|| ErrorObjectOwned::owned(-32007, "skipped", None::<()>))
        })
        .unwrap();
    module
        .register_method("getAccountInfo", |params, chain, _| {
            let (address, _): (String, Value) = params.parse()?;
            Ok::<_, ErrorObjectOwned>(
                json!({"value": chain.lock().unwrap().accounts.get(&address)}),
            )
        })
        .unwrap();
    module.register_method("getMultipleAccounts", |params, chain, _| {
        let (addresses, _): (Vec<String>, Value) = params.parse()?;
        let chain = chain.lock().unwrap();
        Ok::<_, ErrorObjectOwned>(json!({"value": addresses.iter().map(|address| chain.accounts.get(address)).collect::<Vec<_>>()}))
    }).unwrap();
    (
        Arc::new(RpcClient::new(format!("http://{address}"))),
        server.start(module),
    )
}

fn account(owner: Pubkey, data: &[u8]) -> Value {
    json!({"lamports": 1, "owner": owner.to_string(), "data": [STANDARD.encode(data), "base64"], "executable": false, "rentEpoch": 0})
}

fn root_account(program: Pubkey, root: [u8; 32], next_index: u64) -> Value {
    let mut history = [[0u8; 32]; custom_ring_interface::KEY_REGISTRY_ROOT_HISTORY];
    history[0] = root;
    account(
        program,
        bytemuck::bytes_of(&KeyRegistryRoot {
            discriminator: custom_ring_interface::KEY_REGISTRY_ROOT,
            next_index: next_index.to_le_bytes(),
            bump: key_registry::KeyRegistry::root_address(&program).1,
            history_cursor: 0,
            history,
        }),
    )
}

fn activation(program: Pubkey, active: bool) -> Value {
    account(
        zolana_interface::pda::shielded_pool_program_id(),
        bytemuck::bytes_of(&RingConfig {
            discriminator: RING_CONFIG,
            authority: Pubkey::default(),
            program_id: program,
            activated: u8::from(active),
            paused: 0,
            ring_authority_transact_is_enabled: 0,
            bump: 0,
        }),
    )
}

fn block(slot: u64, transactions: Vec<Value>) -> Value {
    json!({"blockhash": Hash(field(slot as u8)).to_string(),
        "previousBlockhash": Hash(field(slot.saturating_sub(1) as u8)).to_string(),
        "parentSlot": slot.saturating_sub(1), "blockTime": slot, "blockHeight": slot, "transactions": transactions})
}

/// Archived transactions must pass the production RPC decoder.
fn transaction(program: Pubkey, accounts: &[Pubkey], data: &[u8]) -> Value {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&[1; 64]);
    bytes.extend_from_slice(&[1, 0, 1, (accounts.len() + 1) as u8]);
    for key in accounts.iter().chain(std::iter::once(&program)) {
        bytes.extend_from_slice(key.as_ref());
    }
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(&[1, accounts.len() as u8, accounts.len() as u8]);
    bytes.extend(0..accounts.len() as u8);
    let mut length = data.len();
    loop {
        let byte = (length & 127) as u8;
        length >>= 7;
        bytes.push(byte | if length == 0 { 0 } else { 128 });
        if length == 0 {
            break;
        }
    }
    bytes.extend_from_slice(data);
    json!({"transaction": [STANDARD.encode(bytes), "base64"], "version": "legacy", "meta": {
        "err": null, "status": {"Ok": null}, "fee": 0,
        "preBalances": vec![1; accounts.len()+1], "postBalances": vec![1; accounts.len()+1],
        "innerInstructions": [], "logMessages": [], "loadedAddresses": {"readonly": [], "writable": []}
    }})
}

/// Initialization and first registration precede the global tip.
async fn late_ring() -> (Projector, Arc<Mutex<Chain>>, ServerHandle, Pubkey, [u8; 32]) {
    let program = Pubkey::new_from_array([11; 32]);
    let address = key_registry::KeyRegistry::root_address(&program).0;
    let mut tree = zolana_ring_key_registry::KeyRegistryTree::new().unwrap();
    let key = RegisteredKey {
        nullifier_pk: &field(5),
        ciphertext: &[5; 32],
    }
    .hash()
    .unwrap();
    let insertion = tree
        .register(zolana_ring_key_registry::Registration {
            member: member(5),
            key,
        })
        .unwrap();
    let mut data = vec![tag::REGISTER_KEY];
    data.extend(
        wincode::serialize(&RegisterKeyIxData {
            proof: CustomRingProof {
                groth16: custom_ring_interface::PlainGroth16Proof {
                    proof_a: [0; 32],
                    proof_b: [0; 64],
                    proof_c: [0; 32],
                },
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
            registry_old_root: EMPTY_ROOT,
            registry_new_root: insertion.new_root,
            registry_next_index: 1,
            nullifier_pk: field(5),
            eph_pk: [5; 33],
            ciphertext: [5; 32],
        })
        .unwrap(),
    );
    let chain = Arc::new(Mutex::new(Chain {
        blocks: BTreeMap::from([
            (
                1,
                block(
                    1,
                    vec![transaction(
                        program,
                        &[
                            Pubkey::new_from_array([1; 32]),
                            Pubkey::new_from_array([2; 32]),
                            Pubkey::new_from_array([3; 32]),
                            address,
                            Pubkey::default(),
                        ],
                        &[tag::CREATE_KEY_REGISTRY_ROOT],
                    )],
                ),
            ),
            (
                2,
                block(
                    2,
                    vec![transaction(
                        program,
                        &[
                            Pubkey::new_from_array([5; 32]),
                            Pubkey::new_from_array([3; 32]),
                            address,
                        ],
                        &data,
                    )],
                ),
            ),
            (3, block(3, vec![])),
        ]),
        accounts: HashMap::from([
            (
                address.to_string(),
                root_account(program, insertion.new_root, 2),
            ),
            (
                zolana_interface::pda::ring_auth(&program).0.to_string(),
                activation(program, false),
            ),
        ]),
        failed_block: None,
    }));
    let (rpc, handle) = rpc(chain.clone()).await;
    let db = Database::connect("sqlite::memory:").await.unwrap();
    RingsMigrator::up(&db, None).await.unwrap();
    let projector = Projector {
        db: Arc::new(db),
        rpc,
        start: StartSlot::Explicit(0),
    };
    assert!(matches!(
        projector.synchronize().await.unwrap(),
        Progress::CaughtUp
    ));
    assert!(
        storage::pending_ring(projector.db.as_ref(), &program.to_bytes())
            .await
            .unwrap()
            .is_some()
    );
    chain.lock().unwrap().accounts.insert(
        zolana_interface::pda::ring_auth(&program).0.to_string(),
        activation(program, true),
    );
    chain.lock().unwrap().failed_block = Some(2);
    (projector, chain, handle, program, insertion.new_root)
}

#[tokio::test]
async fn replay_resumes_after_a_committed_initialization_and_restart() {
    let (projector, chain, handle, program, expected) = late_ring().await;
    // An archive failure must withhold only the affected ring.
    assert!(matches!(
        projector.synchronize().await.unwrap(),
        Progress::CaughtUp
    ));
    let checkpoint = storage::pending_ring(projector.db.as_ref(), &program.to_bytes())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(checkpoint.replayed_tip.unwrap().slot, 1);
    assert_eq!(
        RingStore::<_, key_registry::KeyRegistry>::new(projector.db.as_ref(), program.to_bytes())
            .root()
            .await
            .unwrap()
            .unwrap()
            .root,
        EMPTY_ROOT
    );
    chain.lock().unwrap().failed_block = None;
    let restarted = Projector {
        db: projector.db.clone(),
        rpc: projector.rpc.clone(),
        start: StartSlot::Explicit(0),
    };
    for _ in 0..2 {
        assert!(matches!(
            restarted.synchronize().await.unwrap(),
            Progress::CaughtUp
        ));
    }
    let root =
        RingStore::<_, key_registry::KeyRegistry>::new(restarted.db.as_ref(), program.to_bytes())
            .root()
            .await
            .unwrap()
            .unwrap();
    assert_eq!(root.root, expected);
    assert_eq!(root.next_index, 2);
    assert!(root.fault.is_none());
    assert!(
        storage::pending_ring(restarted.db.as_ref(), &program.to_bytes())
            .await
            .unwrap()
            .is_none()
    );
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn rollback_rewinds_an_incomplete_replay_before_canonical_reindex() {
    let (projector, chain, handle, program, expected) = late_ring().await;
    projector.synchronize().await.unwrap();
    let mut cursor = projector.cursor().await.unwrap();
    for _ in 0..3 {
        projector.rewind_tip(&mut cursor).await.unwrap();
    }
    assert!(
        storage::pending_ring(projector.db.as_ref(), &program.to_bytes())
            .await
            .unwrap()
            .is_none()
    );
    assert!(RingStore::<_, key_registry::KeyRegistry>::new(
        projector.db.as_ref(),
        program.to_bytes()
    )
    .root()
    .await
    .unwrap()
    .is_none());
    chain.lock().unwrap().failed_block = None;
    projector.synchronize().await.unwrap();
    let root =
        RingStore::<_, key_registry::KeyRegistry>::new(projector.db.as_ref(), program.to_bytes())
            .root()
            .await
            .unwrap()
            .unwrap();
    assert_eq!(root.root, expected);
    assert!(root.fault.is_none());
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn a_stalled_replay_does_not_starve_another_pending_ring() {
    let (projector, chain, handle, stalled, _) = late_ring().await;
    let healthy = Pubkey::new_from_array([12; 32]);
    let address = key_registry::KeyRegistry::root_address(&healthy).0;
    {
        let mut chain = chain.lock().unwrap();
        chain
            .accounts
            .insert(address.to_string(), root_account(healthy, EMPTY_ROOT, 1));
        chain.accounts.insert(
            zolana_interface::pda::ring_auth(&healthy).0.to_string(),
            activation(healthy, false),
        );
        chain.blocks.insert(
            4,
            block(
                4,
                vec![transaction(
                    healthy,
                    &[
                        Pubkey::new_from_array([1; 32]),
                        Pubkey::new_from_array([2; 32]),
                        Pubkey::new_from_array([3; 32]),
                        address,
                        Pubkey::default(),
                    ],
                    &[tag::CREATE_KEY_REGISTRY_ROOT],
                )],
            ),
        );
    }
    projector.synchronize().await.unwrap();
    assert_eq!(
        storage::pending(projector.db.as_ref()).await.unwrap().len(),
        2
    );
    chain.lock().unwrap().accounts.insert(
        zolana_interface::pda::ring_auth(&healthy).0.to_string(),
        activation(healthy, true),
    );
    projector.synchronize().await.unwrap();
    assert!(
        storage::pending_ring(projector.db.as_ref(), &stalled.to_bytes())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        storage::pending_ring(projector.db.as_ref(), &healthy.to_bytes())
            .await
            .unwrap()
            .is_none()
    );
    assert!(key_registry::register(
        projector.db.as_ref(),
        &projector.rpc,
        RingMemberProofRequest {
            ring_program_id: healthy.into(),
            member: Hash(member(7)),
            expected_root: Hash(EMPTY_ROOT),
            expected_next_index: 1,
        }
    )
    .await
    .is_ok());
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn a_fork_rewinds_the_committed_replay_checkpoint() {
    let (projector, chain, handle, program, expected) = late_ring().await;
    chain.lock().unwrap().failed_block = Some(3);
    projector.synchronize().await.unwrap();
    let checkpoint = storage::pending_ring(projector.db.as_ref(), &program.to_bytes())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(checkpoint.replayed_tip.unwrap().slot, 2);
    {
        let mut chain = chain.lock().unwrap();
        let transactions = chain.blocks[&2]["transactions"].clone();
        let mut replacement = block(2, vec![]);
        replacement["blockhash"] = json!(Hash(field(22)).to_string());
        chain.blocks.insert(2, replacement);
        let mut replacement = block(3, vec![]);
        replacement["blockhash"] = json!(Hash(field(33)).to_string());
        replacement["previousBlockhash"] = json!(Hash(field(22)).to_string());
        replacement["transactions"] = transactions;
        chain.blocks.insert(3, replacement);
        chain.failed_block = None;
    }
    // A changed blockhash must trigger rollback during synchronization.
    projector.synchronize().await.unwrap();
    let root =
        RingStore::<_, key_registry::KeyRegistry>::new(projector.db.as_ref(), program.to_bytes())
            .root()
            .await
            .unwrap()
            .unwrap();
    assert_eq!(root.root, expected);
    assert_eq!(root.next_index, 2);
    assert!(root.fault.is_none());
    assert!(
        storage::pending_ring(projector.db.as_ref(), &program.to_bytes())
            .await
            .unwrap()
            .is_none()
    );
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn missing_archived_initialization_never_completes_a_replay() {
    let (projector, chain, handle, program, _) = late_ring().await;
    chain.lock().unwrap().blocks.remove(&1);
    chain.lock().unwrap().failed_block = None;
    for _ in 0..2 {
        projector.synchronize().await.unwrap();
        let checkpoint = storage::pending_ring(projector.db.as_ref(), &program.to_bytes())
            .await
            .unwrap()
            .unwrap();
        assert!(checkpoint.replayed_tip.is_none());
        assert!(RingStore::<_, key_registry::KeyRegistry>::new(
            projector.db.as_ref(),
            program.to_bytes()
        )
        .root()
        .await
        .unwrap()
        .is_none());
    }
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn post_init_root_faults_are_local_and_ahead_roots_are_not_quarantined() {
    for invalid in [
        None,
        Some(account(Pubkey::default(), &[0; 42])),
        Some(account(Pubkey::new_from_array([11; 32]), &[0; 3])),
    ] {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();
        let mut cursor = ProjectionCursor::new(0);
        let faulty = initialize_root::<key_registry::KeyRegistry>(&db, &mut cursor, [11; 32]).await;
        let healthy =
            initialize_root::<key_registry::KeyRegistry>(&db, &mut cursor, [12; 32]).await;
        let ahead = initialize_root::<key_registry::KeyRegistry>(&db, &mut cursor, [13; 32]).await;
        let mut accounts = HashMap::from([
            (
                Pubkey::new_from_array(healthy.address).to_string(),
                root_account(Pubkey::new_from_array(healthy.program), healthy.root, 1),
            ),
            (
                Pubkey::new_from_array(ahead.address).to_string(),
                root_account(Pubkey::new_from_array(ahead.program), field(9), 2),
            ),
        ]);
        if let Some(value) = invalid {
            accounts.insert(Pubkey::new_from_array(faulty.address).to_string(), value);
        }
        let chain = Arc::new(Mutex::new(Chain {
            blocks: BTreeMap::from([(1, block(1, vec![]))]),
            accounts,
            failed_block: None,
        }));
        let (rpc, handle) = rpc(chain).await;
        let projector = Projector {
            db: Arc::new(db),
            rpc,
            start: StartSlot::Explicit(0),
        };
        storage::save_cursor(projector.db.as_ref(), &cursor)
            .await
            .unwrap();
        assert!(matches!(
            projector.synchronize().await.unwrap(),
            Progress::CaughtUp
        ));
        let root = |program| {
            RingStore::<_, key_registry::KeyRegistry>::new(projector.db.as_ref(), program)
        };
        assert!(root(faulty.program)
            .root()
            .await
            .unwrap()
            .unwrap()
            .fault
            .is_some());
        assert!(root(ahead.program)
            .root()
            .await
            .unwrap()
            .unwrap()
            .fault
            .is_none());
        let request = |root: &RingRoot| RingMemberProofRequest {
            ring_program_id: Pubkey::new_from_array(root.program).into(),
            member: Hash(member(7)),
            expected_root: Hash(root.root),
            expected_next_index: 1,
        };
        assert!(
            key_registry::register(projector.db.as_ref(), &projector.rpc, request(&healthy))
                .await
                .is_ok()
        );
        assert!(
            key_registry::register(projector.db.as_ref(), &projector.rpc, request(&faulty))
                .await
                .is_err()
        );
        assert!(
            key_registry::register(projector.db.as_ref(), &projector.rpc, request(&ahead))
                .await
                .is_err()
        );
        let mut cursor = projector.cursor().await.unwrap();
        projector.rewind_tip(&mut cursor).await.unwrap();
        assert!(root(faulty.program)
            .root()
            .await
            .unwrap()
            .unwrap()
            .fault
            .is_none());
        handle.stop().unwrap();
        handle.stopped().await;
    }
}
