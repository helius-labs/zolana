use super::tests::{create_registry, database, field};
use std::collections::HashMap;

use super::*;
use crate::api::error::{CustomRingError, PhotonApiError};
use base64::{engine::general_purpose::STANDARD, Engine};
use bytemuck::Zeroable;
use custom_ring_interface::{
    instruction::tag, tagged_x25519, ApplyRecordsIxData, AuthorityWriteRecordsIxData, EscrowKey,
    QueueEntry, RecordWriteData, RegisterKeyIxData, WriteRecordsIxData, APPLY_DELAY_SLOTS,
    MEMBER_QUEUE_LIMIT, MEMBER_REGISTRY_EMPTY_ROOT, QUAD_HEIGHT, ROOT_HISTORY,
};
use jsonrpsee::{server::ServerHandle, types::ErrorObjectOwned};
use sea_orm::ConnectionTrait;
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Mutex};
use zolana_indexer_api::{
    GetRingApplyProofInputsRequest, GetRingMemberOpeningsRequest, GetRingMemberRecordRequest,
    GetRingMemberRecordsRequest, GetRingMemberRegistryRootRequest, GetRingRecordQueueRequest, Hash,
    RingListWriteView, RingMemberOpening, RingMemberRecordView, RingQueueEntryView,
    RingRecordPathView, RingRecordWriteView, SerializablePubkey,
};
use zolana_ring_indexer::{
    records::CanonicalAccounts,
    tree::{MemberRecord, QuadPath, RecordOpening, RecordTree},
};
use zolana_ring_member_registry::MemberRegistryTree;
use zolana_ring_policy::Member;

/// Mutable confirmed RPC history, including failures between replay commits.
#[derive(Default)]
struct Chain {
    blocks: BTreeMap<u64, Value>,
    accounts: HashMap<String, Value>,
    failed_block: Option<u64>,
    /// Account reads answer from a bank that many slots behind the newest block.
    accounts_lag: u64,
}

impl Chain {
    fn accounts_slot(&self) -> u64 {
        let newest = self.blocks.last_key_value().map_or(0, |(slot, _)| *slot);
        newest.saturating_sub(self.accounts_lag)
    }
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
        .register_method("getMultipleAccounts", |params, chain, _| {
            let (addresses, config): (Vec<String>, Value) = params.parse()?;
            let chain = chain.lock().unwrap();
            let slot = chain.accounts_slot();
            if config["minContextSlot"].as_u64() > Some(slot) {
                return Err(ErrorObjectOwned::owned(
                    -32016,
                    "Minimum context slot has not been reached",
                    None::<()>,
                ));
            }
            let accounts = addresses
                .iter()
                .map(|address| chain.accounts.get(address))
                .collect::<Vec<_>>();
            Ok(json!({ "context": { "slot": slot }, "value": accounts }))
        })
        .unwrap();
    (
        Arc::new(RpcClient::new(format!("http://{address}"))),
        server.start(module),
    )
}

fn account(owner: Pubkey, data: &[u8]) -> Value {
    json!({"lamports": 1, "owner": owner.to_string(), "data": [STANDARD.encode(data), "base64"], "executable": false, "rentEpoch": 0})
}

fn registry_accounts(state: &RegistryState) -> [(String, Value); 2] {
    let program = Pubkey::new_from_array(state.program);
    [
        (
            Pubkey::new_from_array(state.registry_address).to_string(),
            account(program, bytemuck::bytes_of(&*state.registry)),
        ),
        (
            Pubkey::new_from_array(state.queue_address).to_string(),
            account(program, bytemuck::bytes_of(&*state.queue)),
        ),
    ]
}

fn activation(program: Pubkey, active: bool) -> (String, Value) {
    let config = account(
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
    );
    (
        zolana_interface::pda::ring_auth(&program).0.to_string(),
        config,
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

#[derive(Clone, Copy)]
struct RingProgram(Pubkey);

struct Registration {
    transaction: Value,
    entry: QueueEntry,
}

impl RingProgram {
    fn creation(self) -> Value {
        let canonical = CanonicalAccounts::of(&self.0).accounts;
        let [payer, authority, config] = [1, 2, 3].map(|seed| Pubkey::new_from_array([seed; 32]));
        let system = Pubkey::default();
        let accounts = [
            payer,
            authority,
            config,
            canonical.registry,
            canonical.queue,
            system,
        ];
        transaction(self.0, &accounts, &[tag::CREATE_MEMBER_REGISTRY])
    }

    fn record(self, signer: Pubkey, data: &[u8]) -> Value {
        let canonical = CanonicalAccounts::of(&self.0).accounts;
        let config = Pubkey::new_from_array([3; 32]);
        let accounts = [signer, config, canonical.registry, canonical.queue];
        transaction(self.0, &accounts, data)
    }

    fn registration(self, signer: Pubkey, seed: u8) -> Registration {
        let data = RegisterKeyIxData {
            proof: Zeroable::zeroed(),
            nullifier_pk: field(seed),
            eph_u: [seed; 32],
            ciphertext: [seed; 32],
        };
        let mut bytes = vec![tag::REGISTER_KEY];
        bytes.extend_from_slice(bytemuck::bytes_of(&data));
        let member = *Member::owner_tag(signer.as_array()).unwrap().as_bytes();
        let key = EscrowKey {
            nullifier_pk: &data.nullifier_pk,
            ciphertext: &data.ciphertext,
        };
        Registration {
            transaction: self.record(signer, &bytes),
            entry: QueueEntry::escrow(member, &key).unwrap(),
        }
    }

    fn write(self, write: &Value) -> Value {
        let signer = Pubkey::new_from_array(bytes32(&write["signer"]));
        let mut data = Vec::new();
        match write["kind"].as_str().unwrap() {
            "member_write" => {
                data.push(tag::WRITE_RECORDS);
                data.extend_from_slice(bytemuck::bytes_of(&vector_lists(write)));
            }
            "register_key" => {
                data.push(tag::REGISTER_KEY);
                data.extend_from_slice(bytemuck::bytes_of(&RegisterKeyIxData {
                    proof: Zeroable::zeroed(),
                    nullifier_pk: bytes32(&write["nullifier_pk"]),
                    eph_u: bytes32(&write["eph_u"]),
                    ciphertext: bytes32(&write["ciphertext"]),
                }));
            }
            kind => panic!("a {kind} write queues only inside its application"),
        }
        self.record(signer, &data)
    }

    fn authority(self, writes: &[RecordWriteData], apply: &ApplyRecordsIxData) -> Value {
        let mut data = vec![tag::AUTHORITY_WRITE_RECORDS];
        let encoded = AuthorityWriteRecordsIxData { writes, apply }
            .encode()
            .unwrap();
        data.extend(encoded);
        self.record(Pubkey::new_from_array([2; 32]), &data)
    }

    fn application(self, apply: &ApplyRecordsIxData) -> Value {
        let canonical = CanonicalAccounts::of(&self.0).accounts;
        let mut data = vec![tag::APPLY_RECORDS];
        data.extend_from_slice(bytemuck::bytes_of(apply));
        transaction(self.0, &[canonical.registry, canonical.queue], &data)
    }
}

async fn state(indexer: &CustomRingIndexer, program: Pubkey) -> Option<RegistryState> {
    RegistryStore::new(indexer.db.as_ref(), program.to_bytes())
        .state()
        .await
        .unwrap()
}

/// Initialization and first registration precede the global tip.
async fn late_ring() -> (
    CustomRingIndexer,
    Arc<Mutex<Chain>>,
    ServerHandle,
    Pubkey,
    QueueEntry,
) {
    let program = Pubkey::new_from_array([11; 32]);
    let registration = RingProgram(program).registration(Pubkey::new_from_array([5; 32]), 5);
    let mut accounts = HashMap::from(registry_accounts(&member_registry::created(
        program.to_bytes(),
        1,
    )));
    accounts.extend([activation(program, false)]);
    let chain = Arc::new(Mutex::new(Chain {
        blocks: BTreeMap::from([
            (1, block(1, vec![RingProgram(program).creation()])),
            (2, block(2, vec![registration.transaction])),
            (3, block(3, vec![])),
        ]),
        accounts,
        ..Default::default()
    }));
    let (rpc, handle) = rpc(chain.clone()).await;
    let indexer = CustomRingIndexer {
        db: Arc::new(database().await),
        rpc,
        start: StartSlot::Explicit(0),
        block_fetches: 4,
    };
    assert!(matches!(
        indexer.synchronize().await.unwrap(),
        Progress::CaughtUp
    ));
    assert!(
        storage::pending_ring(indexer.db.as_ref(), &program.to_bytes())
            .await
            .unwrap()
            .is_some()
    );
    {
        let mut chain = chain.lock().unwrap();
        chain.accounts.extend([activation(program, true)]);
        chain.failed_block = Some(2);
    }
    (indexer, chain, handle, program, registration.entry)
}

#[tokio::test]
async fn replay_resumes_after_a_committed_initialization_and_restart() {
    let (indexer, chain, handle, program, entry) = late_ring().await;
    // An archive failure must withhold only the affected ring.
    assert!(matches!(
        indexer.synchronize().await.unwrap(),
        Progress::CaughtUp
    ));
    let checkpoint = storage::pending_ring(indexer.db.as_ref(), &program.to_bytes())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(checkpoint.replayed_tip.unwrap().slot, 1);
    assert_eq!(state(&indexer, program).await.unwrap().queue.tail(), 0);
    chain.lock().unwrap().failed_block = None;
    let restarted = CustomRingIndexer {
        db: indexer.db.clone(),
        rpc: indexer.rpc.clone(),
        start: StartSlot::Explicit(0),
        block_fetches: 4,
    };
    for _ in 0..2 {
        assert!(matches!(
            restarted.synchronize().await.unwrap(),
            Progress::CaughtUp
        ));
    }
    let replayed = state(&restarted, program).await.unwrap();
    assert!(replayed.fault.is_none());
    assert_eq!(replayed.queue.tail(), 1);
    let queued = RegistryStore::new(restarted.db.as_ref(), program.to_bytes())
        .entries(0..1)
        .await
        .unwrap();
    assert_eq!(queued[0].write.entry, entry);
    assert_eq!(queued[0].chain, replayed.queue.chain_tail());
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
    let (indexer, chain, handle, program, _) = late_ring().await;
    indexer.synchronize().await.unwrap();
    let mut cursor = indexer.cursor().await.unwrap();
    for _ in 0..3 {
        indexer.rewind_tip(&mut cursor).await.unwrap();
    }
    assert!(
        storage::pending_ring(indexer.db.as_ref(), &program.to_bytes())
            .await
            .unwrap()
            .is_none()
    );
    assert!(state(&indexer, program).await.is_none());
    chain.lock().unwrap().failed_block = None;
    indexer.synchronize().await.unwrap();
    let replayed = state(&indexer, program).await.unwrap();
    assert_eq!(replayed.queue.tail(), 1);
    assert!(replayed.fault.is_none());
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn a_stalled_replay_does_not_starve_another_pending_ring() {
    let (indexer, chain, handle, stalled, _) = late_ring().await;
    let healthy = Pubkey::new_from_array([12; 32]);
    {
        let mut chain = chain.lock().unwrap();
        let created = member_registry::created(healthy.to_bytes(), 4);
        chain.accounts.extend(registry_accounts(&created));
        chain.accounts.extend([activation(healthy, false)]);
        chain
            .blocks
            .insert(4, block(4, vec![RingProgram(healthy).creation()]));
    }
    indexer.synchronize().await.unwrap();
    assert_eq!(
        storage::pending(indexer.db.as_ref()).await.unwrap().len(),
        2
    );
    chain
        .lock()
        .unwrap()
        .accounts
        .extend([activation(healthy, true)]);
    indexer.synchronize().await.unwrap();
    assert!(
        storage::pending_ring(indexer.db.as_ref(), &stalled.to_bytes())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        storage::pending_ring(indexer.db.as_ref(), &healthy.to_bytes())
            .await
            .unwrap()
            .is_none()
    );
    let absent = Member::owner_tag(&[7; 32]).unwrap();
    let record = member_registry::member_record(
        indexer.db.as_ref(),
        &indexer.rpc,
        GetRingMemberRecordRequest {
            ring_program_id: healthy.into(),
            member: Hash(*absent.as_bytes()),
            expected_root: Hash(MEMBER_REGISTRY_EMPTY_ROOT),
            expected_next_index: 1,
        },
    )
    .await
    .unwrap();
    assert!(!record.opening.present);
    assert_eq!(record.opening.record.member, Hash([0; 32]));
    assert_eq!(record.root.applied, 0);
    let tip = member_registry::registry_root(
        indexer.db.as_ref(),
        &indexer.rpc,
        GetRingMemberRegistryRootRequest {
            ring_program_id: healthy.into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(tip.next_index, 1);
    assert_eq!(tip.history_cursor, 0);
    assert_eq!(tip.append_path.unwrap().siblings.len(), QUAD_HEIGHT);
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn a_fork_rewinds_the_committed_replay_checkpoint() {
    let (indexer, chain, handle, program, _) = late_ring().await;
    chain.lock().unwrap().failed_block = Some(3);
    indexer.synchronize().await.unwrap();
    let checkpoint = storage::pending_ring(indexer.db.as_ref(), &program.to_bytes())
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
    indexer.synchronize().await.unwrap();
    let replayed = state(&indexer, program).await.unwrap();
    assert_eq!(replayed.queue.tail(), 1);
    let queued = RegistryStore::new(indexer.db.as_ref(), program.to_bytes())
        .entries(0..1)
        .await
        .unwrap();
    assert_eq!(queued[0].slot, 3);
    assert!(replayed.fault.is_none());
    assert!(
        storage::pending_ring(indexer.db.as_ref(), &program.to_bytes())
            .await
            .unwrap()
            .is_none()
    );
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn missing_archived_initialization_never_completes_a_replay() {
    let (indexer, chain, handle, program, _) = late_ring().await;
    chain.lock().unwrap().blocks.remove(&1);
    chain.lock().unwrap().failed_block = None;
    for _ in 0..2 {
        indexer.synchronize().await.unwrap();
        let checkpoint = storage::pending_ring(indexer.db.as_ref(), &program.to_bytes())
            .await
            .unwrap()
            .unwrap();
        assert!(checkpoint.replayed_tip.is_none());
        assert!(state(&indexer, program).await.is_none());
    }
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn post_init_account_faults_are_local_and_ahead_registries_are_not_quarantined() {
    for invalid in [
        None,
        Some(account(Pubkey::default(), &[0; 42])),
        Some(account(Pubkey::new_from_array([11; 32]), &[0; 3])),
    ] {
        let db = database().await;
        let faulty = create_registry(&db, [11; 32]).await;
        let healthy = create_registry(&db, [12; 32]).await;
        let ahead = create_registry(&db, [13; 32]).await;
        let mut moved = ahead.clone();
        moved.registry.push_root(field(9), 1, 1);
        let mut accounts = HashMap::from(registry_accounts(&healthy));
        accounts.extend(registry_accounts(&moved));
        let [faulty_registry, faulty_queue] = registry_accounts(&faulty);
        accounts.extend([faulty_queue]);
        if let Some(value) = invalid {
            accounts.insert(faulty_registry.0, value);
        }
        let chain = Arc::new(Mutex::new(Chain {
            blocks: BTreeMap::from([(1, block(1, vec![]))]),
            accounts,
            ..Default::default()
        }));
        let (rpc, handle) = rpc(chain).await;
        let indexer = CustomRingIndexer {
            db: Arc::new(db),
            rpc,
            start: StartSlot::Explicit(0),
            block_fetches: 4,
        };
        storage::save_cursor(indexer.db.as_ref(), &CustomRingCursor::new(0))
            .await
            .unwrap();
        assert!(matches!(
            indexer.synchronize().await.unwrap(),
            Progress::CaughtUp
        ));
        let program = |state: &RegistryState| Pubkey::new_from_array(state.program);
        assert!(state(&indexer, program(&faulty))
            .await
            .unwrap()
            .fault
            .is_some());
        assert!(state(&indexer, program(&ahead))
            .await
            .unwrap()
            .fault
            .is_none());
        let absent = Member::owner_tag(&[7; 32]).unwrap();
        let read = |state: &RegistryState| {
            member_registry::member_record(
                indexer.db.as_ref(),
                &indexer.rpc,
                GetRingMemberRecordRequest {
                    ring_program_id: program(state).into(),
                    member: Hash(*absent.as_bytes()),
                    expected_root: Hash(MEMBER_REGISTRY_EMPTY_ROOT),
                    expected_next_index: 1,
                },
            )
        };
        assert!(read(&healthy).await.is_ok());
        assert!(matches!(
            read(&faulty).await,
            Err(PhotonApiError::CustomRing(CustomRingError::OutOfSync(reason))) if reason.contains("quarantined")
        ));
        // The chain still holds the projected root, only the newest state moved.
        assert!(read(&ahead).await.is_ok());
        let tip = member_registry::registry_root(
            indexer.db.as_ref(),
            &indexer.rpc,
            GetRingMemberRegistryRootRequest {
                ring_program_id: program(&ahead).into(),
            },
        );
        assert!(matches!(
            tip.await,
            Err(PhotonApiError::CustomRing(CustomRingError::OutOfSync(_)))
        ));
        let mut cursor = indexer.cursor().await.unwrap();
        indexer.rewind_tip(&mut cursor).await.unwrap();
        assert!(state(&indexer, program(&faulty))
            .await
            .unwrap()
            .fault
            .is_none());
        handle.stop().unwrap();
        handle.stopped().await;
    }
}

const RING_RECORDS: &str = include_str!("../../../../test-vectors/ring-records.json");

fn bytes32(value: &Value) -> [u8; 32] {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn number(value: &Value) -> u64 {
    value.as_u64().unwrap()
}

fn vector_path(path: &Value) -> RingRecordPathView {
    RingRecordPathView {
        index: number(&path["index"]),
        siblings: path["siblings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|level| [0, 1, 2].map(|child| Hash(bytes32(&level[child]))))
            .collect(),
    }
}

fn vector_record(record: &Value) -> RingMemberRecordView {
    RingMemberRecordView {
        member: Hash(bytes32(&record["member"])),
        next: Hash(bytes32(&record["next"])),
        lists: number(&record["lists"]),
        escrow_key: Hash(bytes32(&record["escrow_key"])),
        owner_pubkey: None,
        nullifier_pk: None,
        eph_pk: None,
        ciphertext: None,
    }
}

fn vector_write(write: &Value) -> RingRecordWriteView {
    RingRecordWriteView {
        member: Hash(bytes32(&write["member"])),
        mask: number(&write["mask"]),
        value: number(&write["value"]),
        escrow_key: Hash(bytes32(&write["escrow_key"])),
        exists: write["exists"].as_bool().unwrap(),
        old_next: Hash(bytes32(&write["old_next"])),
        old_lists: number(&write["old_lists"]),
        old_escrow: Hash(bytes32(&write["old_escrow"])),
        slot: vector_path(&write["slot"]),
        low: vector_record(&write["low"]),
        low_path: vector_path(&write["low_path"]),
    }
}

fn vector_lists(write: &Value) -> WriteRecordsIxData {
    WriteRecordsIxData {
        mask: number(&write["mask"]).to_le_bytes(),
        value: number(&write["value"]).to_le_bytes(),
    }
}

fn apply_data(new_root: [u8; 32], new_next_index: u64) -> ApplyRecordsIxData {
    ApplyRecordsIxData {
        proof: Zeroable::zeroed(),
        new_root,
        new_next_index: u32::try_from(new_next_index).unwrap().to_le_bytes(),
    }
}

fn recorded(application: &Value) -> ApplyRecordsIxData {
    apply_data(
        bytes32(&application["new_root"]),
        number(&application["new_next_index"]),
    )
}

fn wire_record(record: &RingMemberRecordView) -> MemberRecord {
    MemberRecord {
        member: record.member.0,
        next: record.next.0,
        lists: record.lists,
        escrow_key: record.escrow_key.0,
    }
}

fn wire_path(path: &RingRecordPathView) -> QuadPath {
    QuadPath {
        index: path.index,
        siblings: core::array::from_fn(|level| {
            path.siblings[level].clone().map(|sibling| sibling.0)
        }),
    }
}

fn record_opening(opening: &RingMemberOpening) -> RecordOpening {
    let (record, path) = (wire_record(&opening.record), wire_path(&opening.path));
    if opening.present {
        RecordOpening::Present { record, path }
    } else {
        RecordOpening::Absent { low: record, path }
    }
}

struct GrowingRing {
    program: RingProgram,
    chain: Arc<Mutex<Chain>>,
    handle: ServerHandle,
    indexer: CustomRingIndexer,
    slot: u64,
}

impl GrowingRing {
    async fn created(program: Pubkey) -> Self {
        let ring = Self::creating(program).await;
        ring.catch_up().await;
        ring
    }

    /// The creation block landed, the projection has not read it.
    async fn creating(program: Pubkey) -> Self {
        let created = member_registry::created(program.to_bytes(), 1);
        let mut accounts = HashMap::from(registry_accounts(&created));
        accounts.extend([activation(program, true)]);
        let program = RingProgram(program);
        let chain = Arc::new(Mutex::new(Chain {
            blocks: BTreeMap::from([(1, block(1, vec![program.creation()]))]),
            accounts,
            ..Default::default()
        }));
        let (rpc, handle) = rpc(chain.clone()).await;
        Self {
            program,
            chain,
            handle,
            indexer: CustomRingIndexer {
                db: Arc::new(database().await),
                rpc,
                start: StartSlot::Explicit(0),
                block_fetches: 4,
            },
            slot: 1,
        }
    }

    async fn land(&mut self, transactions: Vec<Value>) {
        self.land_at(self.slot + 1, transactions).await;
    }

    async fn land_at(&mut self, slot: u64, transactions: Vec<Value>) {
        let mut landed = block(slot, transactions);
        landed["parentSlot"] = json!(self.slot);
        landed["previousBlockhash"] = json!(Hash(field(self.slot as u8)).to_string());
        self.slot = slot;
        self.chain.lock().unwrap().blocks.insert(slot, landed);
        self.catch_up().await;
    }

    /// An `ApplyRecords` lands once its queue is due, an authority write at the next slot.
    async fn apply(&mut self, application: &Value, recorded: ApplyRecordsIxData) {
        let (delay, transaction) = match application["instruction"].as_str().unwrap() {
            "apply_records" => (APPLY_DELAY_SLOTS, self.program.application(&recorded)),
            "authority_write_records" => {
                let writes = application["authority_writes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|write| RecordWriteData {
                        member: bytes32(&write["member"]),
                        lists: vector_lists(write),
                    })
                    .collect::<Vec<_>>();
                (1, self.program.authority(&writes, &recorded))
            }
            instruction => panic!("{instruction} applies no records"),
        };
        self.land_at(self.slot + delay, vec![transaction]).await;
    }

    async fn queue(&mut self, application: &Value) {
        let pending = application["pending"].as_array().unwrap();
        let writes = pending
            .iter()
            .map(|write| self.program.write(write))
            .collect();
        self.land(writes).await;
    }

    async fn catch_up(&self) {
        while self.indexer.synchronize().await.unwrap() == Progress::Behind {}
    }

    async fn state(&self) -> RegistryState {
        state(&self.indexer, self.program.0).await.unwrap()
    }

    /// The chain takes the projected accounts, as an honest program writes them.
    async fn publish(&self) {
        let accounts = registry_accounts(&self.state().await);
        self.chain.lock().unwrap().accounts.extend(accounts);
    }

    async fn stop(self) {
        self.handle.stop().unwrap();
        self.handle.stopped().await;
    }
}

#[tokio::test]
async fn replay_applies_queue_and_matches_roots() {
    let vector: Value = serde_json::from_str(RING_RECORDS).unwrap();
    let mut ring = GrowingRing::created(Pubkey::new_from_array([31; 32])).await;
    let ring_program_id: SerializablePubkey = ring.program.0.into();
    let (db, rpc) = (ring.indexer.db.clone(), ring.indexer.rpc.clone());
    let applications = vector["applications"].as_array().unwrap();
    let mut next_apply = 0;
    for application in applications {
        ring.queue(application).await;
        ring.publish().await;
        let queue = member_registry::record_queue(
            db.as_ref(),
            &rpc,
            GetRingRecordQueueRequest { ring_program_id },
        )
        .await
        .unwrap();
        let queued = application["pending"]
            .as_array()
            .unwrap()
            .iter()
            .map(|write| RingQueueEntryView {
                position: number(&write["position"]),
                member: Hash(bytes32(&write["member"])),
                mask: number(&write["mask"]),
                value: number(&write["value"]),
                escrow_key: Hash(bytes32(&write["escrow_key"])),
                slot: ring.slot,
            })
            .collect::<Vec<_>>();
        assert_eq!(queue.entries, queued, "{}", application["name"]);
        assert_eq!(queue.chain_head.0, bytes32(&application["chain_start"]));
        let authority_writes = application["authority_writes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|write| RingListWriteView {
                member: Hash(bytes32(&write["member"])),
                mask: number(&write["mask"]),
                value: number(&write["value"]),
            })
            .collect();
        let inputs = member_registry::apply_proof_inputs(
            db.as_ref(),
            &rpc,
            GetRingApplyProofInputsRequest {
                ring_program_id,
                authority_writes,
            },
        )
        .await
        .unwrap();
        let statement = [
            (inputs.old_root.0, &application["old_root"]),
            (inputs.new_root.0, &application["new_root"]),
            (inputs.chain_start.0, &application["chain_start"]),
            (inputs.chain_end.0, &application["chain_end"]),
        ];
        for (projected, expected) in statement {
            assert_eq!(projected, bytes32(expected), "{}", application["name"]);
        }
        assert_eq!(
            inputs.old_next_index,
            number(&application["old_next_index"])
        );
        assert_eq!(
            inputs.new_next_index,
            number(&application["new_next_index"])
        );
        let writes = application["writes"].as_array().unwrap();
        assert_eq!(
            inputs.writes,
            writes.iter().map(vector_write).collect::<Vec<_>>()
        );
        ring.apply(application, recorded(application)).await;
        if application["instruction"] == "apply_records" {
            next_apply = ring.slot + APPLY_DELAY_SLOTS;
        }
        let state = ring.state().await;
        assert!(state.fault.is_none(), "{}", application["name"]);
        assert_eq!(
            state.registry.current_root(),
            bytes32(&application["new_root"])
        );
        assert_eq!(
            u64::from(state.registry.next_index()),
            number(&application["new_next_index"])
        );
        assert_eq!(state.queue.chain_head, bytes32(&application["chain_end"]));
        assert_eq!(state.queue.head(), state.queue.tail());
        assert_eq!(state.queue.next_apply_slot(), next_apply);
    }
    let state = ring.state().await;
    let chained = RegistryStore::new(db.as_ref(), state.program)
        .entries(0..state.queue.tail())
        .await
        .unwrap();
    let written = applications
        .iter()
        .flat_map(|application| {
            let pending = application["pending"].as_array().unwrap().iter();
            pending.chain(application["authority_writes"].as_array().unwrap())
        })
        .collect::<Vec<_>>();
    assert_eq!(chained.len(), written.len());
    for (entry, write) in chained.iter().zip(written) {
        assert_eq!(entry.chain, bytes32(&write["chain"]));
    }
    // Every authority application is a hard floor, the member application leaves it.
    let floors = [state.registry.prior_floor(), state.registry.floor()];
    assert_eq!(floors, [3, 24]);
    ring.publish().await;
    let current = state.registry.current_root();
    let next_index = u64::from(state.registry.next_index());
    let tip = member_registry::registry_root(
        db.as_ref(),
        &rpc,
        GetRingMemberRegistryRootRequest { ring_program_id },
    )
    .await
    .unwrap();
    let append = wire_path(&tip.append_path.unwrap());
    assert_eq!(append.index, next_index);
    assert_eq!(append.root([0; 32]).unwrap(), current);
    let mut page_start = Some(1);
    let mut leaves = 1..1;
    while let Some(start_index) = page_start {
        let page = member_registry::member_records(
            db.as_ref(),
            &rpc,
            GetRingMemberRecordsRequest {
                ring_program_id,
                expected_root: Hash(current),
                expected_next_index: next_index,
                start_index,
                limit: 5,
            },
        )
        .await
        .unwrap();
        for leaf in &page.records {
            assert_eq!(leaf.path.index, leaves.end);
            let opening = RecordOpening::Present {
                record: wire_record(&leaf.record),
                path: wire_path(&leaf.path),
            };
            assert!(opening.verify(&current, &leaf.record.member.0).is_ok());
            leaves.end += 1;
        }
        page_start = page.next_leaf_index;
    }
    assert_eq!(leaves, 1..next_index);
    let openings = vector["openings"].as_array().unwrap();
    let response = member_registry::member_openings(
        db.as_ref(),
        &rpc,
        GetRingMemberOpeningsRequest {
            ring_program_id,
            members: openings
                .iter()
                .map(|opening| Hash(bytes32(&opening["member"])))
                .collect(),
            expected_root: Hash(bytes32(&openings[0]["root"])),
        },
    )
    .await
    .unwrap();
    let expected = openings
        .iter()
        .map(|opening| RingMemberOpening {
            present: opening["present"].as_bool().unwrap(),
            record: vector_record(&opening["record"]),
            path: vector_path(&opening["path"]),
        })
        .collect::<Vec<_>>();
    assert_eq!(response.openings, expected);
    assert_eq!(response.root.applied, 24);
    let first = &applications[0];
    let member = bytes32(&first["authority_writes"][0]["member"]);
    let earlier = member_registry::member_record(
        db.as_ref(),
        &rpc,
        GetRingMemberRecordRequest {
            ring_program_id,
            member: Hash(member),
            expected_root: Hash(bytes32(&first["new_root"])),
            expected_next_index: number(&first["new_next_index"]),
        },
    )
    .await
    .unwrap();
    assert_eq!((earlier.root.applied, earlier.root.root_index), (3, 1));
    let opened = record_opening(&earlier.opening).verify(&bytes32(&first["new_root"]), &member);
    let lists = number(&first["authority_writes"][0]["value"]);
    assert_eq!(opened.unwrap().map(|record| record.lists), Some(lists));
    // Fill-once escrow keeps the first registration's sealed key.
    let registered = &applications[1]["pending"][1];
    let sealed = member_registry::member_record(
        db.as_ref(),
        &rpc,
        GetRingMemberRecordRequest {
            ring_program_id,
            member: Hash(bytes32(&registered["member"])),
            expected_root: Hash(current),
            expected_next_index: next_index,
        },
    )
    .await
    .unwrap();
    let record = sealed.opening.record;
    assert_eq!(record.escrow_key.0, bytes32(&registered["escrow_key"]));
    let nullifier_pk = bytes32(&registered["nullifier_pk"]);
    assert_eq!(record.nullifier_pk, Some(Hash(nullifier_pk)));
    let eph_pk = tagged_x25519(&bytes32(&registered["eph_u"]));
    assert_eq!(record.eph_pk.unwrap().0, eph_pk);
    assert_eq!(
        record.ciphertext.unwrap().0,
        bytes32(&registered["ciphertext"])
    );
    ring.stop().await;
}

#[tokio::test]
async fn an_application_off_the_projection_stops_the_registry() {
    let vector: Value = serde_json::from_str(RING_RECORDS).unwrap();
    let applications = vector["applications"].as_array().unwrap();
    let first = &applications[0];
    let second = &applications[1];
    let honest = recorded(second);
    let mut forged_root = honest;
    forged_root.new_root[31] ^= 1;
    let mut forged_count = honest;
    forged_count.new_next_index = (honest.new_next_index() + 1).to_le_bytes();
    for (seed, forged) in (32..).zip([forged_root, forged_count]) {
        let mut ring = GrowingRing::created(Pubkey::new_from_array([seed; 32])).await;
        ring.apply(first, recorded(first)).await;
        ring.queue(second).await;
        ring.apply(second, forged).await;
        let stopped = ring.state().await;
        let fault = stopped.fault.clone().unwrap();
        assert!(fault.contains("applied root mismatch"), "{fault}");
        assert_eq!(stopped.registry.current_root(), bytes32(&first["new_root"]));
        assert_eq!((stopped.queue.head(), stopped.queue.tail()), (3, 8));
        // A stopped projection takes no further write and serves no opening.
        ring.queue(&applications[2]).await;
        assert_eq!(ring.state().await, stopped);
        let read = member_registry::member_record(
            ring.indexer.db.as_ref(),
            &ring.indexer.rpc,
            GetRingMemberRecordRequest {
                ring_program_id: ring.program.0.into(),
                member: Hash(bytes32(&first["authority_writes"][0]["member"])),
                expected_root: Hash(bytes32(&first["new_root"])),
                expected_next_index: number(&first["new_next_index"]),
            },
        );
        assert!(matches!(
            read.await,
            Err(PhotonApiError::CustomRing(CustomRingError::OutOfSync(reason))) if reason.contains("quarantined")
        ));
        ring.stop().await;
    }
}

#[tokio::test]
async fn a_write_past_the_member_queue_limit_stops_the_registry() {
    let mut ring = GrowingRing::created(Pubkey::new_from_array([36; 32])).await;
    let program = ring.program;
    let writes = (1..=MEMBER_QUEUE_LIMIT as u8 + 1)
        .map(|seed| {
            let signer = Pubkey::new_from_array([seed; 32]);
            program.registration(signer, seed).transaction
        })
        .collect();
    ring.land(writes).await;
    let stopped = ring.state().await;
    let fault = stopped.fault.unwrap();
    assert!(fault.contains("refuses the change"), "{fault}");
    assert_eq!(stopped.queue.tail(), MEMBER_QUEUE_LIMIT);
    ring.stop().await;
}

async fn count(ring: &GrowingRing, table: &str) -> i64 {
    let db = ring.indexer.db.as_ref();
    let sql = format!("SELECT COUNT(*) AS count FROM {table}");
    let statement = sea_orm::Statement::from_string(db.get_database_backend(), sql);
    let row = db.query_one(statement).await.unwrap().unwrap();
    row.try_get("", "count").unwrap()
}

struct AuthorityGrowth {
    tree: MemberRegistryTree,
    chain: [u8; 32],
}

impl AuthorityGrowth {
    async fn write(&mut self, ring: &mut GrowingRing, members: &[[u8; 32]]) {
        let allow = zolana_ring_policy::ListId::Allow.record_bit();
        for member in members {
            let write = RecordWriteData {
                member: *member,
                lists: WriteRecordsIxData {
                    mask: allow.to_le_bytes(),
                    value: allow.to_le_bytes(),
                },
            };
            let inputs = self
                .tree
                .apply(self.chain, &[write.entry().unwrap()])
                .unwrap();
            self.chain = inputs.chain_end;
            let apply = apply_data(inputs.new_root, inputs.new_next_index);
            let transaction = ring.program.authority(&[write], &apply);
            ring.land(vec![transaction]).await;
        }
    }
}

/// Member `k` of `members` was written at queue position `k`, one based.
async fn assert_every_held_root_opens(ring: &GrowingRing, members: &[[u8; 32]]) {
    ring.publish().await;
    let state = ring.state().await;
    for entry in state.registry.history.iter() {
        let response = member_registry::member_openings(
            ring.indexer.db.as_ref(),
            &ring.indexer.rpc,
            GetRingMemberOpeningsRequest {
                ring_program_id: ring.program.0.into(),
                members: members.iter().map(|member| Hash(*member)).collect(),
                expected_root: Hash(entry.root),
            },
        )
        .await
        .unwrap();
        for ((position, member), opening) in (1..).zip(members).zip(&response.openings) {
            let opened = record_opening(opening).verify(&entry.root, member).unwrap();
            assert_eq!(opened.is_some(), position <= entry.applied());
        }
    }
}

#[tokio::test]
async fn pruning_keeps_what_every_held_root_reads() {
    let mut ring = GrowingRing::created(Pubkey::new_from_array([33; 32])).await;
    let members = (1..=ROOT_HISTORY as u8 + 6)
        .map(|seed| *Member::owner_tag(&[seed; 32]).unwrap().as_bytes())
        .collect::<Vec<_>>();
    let (first, second) = members.split_at(ROOT_HISTORY + 2);
    let mut growth = AuthorityGrowth {
        tree: MemberRegistryTree::new().unwrap(),
        chain: [0; 32],
    };
    growth.write(&mut ring, first).await;
    let applied = ring.state().await;
    let nodes = count(&ring, "ring_record_nodes").await;
    let db = ring.indexer.db.clone();
    // Only the newest block can still roll back.
    storage::prune(db.as_ref(), ring.slot).await.unwrap();
    assert!(count(&ring, "ring_record_nodes").await < nodes);
    let mut cursor = ring.indexer.cursor().await.unwrap();
    ring.indexer.rewind_tip(&mut cursor).await.unwrap();
    cursor.resume(db.as_ref()).await.unwrap();
    assert_eq!(
        count(&ring, "ring_registry_roots").await,
        ROOT_HISTORY as i64
    );
    assert_eq!(count(&ring, "ring_record_queue").await, 0);
    assert_every_held_root_opens(&ring, first).await;
    ring.catch_up().await;
    assert_eq!(ring.state().await, applied);
    growth.write(&mut ring, second).await;
    let nodes = count(&ring, "ring_record_nodes").await;
    storage::prune(db.as_ref(), ring.slot).await.unwrap();
    assert!(count(&ring, "ring_record_nodes").await < nodes);
    assert_every_held_root_opens(&ring, &members).await;
    ring.stop().await;
}

#[tokio::test]
async fn an_account_read_behind_the_creation_block_retries_without_stopping_the_ring() {
    let ring = GrowingRing::creating(Pubkey::new_from_array([35; 32])).await;
    ring.chain.lock().unwrap().accounts_lag = 1;
    assert!(ring.indexer.synchronize().await.is_err());
    assert!(state(&ring.indexer, ring.program.0).await.is_none());
    ring.chain.lock().unwrap().accounts_lag = 0;
    ring.catch_up().await;
    assert!(ring.state().await.fault.is_none());
    ring.stop().await;
}

#[tokio::test]
async fn proof_inputs_refuse_a_queue_the_chain_moved() {
    let vector: Value = serde_json::from_str(RING_RECORDS).unwrap();
    let applications = vector["applications"].as_array().unwrap();
    let mut ring = GrowingRing::created(Pubkey::new_from_array([34; 32])).await;
    let first = &applications[0];
    ring.apply(first, recorded(first)).await;
    ring.queue(&applications[1]).await;
    ring.publish().await;
    let inputs = || {
        member_registry::apply_proof_inputs(
            ring.indexer.db.as_ref(),
            &ring.indexer.rpc,
            GetRingApplyProofInputsRequest {
                ring_program_id: ring.program.0.into(),
                authority_writes: vec![],
            },
        )
    };
    assert!(inputs().await.is_ok());
    let mut moved = ring.state().await;
    let late = QueueEntry::escrow(
        bytes32(&applications[1]["pending"][1]["member"]),
        &EscrowKey {
            nullifier_pk: &[1; 32],
            ciphertext: &[2; 32],
        },
    )
    .unwrap();
    moved.queue.push(&late, ring.slot).unwrap();
    ring.chain
        .lock()
        .unwrap()
        .accounts
        .extend(registry_accounts(&moved));
    assert_eq!(inputs().await, Err(CustomRingError::QueueChanged.into()));
    ring.stop().await;
}

#[tokio::test]
async fn proof_inputs_refuse_an_empty_queue_only_while_the_chain_agrees() {
    let ring = GrowingRing::created(Pubkey::new_from_array([37; 32])).await;
    ring.publish().await;
    let inputs = || {
        member_registry::apply_proof_inputs(
            ring.indexer.db.as_ref(),
            &ring.indexer.rpc,
            GetRingApplyProofInputsRequest {
                ring_program_id: ring.program.0.into(),
                authority_writes: vec![],
            },
        )
    };
    let empty = PhotonApiError::ValidationError("the record queue is empty".into());
    assert_eq!(inputs().await, Err(empty));
    let mut moved = ring.state().await;
    let late = ring
        .program
        .registration(Pubkey::new_from_array([5; 32]), 5);
    moved.queue.push(&late.entry, ring.slot).unwrap();
    ring.chain
        .lock()
        .unwrap()
        .accounts
        .extend(registry_accounts(&moved));
    assert_eq!(inputs().await, Err(CustomRingError::QueueChanged.into()));
    ring.stop().await;
}
