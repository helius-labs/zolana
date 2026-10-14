use std::sync::Mutex;

use async_trait::async_trait;
use solana_account::Account;
use solana_address::Address;
use zolana_client::{
    AsyncRpc, ClientError, GetRingSpendRecordResponse, OutputContext, OutputSlot, RingSpendRecord,
    RingSpendRecordRequest, ShieldedTransaction,
};
use zolana_indexer_api::{
    Base64String, Context, Hash, RingsOutputContext, RingsOutputSlot, SerializablePubkey,
};
use zolana_interface::{instruction::MessageData, pda};
use zolana_keypair::{constants::SALT_LEN, ViewingKey};
use zolana_ring_policy::{entry_nullifier, ListNamespace, Member, SpendCounters, SpendRecord};
use zolana_transaction::{
    serialization::confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
    Data, UtxoSerialization,
};

use super::support::{empty, ring, NullifierRpc};
use crate::{
    entry::{LineageLookup, SpentSlot},
    spend::SpendLookup,
    LiveSpendRecord, ReadSpendRecord, RingError,
};

const ADDRESS_TREE_ID: u16 = 7;
const SECOND_TREE_ID: u16 = 9;

fn namespace() -> Address {
    ring().namespace_pda()
}

fn owner() -> ListNamespace {
    ListNamespace::new(namespace().as_array()).unwrap()
}

fn member() -> Member {
    Member::owner_tag(&[5; 32]).unwrap()
}

fn address() -> [u8; 32] {
    owner().spend_address(&member(), ADDRESS_TREE_ID).unwrap()
}

fn lookup() -> SpendLookup {
    SpendLookup {
        owner: owner(),
        member: member(),
        address_tree_id: ADDRESS_TREE_ID,
    }
}

/// The record, its leaf in `tree_id` and its nullifier.
fn version_in(version: u64, tree_id: u16) -> (SpendRecord, [u8; 32], [u8; 32]) {
    let record = SpendRecord {
        member: member(),
        version,
        window: 3,
        counters_commitment: SpendCounters::EMPTY.commitment().unwrap(),
        blinding: [version as u8 + 1; 32],
    };
    let utxo_hash = record.utxo_hash(&owner(), &address(), tree_id).unwrap();
    (
        record,
        utxo_hash,
        entry_nullifier(&utxo_hash, &record.blinding).unwrap(),
    )
}

fn version(version: u64) -> (SpendRecord, [u8; 32], [u8; 32]) {
    version_in(version, ADDRESS_TREE_ID)
}

/// A registration carries its record inline, a successor in the record message.
fn spender_in(
    spent: [u8; 32],
    record: &SpendRecord,
    utxo_hash: [u8; 32],
    tree_id: u16,
) -> ShieldedTransaction {
    let mut payload = record.to_output_data().to_vec();
    let mut messages = Vec::new();
    let tx_key = ViewingKey::new();
    if record.version != 0 {
        payload = Confidential::encode_plaintext(
            &ConfidentialOutputPlaintext {
                asset_id: zolana_transaction::SOL_ASSET_ID,
                amount: 0,
                blinding: record.blinding,
                ring_program_id: None,
                data: Data::default(),
            },
            namespace().to_bytes(),
            &ConfidentialEncode {
                tx: tx_key.clone(),
                recipient_pubkey: tx_key.pubkey(),
                salt: [9; SALT_LEN],
                slot_index: 0,
            },
        )
        .unwrap()
        .data;
        messages.push(MessageData {
            view_tag: zolana_ring_policy::spend_record_message_tag(namespace().as_array()).unwrap(),
            data: record.to_output_data().to_vec(),
        });
    }
    messages.push(MessageData {
        view_tag: namespace().to_bytes(),
        data: vec![1, 2, 3],
    });
    ShieldedTransaction {
        slot: 0,
        tx_signature: Default::default(),
        event_index: Some(0),
        tx_viewing_pk: Some(tx_key.pubkey()),
        salt: Some([9; SALT_LEN]),
        output_slots: vec![OutputSlot {
            view_tag: namespace().to_bytes(),
            output_context: OutputContext {
                hash: utxo_hash,
                tree_id,
                leaf_index: record.version,
            },
            payload,
        }],
        messages,
        nullifiers: vec![spent],
        proofless: false,
        ring_config: None,
        ring_program_id: None,
    }
}

fn spender(spent: [u8; 32], record: &SpendRecord, utxo_hash: [u8; 32]) -> ShieldedTransaction {
    spender_in(spent, record, utxo_hash, ADDRESS_TREE_ID)
}

fn decode(transaction: &ShieldedTransaction) -> Option<LiveSpendRecord> {
    lookup().decode(
        &address(),
        SpentSlot {
            transaction,
            slot: &transaction.output_slots[0],
        },
    )
}

async fn read(rpc: &NullifierRpc) -> Result<Option<LiveSpendRecord>, RingError> {
    ReadSpendRecord::new(ring(), ADDRESS_TREE_ID, member())
        .read(rpc)
        .await
}

#[tokio::test]
async fn the_walk_returns_the_live_version_with_its_origin() {
    let (first, first_hash, first_nullifier) = version(0);
    let (second, second_hash, second_nullifier) = version(1);
    let rpc = NullifierRpc::new(vec![
        spender(address(), &first, first_hash),
        spender(first_nullifier, &second, second_hash),
    ]);
    let live = read(&rpc).await.unwrap().unwrap();
    assert_eq!(live.record, second);
    assert_eq!(live.nullifier, second_nullifier);
    assert_eq!(live.leaf_index, 1);
    assert_eq!(live.origin.first_nullifier, first_nullifier);
    assert_eq!(live.origin.salt, Some([9; SALT_LEN]));
    assert_eq!(live.origin.messages.len(), 2);
    assert_eq!(rpc.requests().len(), 3);
}

#[tokio::test]
async fn a_record_moved_to_another_tree_hashes_under_its_own_tree() {
    let (first, first_hash, first_nullifier) = version(0);
    let (second, second_hash, second_nullifier) = version_in(1, SECOND_TREE_ID);
    let rpc = NullifierRpc::new(vec![
        spender(address(), &first, first_hash),
        spender_in(first_nullifier, &second, second_hash, SECOND_TREE_ID),
    ]);
    let live = read(&rpc).await.unwrap().unwrap();
    assert_eq!(live.record, second);
    assert_eq!(live.tree_id, SECOND_TREE_ID);
    assert_eq!(live.nullifier, second_nullifier);

    let misplaced = NullifierRpc::new(vec![
        spender(address(), &first, first_hash),
        spender_in(first_nullifier, &second, second_hash, ADDRESS_TREE_ID),
    ]);
    assert!(matches!(
        read(&misplaced).await,
        Err(RingError::BrokenSpendLineage { version: 1, .. })
    ));
}

#[tokio::test]
async fn an_unregistered_member_reads_none() {
    assert_eq!(read(&NullifierRpc::new(Vec::new())).await.unwrap(), None);
}

#[test]
fn a_successor_requires_one_bound_public_record_message() {
    let (record, hash, _) = version(1);
    let transaction = spender(address(), &record, hash);
    assert_eq!(decode(&transaction).unwrap().record, record);
    let mutations: [fn(&mut ShieldedTransaction); 6] = [
        |tx| {
            tx.messages.remove(0);
        },
        |tx| tx.messages.push(tx.messages[0].clone()),
        |tx| tx.messages[0].view_tag[0] ^= 1,
        |tx| tx.messages[0].data[5] ^= 1,
        |tx| {
            tx.messages[0].data.pop();
        },
        |tx| tx.output_slots[0].payload = tx.messages[0].data.clone(),
    ];
    for mutate in mutations {
        let mut changed = transaction.clone();
        mutate(&mut changed);
        assert!(decode(&changed).is_none());
    }
}

#[test]
fn a_record_of_another_member_or_namespace_is_not_decoded() {
    let (record, hash, _) = version(0);
    let transaction = spender(address(), &record, hash);
    assert!(decode(&transaction).is_some());
    let mut other_namespace = transaction.clone();
    other_namespace.output_slots[0].view_tag[0] ^= 1;
    assert!(decode(&other_namespace).is_none());
    let stranger = SpendLookup {
        member: Member::owner_tag(&[6; 32]).unwrap(),
        ..lookup()
    };
    assert!(stranger
        .decode(
            &address(),
            SpentSlot {
                transaction: &transaction,
                slot: &transaction.output_slots[0],
            },
        )
        .is_none());
    // An inline record past genesis is never a registration.
    let (later, later_hash, _) = version(1);
    let mut inline = spender(address(), &later, later_hash);
    inline.output_slots[0].payload = later.to_output_data().to_vec();
    assert!(decode(&inline).is_none());
}

fn indexed_genesis() -> RingSpendRecord {
    let (record, hash, _) = version(0);
    RingSpendRecord {
        output_index: 0,
        transaction: zolana_indexer_api::ShieldedTransaction {
            slot: 2,
            tx_signature: Default::default(),
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![RingsOutputSlot {
                view_tag: Hash(namespace().to_bytes()),
                payload: Base64String(record.to_output_data().to_vec()),
                output_context: RingsOutputContext {
                    hash: Hash(hash),
                    tree: SerializablePubkey::from(pda::tree(ADDRESS_TREE_ID).to_bytes()),
                    tree_id: ADDRESS_TREE_ID,
                    leaf_index: 7,
                },
            }],
            messages: Vec::new(),
            nullifiers: vec![Hash(address())],
            proofless: false,
            ring_config: None,
            ring_program_id: None,
        },
    }
}

/// Serves one indexed record, the listed nullifier PDAs exist on chain.
struct RecordIndexer {
    record: Option<RingSpendRecord>,
    spent: Vec<Address>,
    requests: Mutex<Vec<RingSpendRecordRequest>>,
    reads: Mutex<Vec<Address>>,
}

impl RecordIndexer {
    fn new(record: Option<RingSpendRecord>) -> Self {
        Self {
            record,
            spent: Vec::new(),
            requests: Mutex::new(Vec::new()),
            reads: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl AsyncRpc for RecordIndexer {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.reads.lock().unwrap().push(address);
        Ok(self
            .spent
            .contains(&address)
            .then(|| empty(pda::shielded_pool_program_id())))
    }

    async fn get_ring_spend_record(
        &self,
        request: RingSpendRecordRequest,
    ) -> Result<GetRingSpendRecordResponse, ClientError> {
        self.requests.lock().unwrap().push(request);
        Ok(GetRingSpendRecordResponse {
            context: Context::default(),
            record: self.record.clone(),
        })
    }
}

fn current(member: Member) -> ReadSpendRecord {
    ReadSpendRecord::new(ring(), ADDRESS_TREE_ID, member)
}

#[tokio::test]
async fn the_indexed_record_decodes_for_the_requested_member() {
    let (record, _, nullifier) = version(0);
    let indexer = RecordIndexer::new(Some(indexed_genesis()));
    let live = current(member()).current(&indexer).await.unwrap().unwrap();
    assert_eq!(live.record, record);
    assert_eq!(live.nullifier, nullifier);
    assert_eq!(live.leaf_index, 7);
    let requests = indexer.requests.lock().unwrap();
    assert_eq!(requests[0].member, Hash(*member().as_bytes()));
    assert_eq!(
        requests[0].ring_program_id,
        SerializablePubkey::from(ring().program_id().to_bytes())
    );
}

#[tokio::test]
async fn a_substituted_record_is_refused() {
    let other = Member::owner_tag(&[6; 32]).unwrap();
    let indexer = RecordIndexer::new(Some(indexed_genesis()));
    assert!(matches!(
        current(other).current(&indexer).await,
        Err(RingError::InvalidSpendRecord)
    ));
    let mutations: [fn(&mut RingSpendRecord); 3] = [
        |record| record.output_index = 1,
        |record| record.transaction.output_slots[0].output_context.hash.0[31] ^= 1,
        |record| record.transaction.output_slots[0].output_context.tree_id ^= 1,
    ];
    for mutate in mutations {
        let mut record = indexed_genesis();
        mutate(&mut record);
        let indexer = RecordIndexer::new(Some(record));
        assert!(matches!(
            current(member()).current(&indexer).await,
            Err(RingError::InvalidSpendRecord)
        ));
    }
}

#[tokio::test]
async fn an_unregistered_member_has_no_current_record() {
    let indexer = RecordIndexer::new(None);
    assert_eq!(current(member()).current(&indexer).await.unwrap(), None);
    assert!(indexer.reads.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_record_spent_on_chain_is_projection_lag_in_its_own_tree() {
    let (_, hash, nullifier) = version_in(0, SECOND_TREE_ID);
    let mut record = indexed_genesis();
    let context = &mut record.transaction.output_slots[0].output_context;
    context.hash = Hash(hash);
    context.tree_id = SECOND_TREE_ID;
    let own = pda::nullifier_pda(&pda::tree(SECOND_TREE_ID), &nullifier).0;
    let address_tree = pda::nullifier_pda(&pda::tree(ADDRESS_TREE_ID), &nullifier).0;

    let mut indexer = RecordIndexer::new(Some(record.clone()));
    indexer.spent = vec![address_tree];
    let live = current(member()).current(&indexer).await.unwrap().unwrap();
    assert_eq!(live.tree_id, SECOND_TREE_ID);
    assert_eq!(*indexer.reads.lock().unwrap(), vec![own]);

    let mut lagging = RecordIndexer::new(Some(record));
    lagging.spent = vec![own];
    let error = current(member()).current(&lagging).await.unwrap_err();
    assert!(matches!(
        error,
        RingError::Client(ClientError::RingSpendRecordOutOfSync)
    ));
    assert!(error.is_projection_lag());
}
