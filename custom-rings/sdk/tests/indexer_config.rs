//! `ReadEntry` and `ReadSpendRecord` pass their indexer config to every
//! request of the lineage walk.

use std::sync::Mutex;

use async_trait::async_trait;
use custom_ring_sdk::{CustomRing, ReadEntry, ReadSpendRecord};
use solana_address::Address;
use zolana_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, AsyncRpc, ClientError, Context,
    IndexerRpcConfig,
};
use zolana_ring_policy::{ListId, Member};

#[derive(Default)]
struct Indexer {
    required_slots: Mutex<Vec<Option<u64>>>,
}

impl Indexer {
    fn read(
        &self,
        config: Option<IndexerRpcConfig>,
    ) -> GetShieldedTransactionsByNullifiersResponse {
        self.required_slots
            .lock()
            .expect("required slots")
            .push(config.and_then(|config| config.require_slot));
        GetShieldedTransactionsByNullifiersResponse {
            context: Context {
                block_time: 0,
                slot: 0,
            },
            transactions: Vec::new(),
            output_tree_id: None,
            next_cursor: None,
            scanned_through: Some(Vec::new()),
        }
    }

    fn required_slots(&self) -> Vec<Option<u64>> {
        std::mem::take(&mut self.required_slots.lock().expect("required slots"))
    }
}

#[async_trait]
impl AsyncRpc for Indexer {
    async fn get_shielded_transactions_by_nullifiers(
        &self,
        _nullifiers: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        Ok(self.read(config))
    }
}

fn member() -> Member {
    Member::owner_tag(&[1; 32]).expect("member")
}

fn entry() -> ReadEntry {
    ReadEntry::new(0, Address::new_from_array([8; 32]), ListId::Allow, member())
}

fn spend_record() -> ReadSpendRecord {
    ReadSpendRecord::new(
        CustomRing::new(Address::new_from_array([9; 32])),
        0,
        member(),
    )
}

#[tokio::test]
async fn an_entry_read_requires_the_slot_of_its_indexer_config() {
    let indexer = Indexer::default();
    let config = IndexerRpcConfig::at_slot(42);

    assert_eq!(entry().read(&indexer).await.expect("read"), None);
    assert_eq!(indexer.required_slots(), vec![None]);

    let read = entry().with_indexer_config(config).read(&indexer).await;
    assert_eq!(read.expect("read"), None);
    assert_eq!(indexer.required_slots(), vec![Some(42)]);
}

#[tokio::test]
async fn a_spend_record_read_requires_the_slot_of_its_indexer_config() {
    let indexer = Indexer::default();
    let config = IndexerRpcConfig::at_slot(42);

    assert!(spend_record().read(&indexer).await.expect("read").is_none());
    assert_eq!(indexer.required_slots(), vec![None]);

    let read = spend_record()
        .with_indexer_config(config)
        .read(&indexer)
        .await;
    assert!(read.expect("read").is_none());
    assert_eq!(indexer.required_slots(), vec![Some(42)]);
}
