use std::time::Duration;

use cadence_macros::statsd_count;
use error::IngesterError;

use parser::parse_transaction;
use parser::TreeResolver;
use sea_orm::sea_query::OnConflict;
use sea_orm::ConnectionTrait;
use sea_orm::DatabaseConnection;
use sea_orm::DatabaseTransaction;

use sea_orm::EntityTrait;
use sea_orm::QueryTrait;
use sea_orm::Set;
use sea_orm::TransactionTrait;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;

use self::parser::state_update::StateUpdate;
use self::persist::MAX_SQL_INSERTS;
use self::typedefs::block_info::BlockInfo;
use self::typedefs::block_info::BlockMetadata;
use crate::dao::generated::blocks;
use crate::metric;
pub mod error;
pub mod fetchers;
pub mod indexer;
pub mod parser;
pub mod persist;
pub mod typedefs;

async fn derive_block_state_update(
    conn: &DatabaseConnection,
    block: &BlockInfo,
    resolver: &mut TreeResolver<'_>,
) -> Result<StateUpdate, IngesterError> {
    let mut state_updates: Vec<StateUpdate> = Vec::new();
    for transaction in &block.transactions {
        state_updates
            .push(parse_transaction(conn, transaction, block.metadata.slot, resolver).await?);
    }
    Ok(StateUpdate::merge_updates(state_updates))
}

async fn index_block_metadatas(
    tx: &DatabaseTransaction,
    blocks: Vec<&BlockMetadata>,
) -> Result<(), IngesterError> {
    for block_chunk in blocks.chunks(MAX_SQL_INSERTS) {
        let block_models: Vec<blocks::ActiveModel> = block_chunk
            .iter()
            .map(|block| {
                Ok::<blocks::ActiveModel, IngesterError>(blocks::ActiveModel {
                    slot: Set(i64_from_u64(block.slot, "block slot")?),
                    parent_slot: Set(i64_from_u64(block.parent_slot, "parent slot")?),
                    block_time: Set(block.block_time),
                    blockhash: Set(block.blockhash.clone().into()),
                    parent_blockhash: Set(block.parent_blockhash.clone().into()),
                    block_height: Set(i64_from_u64(block.block_height, "block height")?),
                })
            })
            .collect::<Result<Vec<blocks::ActiveModel>, IngesterError>>()?;

        // We first build the query and then execute it because SeaORM has a bug where it always throws
        // expected not to insert anything if the key already exists.
        let query = blocks::Entity::insert_many(block_models)
            .on_conflict(
                OnConflict::column(blocks::Column::Slot)
                    .do_nothing()
                    .to_owned(),
            )
            .build(tx.get_database_backend());
        tx.execute(query).await?;
    }
    Ok(())
}

fn i64_from_u64(value: u64, field: &str) -> Result<i64, IngesterError> {
    i64::try_from(value)
        .map_err(|_| IngesterError::ParserError(format!("{} {} does not fit in i64", field, value)))
}

pub async fn index_block_batch(
    db: &DatabaseConnection,
    block_batch: &Vec<BlockInfo>,
    rpc_client: &RpcClient,
) -> Result<(), IngesterError> {
    if block_batch.is_empty() {
        return Ok(());
    }
    let blocks_len = block_batch.len();
    let mut state_updates = Vec::new();
    let mut resolver = TreeResolver::new(rpc_client);
    for block in block_batch {
        state_updates.push(derive_block_state_update(db, block, &mut resolver).await?);
    }
    let state_update = StateUpdate::merge_updates(state_updates);

    let tx = db.begin().await?;
    let block_metadatas: Vec<&BlockMetadata> = block_batch.iter().map(|b| &b.metadata).collect();
    index_block_metadatas(&tx, block_metadatas).await?;
    persist::persist_state_update(&tx, state_update).await?;
    metric! {
        statsd_count!("blocks_indexed", i64::try_from(blocks_len).unwrap_or(i64::MAX));
    }
    tx.commit().await?;
    Ok(())
}

pub async fn index_block_batch_with_infinite_retries(
    db: &DatabaseConnection,
    block_batch: Vec<BlockInfo>,
    rpc_client: &RpcClient,
) {
    loop {
        match index_block_batch(db, &block_batch, rpc_client).await {
            Ok(()) => return,
            Err(e) => {
                let Some(start_block) = block_batch.first().map(|block| block.metadata.slot) else {
                    return;
                };
                let end_block = block_batch
                    .last()
                    .map(|block| block.metadata.slot)
                    .unwrap_or(start_block);
                log::error!(
                    "Failed to index block batch {}-{}. Got error {}",
                    start_block,
                    end_block,
                    e
                );
                metric! {
                    statsd_count!("block_batch_index_failures", 1);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
