use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::{collections::HashMap, time::Duration};

use async_stream::stream;
use cadence_macros::statsd_count;
use futures::future::{select, Either};
use futures::sink::SinkExt;
use futures::{pin_mut, Stream, StreamExt};
use log::{error, info};
use rand::{
    distributions::{Alphanumeric, DistString},
    thread_rng,
};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction_error::TransactionError;
use tokio::time::sleep;
use yellowstone_grpc_client::{ClientTlsConfig, GeyserGrpcBuilderResult, GeyserGrpcClient};
use yellowstone_grpc_proto::geyser::{
    subscribe_update::UpdateOneof, CommitmentLevel, SubscribeRequest, SubscribeRequestPing,
};
use yellowstone_grpc_proto::geyser::{
    SubscribeRequestFilterBlocks, SubscribeUpdateBlock, SubscribeUpdateTransactionInfo,
};
use yellowstone_grpc_proto::solana::storage::confirmed_block::InnerInstructions;

use crate::api::method::get_indexer_health::HEALTH_CHECK_SLOT_DISTANCE;
use crate::common::typedefs::hash::Hash;
use crate::ingester::error::IngesterError;
use crate::ingester::fetchers::poller::get_block_poller_stream;
use crate::ingester::typedefs::block_info::{
    BlockInfo, BlockMetadata, Instruction, InstructionGroup, TransactionInfo,
};

use crate::metric;
use crate::monitor::{start_latest_slot_updater, LATEST_SLOT};

pub fn get_grpc_stream_with_rpc_fallback(
    endpoint: String,
    auth_header: String,
    rpc_client: Arc<RpcClient>,
    mut last_indexed_slot: u64,
    max_concurrent_block_fetches: usize,
) -> impl Stream<Item = Vec<BlockInfo>> {
    stream! {
        start_latest_slot_updater(rpc_client.clone()).await;
        let grpc_stream = get_grpc_block_stream(endpoint, auth_header, Some(last_indexed_slot));
        pin_mut!(grpc_stream);
        let mut grpc_stream_active = true;
        let mut rpc_poll_stream:  Option<Pin<Box<dyn Stream<Item = Vec<BlockInfo>> + Send>>> = Some(
            Box::pin(get_block_poller_stream(
                rpc_client.clone(),
                last_indexed_slot,
                max_concurrent_block_fetches,
            ))
        );

        // Await either the gRPC stream or the RPC block fetching
        loop {
            match rpc_poll_stream.as_mut() {
                Some(rpc_poll_stream_value) if !grpc_stream_active => {
                    match rpc_poll_stream_value.next().await {
                        Some(rpc_blocks) => {
                            let rpc_blocks = blocks_after_slot(rpc_blocks, last_indexed_slot);
                            if rpc_blocks.is_empty() {
                                continue;
                            }
                            let blocks_len = rpc_blocks.len();
                            let parent_slot = rpc_blocks[0].metadata.parent_slot;
                            let last_slot = rpc_blocks[blocks_len - 1].metadata.slot;
                            if parent_slot == last_indexed_slot {
                                last_indexed_slot = last_slot;
                                yield rpc_blocks;
                                metric! {
                                    statsd_count!("rpc_block_indexed", metric_count_from_usize(blocks_len));
                                }
                            }
                        }
                        None => {
                            error!("RPC stream ended unexpectedly; restarting RPC fallback");
                            metric! {
                                statsd_count!("rpc_stream_ended", 1);
                            }
                            rpc_poll_stream = Some(Box::pin(get_block_poller_stream(
                                rpc_client.clone(),
                                last_indexed_slot,
                                max_concurrent_block_fetches,
                            )));
                        }
                    }
                }
                Some(rpc_poll_stream_value) => {
                    match select(grpc_stream.next(), rpc_poll_stream_value.next()).await {
                        Either::Left((Some(grpc_block), _)) => {
                            let slot = grpc_block.metadata.slot;
                            if grpc_block.metadata.parent_slot == last_indexed_slot {
                                last_indexed_slot = grpc_block.metadata.slot;
                                yield vec![grpc_block];
                                metric! {
                                    statsd_count!("grpc_block_indexed", 1);
                                }
                                if is_healthy(slot) {
                                    info!("Switching to gRPC block fetching since Photon is up-to-date");
                                    rpc_poll_stream = None;
                                }
                            }
                        }
                        Either::Left((None, _)) => {
                            error!("gRPC stream ended unexpectedly; continuing with RPC fallback");
                            metric! {
                                statsd_count!("grpc_stream_ended", 1);
                            }
                            grpc_stream_active = false;
                            rpc_poll_stream = Some(Box::pin(get_block_poller_stream(
                                rpc_client.clone(),
                                last_indexed_slot,
                                max_concurrent_block_fetches,
                            )));
                        }
                        Either::Right((Some(rpc_blocks), _)) => {
                            let rpc_blocks = blocks_after_slot(rpc_blocks, last_indexed_slot);
                            if rpc_blocks.is_empty() {
                                continue;
                            }
                            let blocks_len = rpc_blocks.len();
                            let parent_slot = rpc_blocks[0].metadata.parent_slot;
                            let last_slot = rpc_blocks[blocks_len - 1].metadata.slot;
                            if parent_slot == last_indexed_slot {
                                last_indexed_slot = last_slot;
                                yield rpc_blocks;
                                metric! {
                                    statsd_count!("rpc_block_indexed", metric_count_from_usize(blocks_len));
                                }
                            }
                        }
                        Either::Right((None, _)) => {
                            error!("RPC stream ended unexpectedly; restarting RPC fallback");
                            metric! {
                                statsd_count!("rpc_stream_ended", 1);
                            }
                            rpc_poll_stream = Some(Box::pin(get_block_poller_stream(
                                rpc_client.clone(),
                                last_indexed_slot,
                                max_concurrent_block_fetches,
                            )));
                        }
                    }
                }
                None if grpc_stream_active => {
                    let block = match tokio::time::timeout(Duration::from_secs(5), grpc_stream.next()).await {
                        Ok(Some(block)) => block,
                        Ok(None) => {
                            error!("gRPC stream ended unexpectedly; enabling RPC fallback");
                            metric! {
                                statsd_count!("grpc_stream_ended", 1);
                            }
                            grpc_stream_active = false;
                            rpc_poll_stream = Some(Box::pin(get_block_poller_stream(
                                rpc_client.clone(),
                                last_indexed_slot,
                                max_concurrent_block_fetches,
                            )));
                            continue;
                        }
                        Err(_) => {
                            metric! {
                                statsd_count!("grpc_timeout", 1);
                            }
                            info!("gRPC stream timed out, enabling RPC block fetching");
                            rpc_poll_stream = Some(Box::pin(get_block_poller_stream(
                                rpc_client.clone(),
                                last_indexed_slot,
                                max_concurrent_block_fetches,
                            )));
                            continue;
                        }
                    };
                    let slot = block.metadata.slot;
                    if block.metadata.parent_slot == last_indexed_slot {
                        last_indexed_slot = block.metadata.slot;
                        yield vec![block];
                    } else {
                        metric! {
                            statsd_count!("grpc_out_of_order", 1);
                        }
                        info!("Switching to RPC block fetching");
                        rpc_poll_stream = Some(Box::pin(get_block_poller_stream(
                            rpc_client.clone(),
                            last_indexed_slot,
                            max_concurrent_block_fetches,
                        )));
                        continue;
                    }
                    if !is_healthy(slot) && rpc_poll_stream.is_none() {
                        info!("gRPC is unhealthy. Enabling RPC block fetching");
                        metric! {
                            statsd_count!("grpc_stale", 1);
                        }
                        rpc_poll_stream = Some(Box::pin(get_block_poller_stream(
                            rpc_client.clone(),
                            last_indexed_slot,
                            max_concurrent_block_fetches,
                        )));
                    }
                }
                None => {
                    info!("gRPC stream is unavailable; enabling RPC block fetching");
                    rpc_poll_stream = Some(Box::pin(get_block_poller_stream(
                        rpc_client.clone(),
                        last_indexed_slot,
                        max_concurrent_block_fetches,
                    )));
                }
            }


        }
    }
}

fn is_healthy(slot: u64) -> bool {
    LATEST_SLOT.load(Ordering::SeqCst).saturating_sub(slot) <= HEALTH_CHECK_SLOT_DISTANCE
}

fn blocks_after_slot(blocks: Vec<BlockInfo>, last_indexed_slot: u64) -> Vec<BlockInfo> {
    blocks
        .into_iter()
        .filter(|block| block.metadata.slot > last_indexed_slot)
        .collect()
}

fn metric_count_from_usize(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn get_grpc_block_stream(
    endpoint: String,
    auth_header: String,
    mut last_indexed_slot: Option<u64>,
) -> impl Stream<Item = BlockInfo> {
    stream! {
        loop {
            let mut grpc_tx;
            let mut grpc_rx;
            {
                let mut grpc_client = match build_geyser_client(endpoint.clone(), auth_header.clone()).await {
                    Ok(grpc_client) => grpc_client,
                    Err(e) => {
                        error!("Error connecting to gRPC, waiting one second then retrying connect: {}", e);
                        metric! {
                            statsd_count!("grpc_connect_error", 1);
                        }
                        sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
                let subscription = grpc_client
                    .subscribe_with_request(Some(get_block_subscribe_request(last_indexed_slot.map(|slot| slot + 1))))
                    .await;
                match subscription {
                    Ok(subscription) => (grpc_tx, grpc_rx) = subscription,
                    Err(e) => {
                        error!("Error subscribing to gRPC stream, waiting one second then retrying connect: {}", e);
                        metric! {
                            statsd_count!("grpc_subscribe_error", 1);
                        }
                        sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                }
            }
            while let Some(message) = grpc_rx.next().await {
                match message {
                    Ok(message) => match message.update_oneof {
                        Some(UpdateOneof::Block(block)) => {
                            match parse_block(block) {
                                Ok(block) => {
                                    last_indexed_slot = Some(block.metadata.slot);
                                    metric! {
                                        statsd_count!("grpc_block_emitted", 1);
                                    }
                                    yield block;
                                }
                                Err(err) => {
                                    error!("Failed to parse gRPC block: {}", err);
                                    metric! {
                                        statsd_count!("grpc_block_parse_failed", 1);
                                    }
                                }
                            }
                        }
                        Some(UpdateOneof::Ping(_)) => {
                            // This is necessary to keep load balancers that expect client pings alive. If your load balancer doesn't
                            // require periodic client pings then this is unnecessary
                            let ping = grpc_tx.send(ping()).await;
                            if let Err(e) = ping {
                                error!("Error sending ping: {}", e);
                                metric! {
                                    statsd_count!("grpc_ping_error", 1);
                                }
                                break;
                            }
                        }
                        Some(UpdateOneof::Pong(_)) => {}
                        _ => {
                            error!("Unknown message: {:?}", message);
                        }
                    },
                    Err(error) => {
                        error!(
                            "error in block subscribe, resubscribing in 1 second: {error:?}"
                        );
                        metric! {
                            statsd_count!("grpc_resubscribe", 1);
                        }
                        break;
                    }
                }
            }
        sleep(Duration::from_secs(1)).await;
        }
    }
}

async fn build_geyser_client(
    endpoint: String,
    auth_header: String,
) -> GeyserGrpcBuilderResult<GeyserGrpcClient> {
    GeyserGrpcClient::build_from_shared(endpoint)?
        .x_token(Some(auth_header))?
        .connect_timeout(Duration::from_secs(10))
        .max_decoding_message_size(100 * 8388608)
        .tls_config(ClientTlsConfig::new().with_native_roots())?
        .timeout(Duration::from_secs(10))
        .connect()
        .await
}

fn generate_random_string(len: usize) -> String {
    Alphanumeric.sample_string(&mut thread_rng(), len)
}

fn get_block_subscribe_request(from_slot: Option<u64>) -> SubscribeRequest {
    info!(
        "Subscribing to gRPC block stream from slot {}",
        from_slot.unwrap_or(0)
    );
    SubscribeRequest {
        blocks: HashMap::from_iter(vec![(
            generate_random_string(20),
            SubscribeRequestFilterBlocks {
                account_include: vec![],
                include_transactions: Some(true),
                include_accounts: Some(false),
                include_entries: Some(false),
                cuckoo_account_include: None,
            },
        )]),
        commitment: Some(CommitmentLevel::Confirmed.into()),
        from_slot,
        ..Default::default()
    }
}

fn ping() -> SubscribeRequest {
    SubscribeRequest {
        ping: Some(SubscribeRequestPing { id: 1 }),
        ..Default::default()
    }
}

fn parse_block(block: SubscribeUpdateBlock) -> Result<BlockInfo, IngesterError> {
    let metadata = BlockMetadata {
        slot: block.slot,
        parent_slot: block.parent_slot,
        block_time: block
            .block_time
            .ok_or_else(|| IngesterError::ParserError("Missing block_time".to_string()))?
            .timestamp,
        blockhash: Hash::try_from(block.blockhash.as_str())
            .map_err(|e| IngesterError::ParserError(format!("Failed to parse blockhash: {}", e)))?,
        parent_blockhash: Hash::try_from(block.parent_blockhash.as_str()).map_err(|e| {
            IngesterError::ParserError(format!("Failed to parse parent_blockhash: {}", e))
        })?,
        block_height: block
            .block_height
            .ok_or_else(|| IngesterError::ParserError("Missing block_height".to_string()))?
            .block_height,
    };
    let transactions = block
        .transactions
        .into_iter()
        .map(parse_transaction)
        .collect::<Result<Vec<_>, IngesterError>>()?;

    Ok(BlockInfo {
        metadata,
        transactions,
    })
}

fn parse_transaction(
    transaction: SubscribeUpdateTransactionInfo,
) -> Result<TransactionInfo, IngesterError> {
    let meta = transaction
        .meta
        .ok_or_else(|| IngesterError::ParserError("Missing transaction metadata".to_string()))?;
    let error = create_tx_error(meta.err.as_ref());
    if let Err(e) = &error {
        error!(
            "Error parsing transaction error: {}. Error bytes: {:?}",
            e, meta.err
        );
    }
    let error = error
        .map_err(|e| IngesterError::ParserError(e.to_string()))?
        .map(|e| e.to_string());

    let signature = Signature::try_from(transaction.signature)
        .map_err(|_| IngesterError::ParserError("Invalid transaction signature".to_string()))?;
    let message = transaction
        .transaction
        .ok_or_else(|| IngesterError::ParserError("Missing transaction".to_string()))?
        .message
        .ok_or_else(|| IngesterError::ParserError("Missing transaction message".to_string()))?;
    let outer_instructions = message.instructions;
    let mut accounts = message.account_keys;
    for account in meta.loaded_writable_addresses {
        accounts.push(account);
    }
    for account in meta.loaded_readonly_addresses {
        accounts.push(account);
    }

    let mut instruction_groups: Vec<InstructionGroup> = outer_instructions
        .iter()
        .map(|ix| {
            let program_id = account_pubkey(
                &accounts,
                ix.program_id_index,
                "outer instruction program id",
            )?;
            let data = ix.data.clone();
            let accounts: Result<Vec<Pubkey>, IngesterError> = ix
                .accounts
                .iter()
                .map(|account_index| {
                    account_pubkey(&accounts, *account_index, "outer instruction account")
                })
                .collect();

            Ok(InstructionGroup {
                outer_instruction: Instruction {
                    program_id,
                    data,
                    accounts: accounts?,
                    stack_height: Some(1),
                },
                inner_instructions: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, IngesterError>>()?;

    for inner_instruction_group in meta.inner_instructions {
        let InnerInstructions {
            index,
            instructions,
        } = inner_instruction_group;
        for instruction in instructions {
            let group_index = usize::try_from(index).map_err(|_| {
                IngesterError::ParserError(format!(
                    "Inner instruction group index {} does not fit in usize",
                    index
                ))
            })?;
            let instruction_group = instruction_groups.get_mut(group_index).ok_or_else(|| {
                IngesterError::ParserError(format!(
                    "Inner instruction group index {} is out of bounds",
                    index
                ))
            })?;
            let program_id = account_pubkey(
                &accounts,
                instruction.program_id_index,
                "inner instruction program id",
            )?;
            let data = instruction.data.clone();
            let accounts: Result<Vec<Pubkey>, IngesterError> = instruction
                .accounts
                .iter()
                .map(|account_index| {
                    account_pubkey(&accounts, *account_index, "inner instruction account")
                })
                .collect();
            instruction_group.inner_instructions.push(Instruction {
                program_id,
                data,
                accounts: accounts?,
                stack_height: instruction.stack_height,
            });
        }
    }

    Ok(TransactionInfo {
        instruction_groups,
        signature,
        error,
    })
}

fn account_pubkey<I>(accounts: &[Vec<u8>], index: I, context: &str) -> Result<Pubkey, IngesterError>
where
    I: TryInto<usize> + Copy + std::fmt::Display,
{
    let index_usize = index.try_into().map_err(|_| {
        IngesterError::ParserError(format!("{} index {} does not fit usize", context, index))
    })?;
    let account = accounts.get(index_usize).ok_or_else(|| {
        IngesterError::ParserError(format!(
            "{} account index {} is out of bounds for {} accounts",
            context,
            index,
            accounts.len()
        ))
    })?;
    Pubkey::try_from(account.clone())
        .map_err(|_| IngesterError::ParserError(format!("Invalid {} pubkey bytes", context)))
}

fn create_tx_error(
    err: Option<&yellowstone_grpc_proto::solana::storage::confirmed_block::TransactionError>,
) -> Result<Option<TransactionError>, &'static str> {
    err.map(|err| {
        bincode::serde::decode_from_slice(&err.err, bincode::config::legacy()).map(|(err, _)| err)
    })
    .transpose()
    .map_err(|_| "failed to decode TransactionError")
}
