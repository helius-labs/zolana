use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use zolana_interface::event::decode_output_data;
use zolana_keypair::viewing_key::ViewTag;
use zolana_transaction::{
    AssetRegistry, OutputContext, OutputSlot, ShieldedTransaction, SyncReport, Wallet,
    DEFAULT_TAG_WINDOW,
};

use crate::{
    error::ClientError,
    rpc::{EncryptedUtxoMatch, Rpc, ShieldedTransaction as RpcShieldedTransaction},
};

const DEFAULT_TAG_QUERY_CHUNK: usize = 64;
const DEFAULT_PAGE_LIMIT: u32 = 1_000;
const DEFAULT_SYNC_ROUNDS: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncWalletConfig {
    pub tag_window: u64,
    pub tag_query_chunk: usize,
    pub page_limit: u32,
    pub rounds: usize,
}

impl Default for SyncWalletConfig {
    fn default() -> Self {
        Self {
            tag_window: DEFAULT_TAG_WINDOW,
            tag_query_chunk: DEFAULT_TAG_QUERY_CHUNK,
            page_limit: DEFAULT_PAGE_LIMIT,
            rounds: DEFAULT_SYNC_ROUNDS,
        }
    }
}

pub fn sync_wallet<I>(
    wallet: &mut Wallet,
    indexer: &I,
    assets: &AssetRegistry,
) -> Result<SyncReport, ClientError>
where
    I: Rpc,
{
    sync_wallet_with_config(wallet, indexer, assets, SyncWalletConfig::default())
}

pub fn sync_wallet_with_config<I>(
    wallet: &mut Wallet,
    indexer: &I,
    assets: &AssetRegistry,
    config: SyncWalletConfig,
) -> Result<SyncReport, ClientError>
where
    I: Rpc,
{
    let config = normalized_config(config);
    let mut transactions: HashMap<String, ShieldedTransaction> = HashMap::new();
    let mut proofless_deposits: HashMap<String, ShieldedTransaction> = HashMap::new();
    let mut report = SyncReport::default();

    for _ in 0..config.rounds {
        let before = (transactions.len(), proofless_deposits.len());
        let tags = wallet_query_tags(wallet, config.tag_window)?;
        fetch_shielded_transactions(indexer, &tags, &mut transactions, config)?;
        fetch_proofless_deposits(indexer, &tags, &mut proofless_deposits, config)?;

        let mut txs = transactions.values().cloned().collect::<Vec<_>>();
        txs.sort_by_key(|tx| tx.nullifiers.first().copied().unwrap_or_default());
        let mut deposits = proofless_deposits
            .iter()
            .map(|(key, tx)| (key.clone(), tx.clone()))
            .collect::<Vec<_>>();
        deposits.sort_by_key(|(key, tx)| {
            (
                tx.output_slots
                    .first()
                    .map(|slot| (slot.output_context.tree, slot.output_context.leaf_index)),
                key.clone(),
            )
        });
        txs.extend(deposits.into_iter().map(|(_, tx)| tx));
        report = wallet.sync(&txs, assets, now_unix_ts(), config.tag_window)?;

        if before == (transactions.len(), proofless_deposits.len()) {
            break;
        }
    }

    Ok(report)
}

fn normalized_config(config: SyncWalletConfig) -> SyncWalletConfig {
    SyncWalletConfig {
        tag_window: config.tag_window,
        tag_query_chunk: config.tag_query_chunk.max(1),
        page_limit: config.page_limit.max(1),
        rounds: config.rounds.max(1),
    }
}

fn wallet_query_tags(wallet: &Wallet, window: u64) -> Result<Vec<ViewTag>, ClientError> {
    let mut tags = HashSet::new();
    // Confidential default-zone outputs (sender change, recipients, merge) are all
    // tagged by the owner signing pubkey.
    tags.insert(wallet.keypair.signing_pubkey().confidential_view_tag()?);
    for entry in &wallet.viewing_key_history {
        tags.insert(entry.key.recipient_bootstrap_view_tag());
        for n in 0..entry.tx_count.saturating_add(window) {
            tags.insert(entry.key.get_sender_view_tag(n)?);
        }
        for n in 0..entry.request_count.saturating_add(window) {
            tags.insert(entry.key.get_recipient_request_view_tag(n)?);
        }
        for (sender, count) in &entry.known_senders {
            for n in 0..count.saturating_add(window) {
                tags.insert(entry.key.get_recipient_shared_view_tag(sender, n)?);
            }
        }
        for (recipient, count) in &entry.known_recipients {
            for n in 0..count.saturating_add(window) {
                tags.insert(entry.key.get_send_shared_view_tag(recipient, n)?);
            }
        }
    }
    Ok(tags.into_iter().collect())
}

fn fetch_shielded_transactions<I: Rpc>(
    indexer: &I,
    tags: &[ViewTag],
    out: &mut HashMap<String, ShieldedTransaction>,
    config: SyncWalletConfig,
) -> Result<(), ClientError> {
    for chunk in tags.chunks(config.tag_query_chunk) {
        let mut cursor = None;
        loop {
            let response = indexer.get_shielded_transactions_by_tags(
                chunk.to_vec(),
                cursor,
                Some(config.page_limit),
            )?;
            for tx in response.transactions {
                // Photon may surface proofless/plaintext deposits from this
                // endpoint before marking them as proofless. They are discovered
                // through `get_encrypted_utxos_by_tags` below, not as decryptable
                // shielded transfers.
                if tx.proofless || tx.tx_viewing_pk.is_none() || tx.salt.is_none() {
                    continue;
                }
                let key = tx.tx_signature.to_string();
                out.entry(key).or_insert(convert_sync_transaction(tx)?);
            }
            cursor = response.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
    }
    Ok(())
}

fn fetch_proofless_deposits<I>(
    indexer: &I,
    tags: &[ViewTag],
    out: &mut HashMap<String, ShieldedTransaction>,
    config: SyncWalletConfig,
) -> Result<(), ClientError>
where
    I: Rpc,
{
    for chunk in tags.chunks(config.tag_query_chunk) {
        let mut cursor = None;
        loop {
            let response = indexer.get_encrypted_utxos_by_tags(
                chunk.to_vec(),
                cursor,
                Some(config.page_limit),
            )?;
            for item in response.matches {
                if item.tx_viewing_pk.is_some() || item.salt.is_some() {
                    continue;
                }
                let key = item.tx_signature.to_string();
                if out.contains_key(&key) {
                    continue;
                }
                if let Some(view) = proofless_deposit_from_indexed_match(item)? {
                    out.insert(key, view);
                }
            }
            cursor = response.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
    }
    Ok(())
}

fn proofless_deposit_from_indexed_match(
    item: EncryptedUtxoMatch,
) -> Result<Option<ShieldedTransaction>, ClientError> {
    // The wallet deserializes the `ProoflessOutput` from the slot payload itself;
    // here we only confirm the payload is a decodable proofless output before
    // wrapping the slot into a proofless `ShieldedTransaction`.
    if decode_output_data(&item.output_slot.payload).is_err() {
        return Ok(None);
    }

    Ok(Some(ShieldedTransaction {
        slot: item.slot,
        tx_signature: item.tx_signature,
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: item.output_slot.view_tag,
            output_context: OutputContext {
                hash: item.output_slot.output_context.hash,
                tree: item.output_slot.output_context.tree,
                leaf_index: item.output_slot.output_context.leaf_index,
            },
            payload: item.output_slot.payload,
        }],
        nullifiers: Vec::new(),
        proofless: true,
    }))
}

fn convert_sync_transaction(
    tx: RpcShieldedTransaction,
) -> Result<ShieldedTransaction, ClientError> {
    let tx_viewing_pk = tx
        .tx_viewing_pk
        .ok_or_else(|| ClientError::Rpc("indexed transaction missing tx_viewing_pk".into()))?;
    let salt = tx
        .salt
        .ok_or_else(|| ClientError::Rpc("indexed transaction missing salt".into()))?;
    let output_slots = tx
        .output_slots
        .into_iter()
        .map(|slot| OutputSlot {
            view_tag: slot.view_tag,
            output_context: OutputContext {
                hash: slot.output_context.hash,
                tree: slot.output_context.tree,
                leaf_index: slot.output_context.leaf_index,
            },
            payload: slot.payload,
        })
        .collect();
    Ok(ShieldedTransaction {
        slot: tx.slot,
        tx_signature: tx.tx_signature,
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some(salt),
        output_slots,
        nullifiers: tx.nullifiers,
        proofless: false,
    })
}

fn now_unix_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use solana_signature::Signature;
    use zolana_interface::event::{encode_output_data, ProoflessOutput};
    use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypair};
    use zolana_transaction::{
        serialization::Proofless, Address, OwnerCx, UtxoSerialization, SOL_MINT,
    };

    use super::*;
    use crate::rpc::{
        Context, GetEncryptedUtxosByTagsResponse, GetShieldedTransactionsByTagsResponse,
        OutputContext, OutputSlot,
    };

    struct MockIndexer {
        transactions: Vec<ShieldedTransaction>,
        matches: Vec<EncryptedUtxoMatch>,
    }

    impl Rpc for MockIndexer {
        fn get_encrypted_utxos_by_tags(
            &self,
            _tags: Vec<ViewTag>,
            _cursor: Option<Vec<u8>>,
            _limit: Option<u32>,
        ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
            Ok(GetEncryptedUtxosByTagsResponse {
                context: Context { slot: 0 },
                matches: self.matches.clone(),
                next_cursor: None,
            })
        }

        fn get_shielded_transactions_by_tags(
            &self,
            _tags: Vec<ViewTag>,
            _cursor: Option<Vec<u8>>,
            _limit: Option<u32>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            Ok(GetShieldedTransactionsByTagsResponse {
                context: Context { slot: 0 },
                transactions: self.transactions.clone(),
                next_cursor: None,
            })
        }
    }

    #[test]
    fn shielded_fetch_skips_rows_without_viewing_material() {
        let indexer = MockIndexer {
            transactions: vec![ShieldedTransaction {
                slot: 1,
                tx_signature: Signature::default(),
                tx_viewing_pk: None,
                salt: None,
                output_slots: vec![OutputSlot {
                    view_tag: [1u8; 32],
                    output_context: OutputContext {
                        hash: [0u8; 32],
                        tree: Address::new_from_array([0u8; 32]),
                        leaf_index: 0,
                    },
                    payload: Vec::new(),
                }],
                nullifiers: Vec::new(),
                proofless: false,
            }],
            matches: Vec::new(),
        };
        let mut out = HashMap::new();

        fetch_shielded_transactions(
            &indexer,
            &[[1u8; 32]],
            &mut out,
            SyncWalletConfig::default(),
        )
        .expect("skip plaintext row");

        assert!(out.is_empty());
    }

    #[test]
    fn proofless_fetch_decodes_indexed_payload() {
        let wallet =
            Wallet::new(ShieldedKeypair::new().expect("shielded keypair")).expect("wallet");
        let output = proofless_output_for_wallet(&wallet, 1_234);
        let item = encrypted_match(&wallet, output.clone());
        let indexer = MockIndexer {
            transactions: Vec::new(),
            matches: vec![item],
        };
        let mut out = HashMap::new();

        fetch_proofless_deposits(
            &indexer,
            &[wallet.keypair.recipient_bootstrap_view_tag()],
            &mut out,
            SyncWalletConfig::default(),
        )
        .expect("decode proofless payload");

        let deposit = out.values().next().expect("proofless deposit");
        assert!(deposit.proofless);
        let slot = deposit.output_slots.first().expect("proofless slot");
        assert_eq!(slot.view_tag, wallet.keypair.recipient_bootstrap_view_tag());
        assert_eq!(slot.output_context.tree.to_bytes(), [7u8; 32]);
        assert_eq!(slot.output_context.leaf_index, 13);
        let decoded = decode_output_data(&slot.payload).expect("decode proofless output");
        assert_eq!(decoded.owner, output.owner);
        assert_eq!(decoded.blinding, output.blinding);
        assert_eq!(decoded.amount, output.amount);
    }

    #[test]
    fn sync_wallet_discovers_indexed_proofless_deposit() {
        let mut wallet =
            Wallet::new(ShieldedKeypair::new().expect("shielded keypair")).expect("wallet");
        let output = proofless_output_for_wallet(&wallet, 42);
        let indexer = MockIndexer {
            transactions: Vec::new(),
            matches: vec![encrypted_match(&wallet, output)],
        };

        sync_wallet(&mut wallet, &indexer, &AssetRegistry::default())
            .expect("sync indexed proofless deposit");

        assert_eq!(wallet.utxos.len(), 1);
        assert_eq!(wallet.utxos[0].utxo.amount, 42);
        assert!(!wallet.utxos[0].spent);
    }

    #[test]
    fn proofless_fetch_skips_rows_with_viewing_material() {
        let wallet =
            Wallet::new(ShieldedKeypair::new().expect("shielded keypair")).expect("wallet");
        let mut item = encrypted_match(&wallet, proofless_output_for_wallet(&wallet, 1));
        item.salt = Some([1u8; 16]);
        let indexer = MockIndexer {
            transactions: Vec::new(),
            matches: vec![item],
        };
        let mut out = HashMap::new();

        fetch_proofless_deposits(
            &indexer,
            &[wallet.keypair.recipient_bootstrap_view_tag()],
            &mut out,
            SyncWalletConfig::default(),
        )
        .expect("skip encrypted row");

        assert!(out.is_empty());
    }

    fn proofless_output_for_wallet(wallet: &Wallet, amount: u64) -> ProoflessOutput {
        ProoflessOutput {
            owner: wallet.keypair.owner_hash().expect("owner hash"),
            blinding: [9u8; BLINDING_LEN],
            asset: SOL_MINT.to_bytes(),
            amount,
            zone_program_id: None,
            zone_data_hash: None,
            zone_data: None,
        }
    }

    fn encrypted_match(wallet: &Wallet, output: ProoflessOutput) -> EncryptedUtxoMatch {
        EncryptedUtxoMatch {
            slot: 1,
            tx_signature: Signature::default(),
            output_slot: OutputSlot {
                view_tag: wallet.keypair.recipient_bootstrap_view_tag(),
                output_context: OutputContext {
                    hash: proofless_leaf_hash(wallet, &output),
                    tree: Address::new_from_array([7u8; 32]),
                    leaf_index: 13,
                },
                payload: encode_output_data(output),
            },
            tx_viewing_pk: None,
            salt: None,
        }
    }

    fn proofless_leaf_hash(wallet: &Wallet, output: &ProoflessOutput) -> [u8; 32] {
        let assets = AssetRegistry::default();
        let owner_cx = OwnerCx {
            owner: wallet.keypair.signing_pubkey(),
            assets: &assets,
            zone_program_id: None,
        };
        let zone_data_hash = output.zone_data_hash.unwrap_or([0u8; 32]);
        let utxo = Proofless::into_utxos(output.clone(), &owner_cx)
            .expect("proofless into utxos")
            .into_iter()
            .next()
            .expect("proofless utxo");
        let nullifier_pk = wallet
            .keypair
            .nullifier_key
            .pubkey()
            .expect("nullifier pubkey");
        utxo.hash(&nullifier_pk, &[0u8; 32], &zone_data_hash)
            .expect("proofless leaf hash")
    }
}
