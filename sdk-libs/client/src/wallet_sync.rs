use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use zolana_interface::event::decode_output_data;
use zolana_keypair::viewing_key::ViewTag;
use zolana_transaction::{
    AssetBalance, EncryptedScheme, OutputContext, OutputSlot, PrivateTransaction,
    ShieldedTransaction, SyncReport, Wallet, DEFAULT_TAG_WINDOW,
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

pub fn sync_wallet<I>(wallet: &mut Wallet, indexer: &I) -> Result<SyncReport, ClientError>
where
    I: Rpc,
{
    sync_wallet_with_config(wallet, indexer, SyncWalletConfig::default())
}

pub fn sync_wallet_with_config<I>(
    wallet: &mut Wallet,
    indexer: &I,
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
        txs.sort_by_key(|a| (a.slot, a.tx_signature));
        let mut deposits = proofless_deposits.values().cloned().collect::<Vec<_>>();
        deposits.sort_by(|a, b| {
            (
                a.output_slots
                    .first()
                    .map(|slot| (slot.output_context.tree, slot.output_context.leaf_index)),
                a.slot,
                a.tx_signature,
            )
                .cmp(&(
                    b.output_slots
                        .first()
                        .map(|slot| (slot.output_context.tree, slot.output_context.leaf_index)),
                    b.slot,
                    b.tx_signature,
                ))
        });
        txs.extend(deposits);
        report = wallet.sync(&txs, now_unix_ts(), config.tag_window)?;

        if before == (transactions.len(), proofless_deposits.len()) {
            break;
        }
    }

    Ok(report)
}

pub fn get_private_transactions(wallet: &Wallet) -> &[PrivateTransaction] {
    wallet.private_transactions()
}

pub fn get_private_token_balances(wallet: &Wallet) -> Result<Vec<AssetBalance>, ClientError> {
    Ok(wallet.balances(true)?)
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
                if tx.proofless
                    || ((tx.tx_viewing_pk.is_none() || tx.salt.is_none())
                        && !has_merge_ciphertext(&tx))
                {
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

fn has_merge_ciphertext(tx: &RpcShieldedTransaction) -> bool {
    tx.output_slots.iter().any(|slot| {
        let Ok(output_data) = borsh::from_slice::<zolana_event::OutputData>(&slot.payload) else {
            return false;
        };
        let blob = match output_data {
            zolana_event::OutputData::Encrypted(blob)
            | zolana_event::OutputData::VerifiablyEncrypted(blob)
            | zolana_event::OutputData::Plaintext(blob) => blob,
        };
        blob.first()
            .and_then(|b| EncryptedScheme::from_byte(*b).ok())
            == Some(EncryptedScheme::Merge)
    })
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
                let key = format!(
                    "{}:{}",
                    item.tx_signature, item.output_slot.output_context.leaf_index
                );
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
        tx_viewing_pk: tx.tx_viewing_pk,
        salt: tx.salt,
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
    use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypair, ViewingKey};
    use zolana_transaction::{
        instructions::{
            merge::Merge as MergePlan,
            transact::{SignedTransaction, Transaction, WithdrawalTarget},
            types::SpendUtxo,
        },
        serialization::{
            merge::{Merge, MergeEncode},
            Proofless,
        },
        Address, AssetRegistry, Data, OwnerCx, PrivateTransactionDirection, PrivateTransactionKind,
        Utxo, UtxoSerialization, WalletUtxo, SOL_MINT,
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

    const SPL_ASSET_ID: u64 = 2;
    const SPL_MINT: Address = Address::new_from_array([2u8; 32]);

    #[test]
    fn sync_wallet_records_confidential_transfer_history_without_duplicates() {
        let assets = AssetRegistry::default();
        let alice = ShieldedKeypair::new().expect("alice");
        let bob = ShieldedKeypair::new().expect("bob");
        let funding = confidential_transfer_tx(&bob, &alice, SOL_MINT, 100, 1, &assets);

        let mut wallet = Wallet::new(alice.clone(), assets.clone()).expect("wallet");
        sync_wallet(
            &mut wallet,
            &MockIndexer {
                transactions: vec![funding.clone()],
                matches: Vec::new(),
            },
        )
        .expect("sync funding");
        assert_eq!(wallet.private_transactions().len(), 1);
        let inbound = wallet.private_transactions().first().expect("inbound");
        assert_eq!(inbound.kind, PrivateTransactionKind::PrivateTransfer);
        assert_eq!(inbound.direction, PrivateTransactionDirection::Inbound);
        assert_eq!(inbound.amount, 100);
        assert_eq!(inbound.counterparty_viewing_pubkey, None);

        let spend = SpendUtxo::from_keypair(wallet.utxos[0].utxo.clone(), &alice);
        let outbound = signed_to_shielded_tx(
            confidential_send(&alice, vec![spend], &bob, SOL_MINT, 40, &assets),
            2,
        );
        let indexer = MockIndexer {
            transactions: vec![funding, outbound],
            matches: Vec::new(),
        };

        sync_wallet(&mut wallet, &indexer).expect("sync outbound");
        sync_wallet(&mut wallet, &indexer).expect("resync is idempotent");

        assert_eq!(wallet.private_transactions().len(), 2);
        let outbound = wallet
            .private_transactions()
            .iter()
            .find(|tx| tx.direction == PrivateTransactionDirection::Outbound)
            .expect("outbound row");
        assert_eq!(outbound.kind, PrivateTransactionKind::PrivateTransfer);
        assert_eq!(outbound.asset, SOL_MINT);
        assert_eq!(outbound.amount, 40);
        assert_eq!(
            outbound.counterparty_viewing_pubkey,
            Some(bob.viewing_pubkey())
        );
    }

    #[test]
    fn sync_wallet_records_confidential_public_withdrawal_history() {
        let assets = AssetRegistry::default();
        let alice = ShieldedKeypair::new().expect("alice");
        let input = SpendUtxo::from_keypair(test_utxo(&alice, SOL_MINT, 100, 7), &alice);
        let withdrawal = signed_to_shielded_tx(
            confidential_withdrawal(&alice, vec![input], SOL_MINT, 30, &assets),
            1,
        );
        let mut wallet = wallet_with_utxo(&alice, SOL_MINT, 100, 7);

        sync_wallet(
            &mut wallet,
            &MockIndexer {
                transactions: vec![withdrawal],
                matches: Vec::new(),
            },
        )
        .expect("sync withdrawal");

        let txs = wallet.private_transactions();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].kind, PrivateTransactionKind::PublicWithdrawal);
        assert_eq!(txs[0].direction, PrivateTransactionDirection::Outbound);
        assert_eq!(txs[0].asset, SOL_MINT);
        assert_eq!(txs[0].amount, 30);
        assert_eq!(txs[0].counterparty_viewing_pubkey, None);
    }

    #[test]
    fn sync_wallet_records_confidential_multi_asset_outbound_rows() {
        let assets = AssetRegistry::new([(SPL_ASSET_ID, SPL_MINT)]).expect("assets");
        let alice = ShieldedKeypair::new().expect("alice");
        let bob = ShieldedKeypair::new().expect("bob");
        let inputs = vec![
            SpendUtxo::from_keypair(test_utxo(&alice, SOL_MINT, 100, 8), &alice),
            SpendUtxo::from_keypair(test_utxo(&alice, SPL_MINT, 100, 9), &alice),
        ];
        let tx = signed_to_shielded_tx(
            confidential_send_and_withdraw(
                &alice, inputs, &bob, SPL_MINT, 60, SOL_MINT, 30, &assets,
            ),
            1,
        );
        let mut wallet = wallet_with_utxos(&alice, &[(SOL_MINT, 100, 8), (SPL_MINT, 100, 9)]);

        sync_wallet(
            &mut wallet,
            &MockIndexer {
                transactions: vec![tx],
                matches: Vec::new(),
            },
        )
        .expect("sync mixed outbound");

        let mut outbound = wallet
            .private_transactions()
            .iter()
            .filter(|tx| tx.direction == PrivateTransactionDirection::Outbound)
            .map(|tx| (tx.asset, tx.amount))
            .collect::<Vec<_>>();
        outbound.sort_by_key(|(asset, _)| *asset);
        let mut expected = vec![(SOL_MINT, 30), (SPL_MINT, 60)];
        expected.sort_by_key(|(asset, _)| *asset);
        assert_eq!(outbound, expected);
    }

    #[test]
    fn sync_wallet_records_merge_history() {
        let assets = AssetRegistry::default();
        let alice = ShieldedKeypair::new().expect("alice");
        let inputs = vec![
            SpendUtxo::from_keypair(test_utxo(&alice, SOL_MINT, 30, 10), &alice),
            SpendUtxo::from_keypair(test_utxo(&alice, SOL_MINT, 70, 11), &alice),
        ];
        let tx = merge_tx(&alice, inputs, 1, &assets);
        let mut wallet = wallet_with_utxos(&alice, &[(SOL_MINT, 30, 10), (SOL_MINT, 70, 11)]);

        let report = sync_wallet(
            &mut wallet,
            &MockIndexer {
                transactions: vec![tx],
                matches: Vec::new(),
            },
        )
        .expect("sync merge");
        assert_eq!(report.undecryptable_candidates, 0);

        let txs = wallet.private_transactions();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].kind, PrivateTransactionKind::Merge);
        assert_eq!(txs[0].direction, PrivateTransactionDirection::SelfTransfer);
        assert_eq!(txs[0].asset, SOL_MINT);
        assert_eq!(txs[0].amount, 100);
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
        let wallet = Wallet::new(
            ShieldedKeypair::new().expect("shielded keypair"),
            AssetRegistry::default(),
        )
        .expect("wallet");
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
        let mut wallet = Wallet::new(
            ShieldedKeypair::new().expect("shielded keypair"),
            AssetRegistry::default(),
        )
        .expect("wallet");
        let output = proofless_output_for_wallet(&wallet, 42);
        let indexer = MockIndexer {
            transactions: Vec::new(),
            matches: vec![encrypted_match(&wallet, output)],
        };

        sync_wallet(&mut wallet, &indexer).expect("sync indexed proofless deposit");

        assert_eq!(wallet.utxos.len(), 1);
        assert_eq!(wallet.utxos[0].utxo.amount, 42);
        assert!(!wallet.utxos[0].spent);
        assert_eq!(wallet.private_transactions().len(), 1);
        let tx = &wallet.private_transactions()[0];
        assert_eq!(tx.kind, zolana_transaction::PrivateTransactionKind::Deposit);
        assert_eq!(
            tx.direction,
            zolana_transaction::PrivateTransactionDirection::Inbound
        );
        assert_eq!(tx.amount, 42);
        assert_eq!(tx.id.slot, 1);
        assert_eq!(tx.id.index, 13);
    }

    #[test]
    fn get_private_token_balances_aggregates_unspent_utxos() {
        let mut wallet = Wallet::new(
            ShieldedKeypair::new().expect("shielded keypair"),
            AssetRegistry::default(),
        )
        .expect("wallet");
        let output = proofless_output_for_wallet(&wallet, 42);
        let indexer = MockIndexer {
            transactions: Vec::new(),
            matches: vec![encrypted_match(&wallet, output)],
        };

        sync_wallet(&mut wallet, &indexer).expect("sync indexed proofless deposit");

        let balances = get_private_token_balances(&wallet).expect("balances");
        assert_eq!(balances.len(), 1);
        assert_eq!(balances[0].amount, 42);
        assert_eq!(balances[0].mint, SOL_MINT);
        assert!(balances[0].utxos.is_empty());
    }

    #[test]
    fn get_private_transactions_matches_wallet_history() {
        let mut wallet = Wallet::new(
            ShieldedKeypair::new().expect("shielded keypair"),
            AssetRegistry::default(),
        )
        .expect("wallet");
        let output = proofless_output_for_wallet(&wallet, 7);
        let indexer = MockIndexer {
            transactions: Vec::new(),
            matches: vec![encrypted_match(&wallet, output)],
        };

        sync_wallet(&mut wallet, &indexer).expect("sync indexed proofless deposit");

        let txs = get_private_transactions(&wallet);
        assert_eq!(txs.len(), 1);
        assert_eq!(
            txs[0].kind,
            zolana_transaction::PrivateTransactionKind::Deposit
        );
        assert_eq!(txs[0].amount, 7);
    }

    #[test]
    fn proofless_fetch_skips_rows_with_viewing_material() {
        let wallet = Wallet::new(
            ShieldedKeypair::new().expect("shielded keypair"),
            AssetRegistry::default(),
        )
        .expect("wallet");
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

    fn confidential_transfer_tx(
        sender: &ShieldedKeypair,
        recipient: &ShieldedKeypair,
        asset: Address,
        amount: u64,
        slot: u64,
        assets: &AssetRegistry,
    ) -> ShieldedTransaction {
        let input = SpendUtxo::from_keypair(test_utxo(sender, asset, amount, slot as u8), sender);
        signed_to_shielded_tx(
            confidential_send(sender, vec![input], recipient, asset, amount, assets),
            slot,
        )
    }

    fn confidential_send(
        sender: &ShieldedKeypair,
        inputs: Vec<SpendUtxo>,
        recipient: &ShieldedKeypair,
        asset: Address,
        amount: u64,
        assets: &AssetRegistry,
    ) -> SignedTransaction {
        let mut tx = Transaction::new(
            sender.shielded_address().expect("sender address"),
            inputs,
            Address::default(),
        );
        tx.send(
            &recipient.shielded_address().expect("recipient address"),
            asset,
            amount,
        )
        .expect("send");
        tx.sign(sender, assets).expect("sign")
    }

    #[allow(clippy::too_many_arguments)]
    fn confidential_send_and_withdraw(
        sender: &ShieldedKeypair,
        inputs: Vec<SpendUtxo>,
        recipient: &ShieldedKeypair,
        send_asset: Address,
        send_amount: u64,
        withdraw_asset: Address,
        withdraw_amount: u64,
        assets: &AssetRegistry,
    ) -> SignedTransaction {
        let mut tx = Transaction::new(
            sender.shielded_address().expect("sender address"),
            inputs,
            Address::default(),
        );
        tx.send(
            &recipient.shielded_address().expect("recipient address"),
            send_asset,
            send_amount,
        )
        .expect("send");
        tx.withdraw(
            withdraw_asset,
            withdraw_amount,
            WithdrawalTarget::Sol {
                user_sol_account: Address::new_from_array([9u8; 32]),
            },
        )
        .expect("withdraw");
        tx.sign(sender, assets).expect("sign")
    }

    fn confidential_withdrawal(
        sender: &ShieldedKeypair,
        inputs: Vec<SpendUtxo>,
        asset: Address,
        amount: u64,
        assets: &AssetRegistry,
    ) -> SignedTransaction {
        let mut tx = Transaction::new(
            sender.shielded_address().expect("sender address"),
            inputs,
            Address::default(),
        );
        tx.withdraw(
            asset,
            amount,
            WithdrawalTarget::Sol {
                user_sol_account: Address::new_from_array([9u8; 32]),
            },
        )
        .expect("withdraw");
        tx.sign(sender, assets).expect("sign")
    }

    fn signed_to_shielded_tx(signed: SignedTransaction, slot: u64) -> ShieldedTransaction {
        let nullifiers = signed
            .input_commitments()
            .expect("input commitments")
            .into_iter()
            .map(|commitment| commitment.nullifier)
            .collect();
        let external = signed.external_data;
        let output_slots = external
            .output_utxo_hashes
            .iter()
            .enumerate()
            .map(|(i, hash)| {
                let ciphertext = match i {
                    0 => external.output_ciphertexts.first(),
                    1 => None,
                    _ => external.output_ciphertexts.get(i - 1),
                };
                OutputSlot {
                    view_tag: ciphertext.map(|c| c.view_tag).unwrap_or_default(),
                    output_context: OutputContext {
                        hash: *hash,
                        tree: Address::new_from_array([slot as u8; 32]),
                        leaf_index: i as u64,
                    },
                    payload: ciphertext.map(|c| c.data.clone()).unwrap_or_default(),
                }
            })
            .collect();
        ShieldedTransaction {
            slot,
            tx_signature: signature_for_slot(slot),
            tx_viewing_pk: Some(
                zolana_keypair::P256Pubkey::from_bytes(external.tx_viewing_pk)
                    .expect("tx viewing pk"),
            ),
            salt: Some(external.salt),
            output_slots,
            nullifiers,
            proofless: false,
        }
    }

    fn merge_tx(
        owner: &ShieldedKeypair,
        inputs: Vec<SpendUtxo>,
        slot: u64,
        assets: &AssetRegistry,
    ) -> ShieldedTransaction {
        let merge = MergePlan::new(owner, inputs).expect("merge plan");
        let prepared = merge.prepare();
        let commitments = prepared.input_commitments().expect("input commitments");
        let output = Utxo {
            owner: owner.signing_pubkey(),
            asset: prepared.output.asset,
            amount: prepared.output.amount,
            blinding: prepared.output.blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let output_hash = output
            .hash(
                &owner.nullifier_key.pubkey().expect("nullifier pubkey"),
                &[0u8; 32],
                &[0u8; 32],
            )
            .expect("output hash");
        let tx_key = ViewingKey::new();
        let ciphertext = Merge::encode(
            std::slice::from_ref(&output),
            &OwnerCx {
                owner: owner.signing_pubkey(),
                assets,
                zone_program_id: None,
            },
            owner
                .signing_pubkey()
                .confidential_view_tag()
                .expect("owner tag"),
            &MergeEncode {
                tx: tx_key,
                user_viewing_pk: owner.viewing_pubkey(),
            },
        )
        .expect("merge ciphertext");
        ShieldedTransaction {
            slot,
            tx_signature: signature_for_slot(slot),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![OutputSlot {
                view_tag: ciphertext.view_tag,
                output_context: OutputContext {
                    hash: output_hash,
                    tree: Address::new_from_array([slot as u8; 32]),
                    leaf_index: 0,
                },
                payload: ciphertext.data,
            }],
            nullifiers: commitments
                .into_iter()
                .map(|commitment| commitment.nullifier)
                .collect(),
            proofless: false,
        }
    }

    fn signature_for_slot(slot: u64) -> Signature {
        let mut bytes = [0u8; 64];
        bytes[..8].copy_from_slice(&slot.to_be_bytes());
        Signature::from(bytes)
    }

    fn wallet_with_utxo(owner: &ShieldedKeypair, asset: Address, amount: u64, seed: u8) -> Wallet {
        wallet_with_utxos(owner, &[(asset, amount, seed)])
    }

    fn wallet_with_utxos(owner: &ShieldedKeypair, entries: &[(Address, u64, u8)]) -> Wallet {
        let mut registry = AssetRegistry::default();
        let mut next_asset_id = 2u64;
        for &(asset, _, _) in entries {
            if asset != SOL_MINT && registry.asset_id(&asset).is_err() {
                registry
                    .insert(next_asset_id, asset)
                    .expect("register asset");
                next_asset_id += 1;
            }
        }
        let mut wallet = Wallet::new(owner.clone(), registry).expect("wallet");
        for &(asset, amount, seed) in entries {
            let utxo = test_utxo(owner, asset, amount, seed);
            let nullifier_pk = owner.nullifier_key.pubkey().expect("nullifier pubkey");
            let hash = utxo
                .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
                .expect("utxo hash");
            let nullifier = utxo
                .nullifier(&hash, &owner.nullifier_key)
                .expect("nullifier");
            wallet.utxos.push(WalletUtxo {
                utxo,
                output_context: OutputContext {
                    hash,
                    tree: Address::default(),
                    leaf_index: u64::from(seed),
                },
                nullifier,
                spent: false,
            });
        }
        wallet
    }

    fn test_utxo(owner: &ShieldedKeypair, asset: Address, amount: u64, seed: u8) -> Utxo {
        Utxo {
            owner: owner.signing_pubkey(),
            asset,
            amount,
            blinding: [seed; BLINDING_LEN],
            zone_program_id: None,
            data: Data::default(),
        }
    }

    fn proofless_output_for_wallet(wallet: &Wallet, amount: u64) -> ProoflessOutput {
        ProoflessOutput {
            owner: wallet.keypair.owner_hash().expect("owner hash"),
            blinding: [9u8; BLINDING_LEN],
            asset: SOL_MINT.to_bytes(),
            amount,
            data_hash: None,
            utxo_data: None,
            zone_program_id: None,
            zone_data_hash: None,
            zone_data: None,
            memo: None,
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
        let data_hash = output.data_hash.unwrap_or([0u8; 32]);
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
        utxo.hash(&nullifier_pk, &data_hash, &zone_data_hash)
            .expect("proofless leaf hash")
    }
}
