//! A wallet's spendable UTXOs, read from the indexer.
//!
//! Stateless: [`SpendableUtxos::fetch`] reads the transactions tagged for the
//! wallet, decrypts them with [`decrypt_spendable`], then reads the
//! transactions that spent the UTXOs it found, until a round finds nothing
//! new. A merge, or a spend another client made, can carry none of the
//! wallet's tags; only the nullifier rounds find those.

use std::collections::HashSet;

use solana_address::Address;
use solana_signature::Signature;
use zolana_keypair::P256Pubkey;
use zolana_transaction::{
    decrypt_spendable, AssetRegistry, DepositPayload, ShieldedKeys, SpendableDecryptionResult,
};

use crate::{
    error::ClientError,
    rpc::{EncryptedUtxoMatch, Rpc, ShieldedTransaction},
};

const PAGE_LIMIT: u32 = 1_000;

pub struct SpendableUtxos<'a, K: ?Sized> {
    keys: &'a K,
    assets: &'a AssetRegistry,
    ring_deposit_payload: Option<(Address, DepositPayload)>,
}

impl<'a, K: ShieldedKeys + ?Sized> SpendableUtxos<'a, K> {
    pub fn new(keys: &'a K, assets: &'a AssetRegistry) -> Self {
        Self {
            keys,
            assets,
            ring_deposit_payload: None,
        }
    }

    /// For a ring program that frames the ciphertexts of its deposits. It
    /// reads only that ring's deposits, and [`fetch`](Self::fetch) fails on
    /// framing that does not parse.
    pub fn with_ring_deposit_payload(
        mut self,
        ring_program_id: Address,
        deposit_payload: DepositPayload,
    ) -> Self {
        self.ring_deposit_payload = Some((ring_program_id, deposit_payload));
        self
    }

    /// Reads the transactions tagged with the owner tag, which confidential
    /// outputs carry, and with each held viewing key's tag, which deposits
    /// carry. Anonymous transfers, tagged per counterparty, are not read.
    pub fn fetch<I: Rpc + ?Sized>(
        &self,
        indexer: &I,
    ) -> Result<SpendableDecryptionResult, ClientError> {
        let address = self.keys.address()?;
        let mut tags = vec![address.signing_pubkey.confidential_view_tag()?];
        tags.extend(self.keys.viewing_public_keys().iter().map(P256Pubkey::x));

        let mut transactions = Transactions::default();
        for tx in tagged_transactions(indexer, &tags)? {
            transactions.insert(self.unwrap_ring_deposits(tx)?);
        }
        loop {
            let spendable = decrypt_spendable(self.keys, &transactions.all, self.assets)?;
            let nullifiers: Vec<_> = spendable.utxos().map(|utxo| utxo.nullifier).collect();
            let mut found = false;
            for tx in spending_transactions(indexer, &nullifiers)? {
                found |= transactions.insert(self.unwrap_ring_deposits(tx)?);
            }
            if !found {
                return Ok(spendable);
            }
        }
    }

    fn unwrap_ring_deposits(
        &self,
        mut tx: ShieldedTransaction,
    ) -> Result<ShieldedTransaction, ClientError> {
        if let Some((ring_program_id, deposit_payload)) = &self.ring_deposit_payload {
            for slot in &mut tx.output_slots {
                slot.unwrap_ring_deposit(ring_program_id, *deposit_payload)?;
            }
        }
        Ok(tx)
    }
}

/// Every fetched transaction once. A proofless deposit arrives one output at a
/// time, so its leaf is part of its identity.
#[derive(Default)]
struct Transactions {
    seen: HashSet<(Signature, Option<u16>, Option<u64>)>,
    all: Vec<ShieldedTransaction>,
}

impl Transactions {
    fn insert(&mut self, tx: ShieldedTransaction) -> bool {
        let leaf = tx
            .proofless
            .then(|| tx.output_slots.first())
            .flatten()
            .map(|slot| slot.output_context.leaf_index);
        let inserted = self.seen.insert((tx.tx_signature, tx.event_index, leaf));
        if inserted {
            self.all.push(tx);
        }
        inserted
    }
}

/// The transactions tagged with any of `tags`. Deposits come from the
/// encrypted-output stream, one transaction per output: a deposit transaction
/// can shield several outputs.
fn tagged_transactions<I: Rpc + ?Sized>(
    indexer: &I,
    tags: &[[u8; 32]],
) -> Result<Vec<ShieldedTransaction>, ClientError> {
    let mut transactions = Vec::new();
    let mut cursor = None;
    loop {
        let page = indexer.get_shielded_transactions_by_tags(
            tags.to_vec(),
            cursor,
            Some(PAGE_LIMIT),
            None,
        )?;
        transactions.extend(page.transactions.into_iter().filter(|tx| !tx.proofless));
        let Some(next) = page.next_cursor else { break };
        cursor = Some(next);
    }
    let mut cursor = None;
    loop {
        let page =
            indexer.get_encrypted_utxos_by_tags(tags.to_vec(), cursor, Some(PAGE_LIMIT), None)?;
        transactions.extend(
            page.matches
                .into_iter()
                .filter_map(EncryptedUtxoMatch::into_proofless_transaction),
        );
        let Some(next) = page.next_cursor else { break };
        cursor = Some(next);
    }
    Ok(transactions)
}

/// The transactions that spent any of `nullifiers`.
fn spending_transactions<I: Rpc + ?Sized>(
    indexer: &I,
    nullifiers: &[[u8; 32]],
) -> Result<Vec<ShieldedTransaction>, ClientError> {
    let mut transactions = Vec::new();
    for chunk in nullifiers.chunks(PAGE_LIMIT as usize) {
        let mut cursor = None;
        loop {
            let page = indexer.get_shielded_transactions_by_nullifiers(
                chunk.to_vec(),
                cursor,
                Some(PAGE_LIMIT),
                None,
            )?;
            transactions.extend(page.transactions);
            let Some(next) = page.next_cursor else { break };
            cursor = Some(next);
        }
    }
    Ok(transactions)
}
