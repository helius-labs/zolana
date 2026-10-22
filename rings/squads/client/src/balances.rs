//! `getBalances`: decrypt every UTXO an account owns with the auditor-recovered
//! shared viewing key, drop spent ones, and aggregate per asset.
//!
//! An account's outputs are found by its view tags, except merged outputs, which
//! SPP indexes by the merge's first nullifier:
//! - a deposit publishes its blinding in the clear in its ring deposit record;
//! - a transfer's recipient output carries the 72-byte recipient ciphertext;
//! - a spend's change output carries the 40-byte sender ciphertext, keyed by the
//!   spend's first published nullifier;
//! - a merge output carries no ciphertext: its amount is the sum of the merged
//!   inputs and its blinding derives from the nullifier secret.
//!
//! Every candidate is accepted only if it recomputes the published UTXO hash.

use std::collections::{HashMap, HashSet};

use zolana_client::Rpc;
use zolana_event_parser::decode_encrypted_ring_deposit_output_data;
use zolana_keypair::{NullifierKey, PublicKey};
use zolana_squads_interface::{
    constants::{RECIPIENT_CIPHERTEXT_LEN, SENDER_CIPHERTEXT_LEN},
    SQUADS_RING_PROGRAM_ID,
};
use zolana_squads_sdk::{
    encrypted_utxo::decrypt_recipient_ciphertext, prover::decrypt_sender_change,
};
use zolana_transaction::{
    instructions::{merge::merge_output_blinding, transact::asset_field},
    Address, Data, Mint, OutputSlot, ShieldedTransaction, Utxo, SOL_MINT,
};

use crate::{
    backend::{ResolvedAccount, SquadsBackend},
    error::{Result, SquadsBackendError},
    tags::account_query_tags,
    types::{AssetBalance, DecryptedUtxo, GetBalancesRequest, GetBalancesResponse},
};

const PAGE_LIMIT: u32 = 1_000;

/// An account's UTXO decryption context.
struct Owner<'a> {
    resolved: &'a ResolvedAccount,
    nullifier_key: NullifierKey,
    nullifier_pubkey: [u8; 32],
    tags: Vec<[u8; 32]>,
    /// `asset_field(mint)` and the raw mint bytes, each to `(asset_id, mint)`.
    assets: HashMap<[u8; 32], (u64, Address)>,
}

impl Owner<'_> {
    /// Accept `(asset_id, amount, blinding)` for `slot` only if it recomputes
    /// the published hash.
    fn utxo(
        &self,
        slot: &OutputSlot,
        asset: &[u8; 32],
        amount: u64,
        blinding: [u8; 32],
    ) -> Option<DecryptedUtxo> {
        let (asset_id, mint) = *self.assets.get(asset)?;
        let context = &slot.output_context;
        let utxo = Utxo {
            owner: PublicKey::from_owner_identity(self.resolved.account.owner.to_bytes()),
            asset: if mint == SOL_MINT {
                Mint::SOL
            } else {
                Mint::new(mint, asset_id)
            },
            amount,
            blinding,
            ring_program_id: Some(Address::new_from_array(SQUADS_RING_PROGRAM_ID)),
            data: Data::default(),
        };
        let hash = utxo
            .hash(
                &self.nullifier_pubkey,
                &[0u8; 32],
                &[0u8; 32],
                context.tree_id,
            )
            .ok()?;
        (hash == context.hash).then_some(DecryptedUtxo {
            utxo_hash: hash,
            asset_id,
            amount,
            blinding,
            tree_id: context.tree_id,
            leaf_index: context.leaf_index,
        })
    }

    /// Decrypt the outputs of `tx` tagged for this account.
    fn tagged_outputs(&self, tx: &ShieldedTransaction) -> Vec<DecryptedUtxo> {
        let mut out = Vec::new();
        for slot in tx
            .output_slots
            .iter()
            .filter(|slot| self.tags.contains(&slot.view_tag))
        {
            let decrypted = if tx.proofless {
                self.deposit(slot)
            } else if slot.payload.len() == RECIPIENT_CIPHERTEXT_LEN {
                self.recipient_output(tx, slot)
            } else if slot.payload.len() == SENDER_CIPHERTEXT_LEN {
                self.change_output(tx, slot)
            } else {
                None
            };
            out.extend(decrypted);
        }
        out
    }

    fn deposit(&self, slot: &OutputSlot) -> Option<DecryptedUtxo> {
        let output = decode_encrypted_ring_deposit_output_data(&slot.payload).ok()?;
        let blinding: [u8; 32] = output.encrypted.ciphertext.as_slice().try_into().ok()?;
        self.utxo(slot, &output.asset, output.amount, blinding)
    }

    fn recipient_output(
        &self,
        tx: &ShieldedTransaction,
        slot: &OutputSlot,
    ) -> Option<DecryptedUtxo> {
        let tx_viewing_pk = tx.tx_viewing_pk?;
        let ciphertext: [u8; RECIPIENT_CIPHERTEXT_LEN] = slot.payload.as_slice().try_into().ok()?;
        let (amount, asset, blinding) = decrypt_recipient_ciphertext(
            &self.resolved.shared_viewing_sk,
            &tx_viewing_pk,
            &ciphertext,
        )
        .ok()?;
        self.utxo(slot, &asset, amount, blinding)
    }

    fn change_output(&self, tx: &ShieldedTransaction, slot: &OutputSlot) -> Option<DecryptedUtxo> {
        let first_nullifier = tx.nullifiers.first()?;
        let (amount, asset, blinding) = decrypt_sender_change(
            &self.resolved.shared_viewing_sk,
            first_nullifier,
            &slot.payload,
        )
        .ok()?;
        self.utxo(slot, &asset, amount, blinding)
    }

    /// The merged output of `tx`, if it merged this account's `known` UTXOs.
    fn merge_output(
        &self,
        tx: &ShieldedTransaction,
        known: &HashMap<[u8; 32], DecryptedUtxo>,
    ) -> Option<DecryptedUtxo> {
        let [slot] = tx.output_slots.as_slice() else {
            return None;
        };
        let first_nullifier = tx.nullifiers.first()?;
        if slot.view_tag != *first_nullifier {
            return None;
        }
        let first = known.get(first_nullifier)?;
        let amount = tx
            .nullifiers
            .iter()
            .filter_map(|nullifier| known.get(nullifier))
            .try_fold(0u64, |acc, utxo| acc.checked_add(utxo.amount))?;
        let blinding = merge_output_blinding(&self.nullifier_key, first_nullifier).ok()?;
        let (_, mint) = self
            .assets
            .values()
            .find(|(asset_id, _)| *asset_id == first.asset_id)?;
        self.utxo(slot, &mint.to_bytes(), amount, blinding)
    }

    fn nullifier(&self, utxo: &DecryptedUtxo) -> Result<[u8; 32]> {
        self.nullifier_key
            .nullifier(&utxo.utxo_hash, &utxo.blinding)
            .map_err(|e| SquadsBackendError::Crypto(format!("nullifier: {e:?}")))
    }
}

impl<I: Rpc, R: Rpc> SquadsBackend<I, R> {
    /// The user's balance per asset, decrypted with the shared viewing key.
    pub fn get_balances(&self, request: GetBalancesRequest) -> Result<GetBalancesResponse> {
        self.authorize_read(request.viewing_key_account, &request.signature)?;

        let resolved = self.resolve_shared_key(request.viewing_key_account)?;
        let nullifier_key = NullifierKey::from_secret(resolved.nullifier_secret);
        let owner = Owner {
            tags: account_query_tags(&resolved.account),
            assets: self.asset_field_map()?,
            nullifier_pubkey: resolved.account.nullifier_pubkey,
            nullifier_key,
            resolved: &resolved,
        };

        let mut known: HashMap<[u8; 32], DecryptedUtxo> = HashMap::new();
        let mut hashes: HashSet<[u8; 32]> = HashSet::new();
        let mut add =
            |utxo: DecryptedUtxo, owner: &Owner<'_>, known: &mut HashMap<_, _>| -> Result<()> {
                if hashes.insert(utxo.utxo_hash) {
                    known.insert(owner.nullifier(&utxo)?, utxo);
                }
                Ok(())
            };

        for tx in self.transactions_by_tags(&owner.tags)? {
            for utxo in owner.tagged_outputs(&tx) {
                add(utxo, &owner, &mut known)?;
            }
        }
        // Merges chain: a merged output can itself be merged later, so repeat
        // until no new merge output appears.
        let mut queried: HashSet<[u8; 32]> = HashSet::new();
        loop {
            let pending: Vec<[u8; 32]> = known
                .keys()
                .filter(|nullifier| !queried.contains(*nullifier))
                .copied()
                .collect();
            if pending.is_empty() {
                break;
            }
            queried.extend(pending.iter().copied());
            let mut found = Vec::new();
            for tx in self.transactions_by_nullifiers(pending)? {
                found.extend(owner.merge_output(&tx, &known));
            }
            for utxo in found {
                add(utxo, &owner, &mut known)?;
            }
        }

        let mut unspent = Vec::new();
        for (nullifier, utxo) in known {
            if !self.is_spent(&nullifier, utxo.tree_id)? {
                unspent.push(utxo);
            }
        }
        Ok(GetBalancesResponse {
            balances: self.aggregate(unspent, &owner.assets, request.skip_utxos),
        })
    }

    /// Mock authorization hook. A production backend verifies `signature` over the
    /// request by the account owner (or a smart-account key holder) and rejects
    /// reads of another user's data; the in-process mock authorizes every caller.
    fn authorize_read(&self, _viewing_key_account: Address, _signature: &[u8; 64]) -> Result<()> {
        Ok(())
    }

    /// `asset_field(mint)` and the raw mint bytes both map to `(asset_id, mint)`:
    /// ciphertexts carry the field element, deposit records the mint.
    fn asset_field_map(&self) -> Result<HashMap<[u8; 32], (u64, Address)>> {
        let mut map = HashMap::new();
        for (asset_id, mint) in self.assets() {
            let fe = asset_field(mint)
                .map_err(|e| SquadsBackendError::Crypto(format!("asset_field: {e:?}")))?;
            map.insert(fe, (*asset_id, *mint));
            map.insert(mint.to_bytes(), (*asset_id, *mint));
        }
        Ok(map)
    }

    fn transactions_by_tags(&self, tags: &[[u8; 32]]) -> Result<Vec<ShieldedTransaction>> {
        let mut transactions = Vec::new();
        let mut cursor = None;
        loop {
            let response = self.indexer().get_shielded_transactions_by_tags(
                tags.to_vec(),
                cursor,
                Some(PAGE_LIMIT),
                None,
            )?;
            transactions.extend(response.transactions);
            cursor = response.next_cursor;
            if cursor.is_none() {
                return Ok(transactions);
            }
        }
    }

    fn transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
    ) -> Result<Vec<ShieldedTransaction>> {
        let mut transactions = Vec::new();
        let mut cursor = None;
        loop {
            let response = self.indexer().get_shielded_transactions_by_nullifiers(
                nullifiers.clone(),
                cursor,
                Some(PAGE_LIMIT),
                None,
            )?;
            transactions.extend(response.transactions);
            cursor = response.next_cursor;
            if cursor.is_none() {
                return Ok(transactions);
            }
        }
    }

    /// A UTXO is spent when its nullifier is already in its tree, i.e. no
    /// non-inclusion proof can be produced for it.
    fn is_spent(&self, nullifier: &[u8; 32], tree_id: u16) -> Result<bool> {
        match self.indexer().get_non_inclusion_proofs(
            self.tree_for(tree_id),
            vec![*nullifier],
            None,
        ) {
            Ok(response) => Ok(response.proofs.is_empty()),
            Err(_) => Ok(true),
        }
    }

    fn aggregate(
        &self,
        utxos: Vec<DecryptedUtxo>,
        asset_map: &HashMap<[u8; 32], (u64, Address)>,
        skip_utxos: bool,
    ) -> Vec<AssetBalance> {
        let mint_for = |asset_id: u64| -> Address {
            asset_map
                .values()
                .find(|(id, _)| *id == asset_id)
                .map(|(_, mint)| *mint)
                .unwrap_or_default()
        };

        let mut by_asset: HashMap<u64, AssetBalance> = HashMap::new();
        for utxo in utxos {
            let entry = by_asset
                .entry(utxo.asset_id)
                .or_insert_with(|| AssetBalance {
                    asset_id: utxo.asset_id,
                    mint: mint_for(utxo.asset_id),
                    amount: 0,
                    utxos: Vec::new(),
                });
            entry.amount = entry.amount.saturating_add(utxo.amount);
            if !skip_utxos {
                entry.utxos.push(utxo);
            }
        }

        let mut balances: Vec<AssetBalance> = by_asset.into_values().collect();
        balances.sort_by_key(|b| b.asset_id);
        for balance in &mut balances {
            balance
                .utxos
                .sort_by_key(|utxo| (utxo.tree_id, utxo.leaf_index));
        }
        balances
    }
}
