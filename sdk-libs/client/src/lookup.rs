//! Bounded, signature-scoped activity. No transaction or nullifier history
//! pages are read. Missing evidence never becomes a partial or guessed result.

use crate::{
    fetch_spl_asset_registrations, rpc::solana_rpc::ConfirmedInstructionGroups, ClientError, Rpc,
};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction_status_client_types::EncodedConfirmedTransactionWithStatusMeta;
use spr_interface::{
    event::OutputDataEncoding,
    instruction::{fetch_tag, settlement_accounts, tag, CircuitId, TransactIxData},
    PROGRAM_ID_PUBKEY,
};
use spr_keypair::PublicKey;
use spr_transaction::{
    decrypt, serialization::confidential::Confidential, utxo::DummyOutputOpening, verify_owned,
    AssetRegistry, EncryptedScheme, HistoryEntry, HistoryKind, ShieldedKeys, ShieldedTransaction,
    TransactionError, TransactionKeyRequest, SOL_MINT,
};
use std::collections::{BTreeMap, HashMap, HashSet};

type Confirmed = EncodedConfirmedTransactionWithStatusMeta;

/// Completeness of activity details, independent of transaction confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionLookupStatus {
    /// Complete for configured assets; an empty result means no matching rows.
    Ready,
    /// The confirmed slot is ahead of the indexer. Retry after it catches up.
    PendingIndexing,
    /// Neither source found the signature. Pruned history can also cause this.
    NotFound,
    /// Found, but the format or available evidence cannot establish every row.
    Incomplete,
}
use TransactionLookupStatus as Status;

/// A signature-scoped result. Only `Ready` carries activity entries.
#[derive(Clone, Debug)]
pub struct TransactionLookup {
    pub status: TransactionLookupStatus,
    pub entries: Vec<HistoryEntry>,
    pub slot: Option<u64>,
    pub indexed_slot: u64,
    /// Mappings used by the read, including any discovered registered assets.
    pub asset_registry: AssetRegistry,
}

/// Stateless counterpart of `UtxoScan` for one signature. Requires a combined
/// RPC/indexer reader; `ZolanaClient` implements that surface.
pub struct TransactionReader<'a, K: ?Sized> {
    keys: &'a K,
    assets: &'a AssetRegistry,
    discover_assets: bool,
    padding: &'a [DummyOutputOpening],
}

impl<'a, K: ShieldedKeys + ?Sized> TransactionReader<'a, K> {
    pub fn new(keys: &'a K, assets: &'a AssetRegistry) -> Self {
        Self {
            keys,
            assets,
            discover_assets: false,
            padding: &[],
        }
    }

    /// Resolve registered assets once when the fetched events need them.
    /// Without this, only the supplied asset registry is read.
    #[must_use]
    pub fn with_asset_discovery(mut self) -> Self {
        self.discover_assets = true;
        self
    }

    /// Verify saved dummy openings against published commitments and trees.
    /// Useful for an exact-balance send whose padding borrows a recipient tag.
    /// Other outputs and settlements still require their normal evidence.
    #[must_use]
    pub fn with_padding_openings(mut self, padding: &'a [DummyOutputOpening]) -> Self {
        self.padding = padding;
        self
    }

    /// Read exactly this signature, plus any needed asset and recipient records.
    /// Network errors propagate. No history pagination or confirmation polling.
    pub fn fetch<R: Rpc + Sync + ?Sized>(
        &self,
        client: &R,
        signature: Signature,
    ) -> Result<TransactionLookup, ClientError> {
        let (indexed, confirmed) = std::thread::scope(|scope| {
            let indexed =
                scope.spawn(|| client.get_shielded_transactions_by_signature(signature, None));
            let confirmed = client.get_confirmed_transaction(signature);
            (
                indexed
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
                confirmed,
            )
        });
        let indexed = indexed?;
        let confirmed = confirmed?;
        let mut registry = self.assets.clone();
        let mut event_ids = HashSet::new();
        let mut transactions = Vec::with_capacity(indexed.transactions.len());
        let slot = confirmed
            .as_ref()
            .map(|tx| tx.slot)
            .or_else(|| indexed.transactions.first().map(|tx| tx.transaction.slot));
        for event in indexed.transactions {
            let tx = event.transaction;
            if tx.tx_signature != signature
                || Some(tx.slot) != slot
                || !event_ids.insert(event.event_index)
            {
                return Err(ClientError::Rpc(
                    "inconsistent signature lookup response".into(),
                ));
            }
            transactions.push(tx);
        }
        let result = |status, entries, registry: &AssetRegistry| TransactionLookup {
            status,
            entries,
            slot,
            indexed_slot: indexed.context.slot,
            asset_registry: registry.clone(),
        };
        if slot.is_none() {
            return Ok(result(Status::NotFound, vec![], &registry));
        }
        if slot.is_some_and(|slot| slot > indexed.context.slot) {
            return Ok(result(Status::PendingIndexing, vec![], &registry));
        }
        if transactions.is_empty() {
            return Ok(result(Status::Ready, vec![], &registry));
        }
        if confirmed
            .as_ref()
            .and_then(|tx| tx.transaction.meta.as_ref())
            .is_some_and(|meta| meta.err.is_some())
        {
            return Err(ClientError::Rpc(
                "indexer returned shielded events for a failed transaction".into(),
            ));
        }
        let mut details = self.lookup_details(
            client,
            signature,
            &transactions,
            &registry,
            self.discover_assets,
            confirmed.as_ref(),
        )?;
        if matches!(details, Details::NeedAssets) && self.discover_assets {
            for mint in fetch_spl_asset_registrations(client, slot)? {
                if registry.asset_id(&mint.asset).ok() != Some(mint.asset_id) {
                    registry.insert(mint.asset_id, mint.asset)?;
                }
            }
            details = self.lookup_details(
                client,
                signature,
                &transactions,
                &registry,
                false,
                confirmed.as_ref(),
            )?;
        }
        match details {
            Details::Complete(entries) => Ok(result(Status::Ready, entries, &registry)),
            Details::Incomplete | Details::NeedAssets => {
                Ok(result(Status::Incomplete, vec![], &registry))
            }
        }
    }
}
enum Details {
    Complete(Vec<HistoryEntry>),
    NeedAssets,
    Incomplete,
}

#[derive(Default)]
struct Movement {
    received: u128,
    spent: u128,
}

impl<K: ShieldedKeys + ?Sized> TransactionReader<'_, K> {
    fn lookup_details<R: Rpc + ?Sized>(
        &self,
        client: &R,
        signature: Signature,
        transactions: &[ShieldedTransaction],
        assets: &AssetRegistry,
        discover: bool,
        confirmed: Option<&Confirmed>,
    ) -> Result<Details, ClientError> {
        let padding = self
            .padding
            .iter()
            .map(|opening| Ok((opening.tree_id, opening.commitment()?)))
            .collect::<Result<HashSet<_>, TransactionError>>()?;
        let address = self.keys.address()?;
        let owner = Pubkey::new_from_array(address.signing_pubkey.confidential_view_tag()?);
        let decoded = decrypt(self.keys, transactions, assets)?;
        if discover && (!decoded.unknown_asset_ids.is_empty() || !decoded.unknown_mints.is_empty())
        {
            return Ok(Details::NeedAssets);
        }
        if !discover
            && self.discover_assets
            && (!decoded.unknown_asset_ids.is_empty() || !decoded.unknown_mints.is_empty())
        {
            return Ok(Details::Incomplete);
        }
        let owned = verify_owned(self.keys, &decoded)?;
        let by_hash: HashMap<_, _> = owned
            .utxos
            .iter()
            .map(|utxo| (utxo.utxo_hash, utxo))
            .collect();
        let mut movements = BTreeMap::<Pubkey, Movement>::new();
        let mut counted = HashSet::new();
        let mut spends = HashSet::new();
        let own_tag = address.signing_pubkey.confidential_view_tag()?;
        let own_hash = address.owner_hash()?;
        let mut tags: HashSet<_> = self
            .keys
            .viewing_public_keys()
            .iter()
            .map(|key| key.u())
            .collect();
        tags.insert(own_tag);
        let mut pays_another = false;
        let deposit = transactions.iter().any(|tx| tx.proofless);
        let groups = confirmed
            .cloned()
            .and_then(|tx| ConfirmedInstructionGroups::try_from(tx).ok());

        for tx in transactions {
            let mut received = BTreeMap::<Pubkey, u128>::new();
            for slot in &tx.output_slots {
                if let Some(note) = by_hash.get(&slot.output_context.hash) {
                    *received.entry(note.utxo.asset.asset).or_default() +=
                        u128::from(note.utxo.amount);
                    if counted.insert(note.utxo_hash) {
                        movements.entry(note.utxo.asset.asset).or_default().received +=
                            u128::from(note.utxo.amount);
                    }
                } else if matches!(slot.output_data(), Some(OutputDataEncoding::Encrypted(ref blob))
                    if blob.first() == Some(&EncryptedScheme::Confidential.as_byte()) &&
                    Confidential::embedded_viewing_pk(&blob[1..]).ok() == Some(address.viewing_pubkey))
                    || slot.proofless_output().is_some_and(|output| {
                        output.owner == own_hash
                            && assets
                                .asset_id(&Pubkey::new_from_array(output.asset))
                                .is_ok()
                    })
                {
                    return Ok(Details::Incomplete);
                } else if !tags.contains(&slot.view_tag) {
                    pays_another = true;
                }
            }
            if tx.proofless {
                continue;
            }
            if tx.may_be_merge() && tx.output_slots.iter().any(|slot| {
                matches!(slot.output_data(), Some(OutputDataEncoding::VerifiablyEncrypted(ref blob) | OutputDataEncoding::Encrypted(ref blob))
                    if blob.first() == Some(&EncryptedScheme::Merge.as_byte()))
            }) {
                if received.is_empty() && decoded.unknown_mints.is_empty() &&
                    tx.output_slots.iter().any(|slot| tags.contains(&slot.view_tag)) {
                    return Ok(Details::Incomplete);
                }
                // The existing merge decoder derives the key from the owner's
                // nullifier secret and accepts only commitment-matching notes.
                if !received.is_empty() && spends.insert(tx.nullifiers.clone()) {
                    for (mint, amount) in received {
                        movements.entry(mint).or_default().spent += amount;
                    }
                }
                continue;
            }
            let Some(first) = tx.nullifiers.first() else {
                continue;
            };
            let key = self
                .keys
                .transaction_keys(&[TransactionKeyRequest {
                    viewing_pubkey: address.viewing_pubkey,
                    first_nullifier: *first,
                }])?
                .into_iter()
                .next()
                .ok_or(TransactionError::IncompleteDerivation { got: 0, want: 1 })?;
            let context = groups
                .as_ref()
                .and_then(|groups| transact_context(tx, groups));
            if groups.is_some() && tx.ring_config.is_none() && context.is_none() {
                return Ok(Details::Incomplete);
            }
            if Some(key.pubkey()) != tx.tx_viewing_pk {
                // A sponsor signing as fee payer owns no inputs merely by
                // paying. An actual owner whose key cannot read the spend
                // needs context this bounded reader does not have.
                if context
                    .as_ref()
                    .is_some_and(|cx| cx.owners.contains(&owner))
                {
                    return Ok(Details::Incomplete);
                }
                continue;
            }
            let Some(cx) = context else {
                return Ok(Details::Incomplete);
            };
            if !matches!(cx.data.circuit.uncached(), CircuitId::ConfidentialEddsa(..))
                || cx.owners != [owner]
            {
                return Ok(Details::Incomplete);
            }
            if !spends.insert(tx.nullifiers.clone()) {
                continue;
            }
            let owners: Vec<_> = tx
                .output_slots
                .iter()
                .filter(|slot| slot.view_tag != own_tag)
                .map(|slot| Pubkey::new_from_array(slot.view_tag))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            let records = if owners.is_empty() {
                HashMap::new()
            } else {
                let response = client.get_user_records(owners.clone(), None)?;
                if response.records.len() != owners.len() {
                    return Ok(Details::Incomplete);
                }
                let mut records = HashMap::new();
                for (owner, record) in owners.into_iter().zip(response.records) {
                    let Some(record) = record else {
                        return Ok(Details::Incomplete);
                    };
                    if record.owner != owner {
                        return Ok(Details::Incomplete);
                    }
                    records.insert(owner, record);
                }
                records
            };
            // Outputs owned by somebody else and public settlement legs are
            // the outflow. Change cancels out, so no input-note history is
            // required. Self-transfers instead spend exactly their kept value.
            let mut net = BTreeMap::<Pubkey, i128>::new();
            let Some(salt) = tx.salt else {
                return Ok(Details::Incomplete);
            };
            for (index, slot) in tx.output_slots.iter().enumerate() {
                if slot.view_tag == own_tag
                    || padding.contains(&(slot.output_context.tree_id, slot.output_context.hash))
                {
                    continue;
                }
                let Some(OutputDataEncoding::Encrypted(blob)) = slot.output_data() else {
                    return Ok(Details::Incomplete);
                };
                let Some((&scheme, body)) = blob.split_first() else {
                    return Ok(Details::Incomplete);
                };
                if scheme != EncryptedScheme::Confidential.as_byte() {
                    return Ok(Details::Incomplete);
                }
                let Ok(plaintext) =
                    Confidential::decrypt_with_tx_key(&key, body, salt, index as u32)
                else {
                    return Ok(Details::Incomplete);
                };
                let record = &records[&Pubkey::new_from_array(slot.view_tag)];
                let owner = PublicKey::from_ed25519(record.owner.as_array());
                let note = match plaintext.into_utxo(owner, assets) {
                    Ok(note) => note,
                    Err(TransactionError::UnknownAsset(_)) if discover => {
                        return Ok(Details::NeedAssets)
                    }
                    Err(TransactionError::UnknownAsset(_)) if !self.discover_assets => continue,
                    Err(_) => return Ok(Details::Incomplete),
                };
                if note.ring_program_id.is_some()
                    || note.data.utxo_data().is_some()
                    || note.data.ring_data().is_some()
                    || note.hash(
                        &record.nullifier_pubkey,
                        &[0; 32],
                        &[0; 32],
                        slot.output_context.tree_id,
                    )? != slot.output_context.hash
                {
                    return Ok(Details::Incomplete);
                }
                *net.entry(note.asset.asset).or_default() += i128::from(note.amount);
            }
            let Some(settlements) =
                settlement_accounts(&cx.data.interface_transfers, cx.data.circuit, &cx.accounts)
            else {
                return Ok(Details::Incomplete);
            };
            let mut offset = 0;
            for leg in &cx.data.interface_transfers {
                let mint = leg
                    .mint_account_position()
                    .map_or(SOL_MINT, |i| settlements[offset + i]);
                offset += leg.settlement_account_count();
                if assets.asset_id(&mint).is_err() {
                    if discover {
                        return Ok(Details::NeedAssets);
                    }
                    if self.discover_assets {
                        return Ok(Details::Incomplete);
                    }
                    continue;
                }
                *net.entry(mint).or_default() += if leg.is_deposit() {
                    -i128::from(leg.amount())
                } else {
                    i128::from(leg.amount())
                };
            }
            for mint in received.keys() {
                net.entry(*mint).or_default();
            }
            for (mint, net) in net {
                let kept = received.get(&mint).copied().unwrap_or_default();
                let spent = kept as i128 + net;
                if spent < 0 {
                    return Ok(Details::Incomplete);
                }
                movements.entry(mint).or_default().spent += spent as u128;
            }
        }
        let mut entries = Vec::new();
        for (mint, movement) in movements {
            let (received, spent) = (movement.received, movement.spent);
            let (kind, amount) = if spent == 0 {
                (
                    if deposit {
                        HistoryKind::Deposit
                    } else {
                        HistoryKind::Received
                    },
                    received,
                )
            } else if spent == received {
                (HistoryKind::SelfTransfer, spent)
            } else if received > spent {
                (HistoryKind::Deposit, received - spent)
            } else {
                (
                    if pays_another {
                        HistoryKind::Sent
                    } else {
                        HistoryKind::Withdrawal
                    },
                    spent - received,
                )
            };
            if amount == 0 {
                continue;
            }
            let amount = u64::try_from(amount)
                .map_err(|_| ClientError::Rpc("activity amount exceeds u64".into()))?;
            entries.push(HistoryEntry {
                kind,
                mint,
                amount,
                tx_signature: signature,
                slot: transactions[0].slot,
            });
        }
        Ok(Details::Complete(entries))
    }
}

struct TransactContext {
    data: TransactIxData,
    accounts: Vec<Pubkey>,
    owners: Vec<Pubkey>,
}

/// Bind the indexer's event to a real SPP invocation, including ciphertexts,
/// commitments and resolved owner tags. A matching byte sequence elsewhere in
/// the transaction is not an instruction or evidence for a settlement.
fn transact_context(
    tx: &ShieldedTransaction,
    groups: &ConfirmedInstructionGroups,
) -> Option<TransactContext> {
    for instruction in groups
        .groups
        .iter()
        .flat_map(|group| std::iter::once(&group.outer).chain(&group.inner))
    {
        if instruction.program_id != PROGRAM_ID_PUBKEY
            || instruction.data.first() != Some(&tag::TRANSACT)
        {
            continue;
        }
        let data = TransactIxData::deserialize(instruction.data.get(1..)?).ok()?;
        if data
            .inputs
            .iter()
            .map(|input| input.nullifier_hash)
            .collect::<Vec<_>>()
            != tx.nullifiers
            || data.outputs.len() != tx.output_slots.len()
            || Some(data.tx_viewing_pk) != tx.tx_viewing_pk.map(|key| *key.as_bytes())
            || Some(data.salt) != tx.salt
        {
            continue;
        }
        let same_outputs = data
            .outputs
            .iter()
            .zip(&tx.output_slots)
            .all(|(output, slot)| {
                output.utxo_hash == slot.output_context.hash
                    && output.data.as_deref() == Some(slot.payload.as_slice())
                    && fetch_tag(&output.owner_tag, |i| {
                        instruction
                            .accounts
                            .get(usize::from(i))
                            .map(|key| key.to_bytes())
                    })
                    .ok()
                        == Some(slot.view_tag)
            });
        if !same_outputs {
            continue;
        }
        let settlements = settlement_accounts(
            &data.interface_transfers,
            data.circuit,
            &instruction.accounts,
        )?;
        let start = 4 + data.tree_contexts.len() + data.inputs.len();
        let cache_accounts = data.circuit.cache_access().map_or(0, |access| {
            usize::from(access.read_bitmap != 0) + 2 * usize::from(access.writes_cache())
        });
        let end = instruction
            .accounts
            .len()
            .checked_sub(cache_accounts + settlements.len())?;
        let owners = instruction.accounts.get(start..end)?.to_vec();
        return Some(TransactContext {
            data,
            accounts: instruction.accounts.clone(),
            owners,
        });
    }
    None
}

#[cfg(test)]
mod tests;
