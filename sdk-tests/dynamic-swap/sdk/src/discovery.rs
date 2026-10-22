use anyhow::{bail, Result};
use zolana_client::Rpc;
use zolana_interface::event::OutputDataEncoding;
use zolana_keypair::{ShieldedAddress, ShieldedPda, ViewingKey};
use zolana_transaction::{
    serialization::confidential::{Confidential, ConfidentialOutputPlaintext},
    utxo::Blinding,
    DecodeCx, EncryptedScheme, Mint, OutputContext, ShieldedTransaction, UtxoSerialization,
};

use crate::{
    err,
    state::{decode_order_note, decode_pool_note, PoolUtxo},
};

/// The order UTXO data a settler recovers by scanning for and decrypting the
/// order UTXO's confidential slot -- no client-side tracking. Together with the
/// `order_utxo_hash` the caller read from the escrow account and the pair's
/// public source asset, this is the complete preimage `settle` needs to spend
/// the order.
pub struct DiscoveredEscrow {
    pub order_amount: u64,
    pub order_blinding: Blinding,
    /// The taker's owner-hash, reopened with `min_price` from the order UTXO's
    /// composite data hash by the settle proof.
    pub recipient_owner_hash: [u8; 32],
    pub min_price: u64,
}

/// Scans for the `create_escrow` transaction whose order slot committed the
/// leaf `order_utxo_hash` (the value stored in the escrow account being
/// settled) by the escrow_authority PDA's public view tag, and decrypts that
/// slot with the maker's derived viewing key (see
/// `state::escrow_authority_identity`). Keying the scan by the committed leaf
/// pins the result to the escrow under settlement even when the pair has many
/// open orders sharing the authority tag. Only the SPP `transact` query and
/// `Confidential::decode` do real work here.
pub fn discover_escrow_note<I: Rpc>(
    indexer: &I,
    owner: &ShieldedPda,
    order_utxo_hash: &[u8; 32],
) -> Result<DiscoveredEscrow> {
    let tag = owner
        .shielded_address()?
        .confidential_view_tag()
        .map_err(err)?;
    let mut cursor = None;
    loop {
        let page = indexer
            .get_shielded_transactions_by_tags(vec![tag], cursor, None, None)
            .map_err(err)?;
        for tx in &page.transactions {
            if let Some(plaintext) =
                decode_order_slot(tx, &tag, order_utxo_hash, owner.viewing_key())?
            {
                let note = decode_order_note(&plaintext.data)?;
                return Ok(DiscoveredEscrow {
                    order_amount: plaintext.amount,
                    order_blinding: plaintext.blinding,
                    recipient_owner_hash: note.recipient_owner_hash,
                    min_price: note.min_price,
                });
            }
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => bail!("no escrow order note found for the committed order leaf"),
        }
    }
}

/// One pool note recovered by scanning: enough, together with the pair's
/// public destination asset, to rebuild the full `PoolUtxo` preimage and its
/// spend. The caller filters out already-spent leaves.
pub struct DiscoveredPoolNote {
    /// The committed leaf, for merkle-proof lookup and spent-set filtering.
    pub utxo_hash: [u8; 32],
    pub amount: u64,
    pub blinding: Blinding,
    pub booked: u64,
}

/// Scans for every pool note addressed to the pool_authority's view tag:
/// payload-bearing confidential pool notes from deposit, settle, withdraw and
/// rebalance transactions, decrypted with the maker's pool-role viewing key
/// (see `state::pool_authority_identity`) and served by the transactions
/// query. Proofless deposits cannot carry the booked data hash, so no pool
/// note arrives through them. Tags are public routing hints: unrelated or
/// malformed candidates are skipped. Payloadless rebalance outputs require
/// retaining their preimages locally. Only notes whose destination asset, pool
/// ownership, booked amount and full commitment validate are returned.
/// Indexer failures still propagate.
pub fn discover_pool_notes<I: Rpc>(
    indexer: &I,
    owner: &ShieldedPda,
    destination_asset: Mint,
) -> Result<Vec<DiscoveredPoolNote>> {
    let address = owner.shielded_address()?;
    let tag = address.confidential_view_tag().map_err(err)?;
    let mut notes = Vec::new();

    let mut cursor = None;
    loop {
        let page = indexer
            .get_shielded_transactions_by_tags(vec![tag], cursor, None, None)
            .map_err(err)?;
        for tx in &page.transactions {
            decode_pool_slots(
                tx,
                &tag,
                owner.viewing_key(),
                &address,
                destination_asset,
                &mut notes,
            );
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(notes),
        }
    }
}

/// Decode every confidential slot in `tx` addressed to the pool_authority
/// `tag` into pool notes (the slot index counted over data-bearing slots forms
/// the `DecodeCx`, the same path a wallet scan uses).
fn decode_pool_slots(
    tx: &ShieldedTransaction,
    tag: &[u8; 32],
    viewing_key: &ViewingKey,
    address: &ShieldedAddress,
    destination_asset: Mint,
    notes: &mut Vec<DiscoveredPoolNote>,
) {
    let mut slot_index = 0u32;
    for slot in &tx.output_slots {
        let Some(output_data) = slot.output_data() else {
            continue;
        };
        let this_index = slot_index;
        slot_index += 1;
        let OutputDataEncoding::Encrypted(blob) = output_data else {
            continue;
        };
        let Some((&scheme_byte, body)) = blob.split_first() else {
            continue;
        };
        if &slot.view_tag != tag {
            continue;
        }
        if EncryptedScheme::from_byte(scheme_byte).ok() != Some(EncryptedScheme::Confidential) {
            continue;
        }
        let cx = DecodeCx::for_slot(viewing_key, tx, this_index);
        let Ok(plaintext) = Confidential::decode(body, &cx) else {
            continue;
        };
        if plaintext.asset_id != destination_asset.asset_id
            || plaintext.ring_program_id.is_some()
            || plaintext.data.ring_data().is_some()
        {
            continue;
        }
        let Ok(booked) = decode_pool_note(&plaintext.data) else {
            continue;
        };
        let note = PoolUtxo {
            asset: destination_asset,
            amount: plaintext.amount,
            booked,
            blinding: plaintext.blinding,
        };
        if let Some(note) = validate_pool_note(note, address, &slot.output_context) {
            notes.push(note);
        }
    }
}

/// Rebuild the commitment with the expected pool owner and destination asset.
fn validate_pool_note(
    note: PoolUtxo,
    address: &ShieldedAddress,
    context: &OutputContext,
) -> Option<DiscoveredPoolNote> {
    if note.booked > note.amount {
        return None;
    }
    let hash = note.output_utxo(address).ok()?.hash(context.tree_id).ok()?;
    if hash != context.hash {
        return None;
    }
    Some(DiscoveredPoolNote {
        utxo_hash: hash,
        amount: note.amount,
        blinding: note.blinding,
        booked: note.booked,
    })
}

/// Locate the confidential output slot addressed to the escrow_authority `tag`
/// whose committed leaf is `order_utxo_hash`, and decrypt it with the maker's
/// derived viewing key. The confidential-slot index (counted over data-bearing
/// slots, the same order the encrypter used; in a create_escrow transaction
/// every slot is data-bearing, so it equals the raw position) plus the
/// transaction's own `tx_viewing_pk`/`salt` form the `DecodeCx` the standard
/// confidential decode expects -- the same path a wallet scan uses.
fn decode_order_slot(
    tx: &ShieldedTransaction,
    tag: &[u8; 32],
    order_utxo_hash: &[u8; 32],
    viewing_key: &ViewingKey,
) -> Result<Option<ConfidentialOutputPlaintext>> {
    let mut slot_index = 0u32;
    for slot in &tx.output_slots {
        let Some(output_data) = slot.output_data() else {
            continue;
        };
        let this_index = slot_index;
        slot_index += 1;
        let OutputDataEncoding::Encrypted(blob) = output_data else {
            continue;
        };
        let Some((&scheme_byte, body)) = blob.split_first() else {
            continue;
        };
        if EncryptedScheme::from_byte(scheme_byte).ok() != Some(EncryptedScheme::Confidential) {
            continue;
        }
        if &slot.view_tag != tag || &slot.output_context.hash != order_utxo_hash {
            continue;
        }
        let cx = DecodeCx::for_slot(viewing_key, tx, this_index);
        let plaintext = Confidential::decode(body, &cx).map_err(err)?;
        return Ok(Some(plaintext));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_address::Address;
    use zolana_client::{
        rpc::IndexerRpcConfig, ClientError, Context, GetShieldedTransactionsByTagsResponse,
    };
    use zolana_transaction::{
        serialization::confidential::ConfidentialEncode, Data, DataRecord, OutputSlot,
    };

    struct Indexer {
        transactions: Vec<ShieldedTransaction>,
        fail_transactions: bool,
    }

    impl Rpc for Indexer {
        fn get_shielded_transactions_by_tags(
            &self,
            _: Vec<[u8; 32]>,
            _: Option<Vec<u8>>,
            _: Option<u32>,
            _: Option<IndexerRpcConfig>,
        ) -> std::result::Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            if self.fail_transactions {
                return Err(ClientError::Rpc("transaction indexer unavailable".into()));
            }
            Ok(GetShieldedTransactionsByTagsResponse {
                context: Context {
                    block_time: 0,
                    slot: 1,
                },
                output_tree_id: Some(1),
                transactions: self.transactions.clone(),
                next_cursor: None,
                scanned_through: None,
            })
        }
    }

    fn fixture() -> (ShieldedPda, PoolUtxo) {
        let owner =
            crate::state::pool_authority_identity(&Address::new_unique(), &ViewingKey::new())
                .unwrap();
        let note = PoolUtxo {
            asset: Mint::new(Address::new_unique(), 3),
            amount: 100,
            booked: 80,
            blinding: [3; 32],
        };
        (owner, note)
    }

    /// A slot carrying the pool note's commitment and a plaintext payload,
    /// which consumes a confidential slot index without decoding.
    fn pool_slot(owner: &ShieldedAddress, note: &PoolUtxo) -> OutputSlot {
        OutputSlot {
            view_tag: owner.confidential_view_tag().unwrap(),
            output_context: OutputContext {
                hash: note.output_utxo(owner).unwrap().hash(1).unwrap(),
                tree_id: 1,
                leaf_index: 0,
            },
            payload: borsh::to_vec(&OutputDataEncoding::Plaintext(vec![0])).unwrap(),
        }
    }

    #[test]
    fn invalid_encrypted_candidates_do_not_hide_later_valid_slots() {
        let (owner, note) = fixture();
        let address = owner.shielded_address().unwrap();
        let valid_slot = pool_slot(&address, &note);
        let tx_key = ViewingKey::new();
        let salt = [1; 16];
        let valid_plaintext = ConfidentialOutputPlaintext {
            asset_id: note.asset.asset_id,
            amount: note.amount,
            blinding: note.blinding,
            ring_program_id: None,
            data: Data::new(vec![DataRecord::UtxoData(crate::state::encode_pool_note(
                note.booked,
            ))]),
        };
        let mut variants = Vec::new();
        let mut missing = valid_plaintext.clone();
        missing.data = Data::default();
        variants.push(missing);
        let mut malformed = valid_plaintext.clone();
        malformed.data = Data::new(vec![DataRecord::UtxoData(vec![1; 7])]);
        variants.push(malformed);
        let mut wrong_asset = valid_plaintext.clone();
        wrong_asset.asset_id += 1;
        variants.push(wrong_asset);
        let mut wrong_preimage = valid_plaintext.clone();
        wrong_preimage.amount += 1;
        variants.push(wrong_preimage);
        let mut ring = valid_plaintext.clone();
        ring.ring_program_id = Some(Address::new_unique());
        variants.push(ring);
        let mut overbooked = valid_plaintext.clone();
        overbooked.amount = 1;
        variants.push(overbooked);
        variants.push(valid_plaintext);
        // A malformed encrypted slot and a plaintext slot both consume an index.
        let mut corrupt = valid_slot.clone();
        corrupt.payload = borsh::to_vec(&OutputDataEncoding::Encrypted(vec![
            EncryptedScheme::Confidential as u8,
            0,
        ]))
        .unwrap();
        let mut slots = vec![corrupt, valid_slot.clone()];
        for (offset, plaintext) in variants.into_iter().enumerate() {
            let cx = ConfidentialEncode {
                tx: tx_key.clone(),
                recipient_pubkey: address.viewing_pubkey,
                salt,
                slot_index: u32::try_from(offset + 2).unwrap(),
            };
            let mut blob = vec![EncryptedScheme::Confidential as u8];
            blob.extend(Confidential::encrypt(&plaintext.serialize().unwrap(), &cx).unwrap());
            let mut slot = valid_slot.clone();
            if plaintext.amount == 1 {
                // Correct commitment, invalid booked amount.
                slot.output_context.hash = PoolUtxo {
                    amount: 1,
                    ..note.clone()
                }
                .output_utxo(&address)
                .unwrap()
                .hash(1)
                .unwrap();
            }
            slot.payload = borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).unwrap();
            slots.push(slot);
        }
        let tx = ShieldedTransaction {
            slot: 1,
            tx_signature: Default::default(),
            event_index: None,
            tx_viewing_pk: Some(tx_key.pubkey()),
            salt: Some(salt),
            output_slots: slots,
            messages: vec![],
            nullifiers: vec![],
            proofless: false,
            ring_config: None,
            ring_program_id: None,
        };
        let mut missing_context = tx.clone();
        missing_context.salt = None;
        let indexer = Indexer {
            transactions: vec![missing_context, tx],
            fail_transactions: false,
        };
        let notes = discover_pool_notes(&indexer, &owner, note.asset).unwrap();
        assert_eq!(
            notes
                .iter()
                .map(|n| (n.utxo_hash, n.amount, n.blinding, n.booked))
                .collect::<Vec<_>>(),
            vec![(
                valid_slot.output_context.hash,
                note.amount,
                note.blinding,
                note.booked
            )]
        );
    }

    #[test]
    fn indexer_failures_remain_errors() {
        let (owner, note) = fixture();
        let indexer = Indexer {
            transactions: vec![],
            fail_transactions: true,
        };
        let error = discover_pool_notes(&indexer, &owner, note.asset)
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("transaction indexer unavailable"),
            "{error}"
        );
    }
}
