use anyhow::{bail, Result};
use borsh::BorshDeserialize;
use zolana_client::Rpc;
use zolana_event::ProoflessOutput;
use zolana_interface::event::OutputDataEncoding;
use zolana_keypair::{ShieldedPda, ViewingKey};
use zolana_transaction::{
    serialization::confidential::{Confidential, ConfidentialOutputPlaintext},
    utxo::Blinding,
    Data, DataRecord, DecodeCx, EncryptedScheme, ShieldedTransaction, UtxoSerialization,
};

use crate::{
    err,
    state::{decode_order_note, decode_pool_note},
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
/// public deposit notes (proofless payloads, readable without a key, served
/// by the per-slot ciphertext query -- the same stream a wallet sync reads
/// deposits from) and confidential change notes from settle/rebalance
/// (decrypted with the maker's pool-role viewing key, see
/// `state::pool_authority_identity`, served by the transactions query).
pub fn discover_pool_notes<I: Rpc>(
    indexer: &I,
    owner: &ShieldedPda,
) -> Result<Vec<DiscoveredPoolNote>> {
    let tag = owner
        .shielded_address()?
        .confidential_view_tag()
        .map_err(err)?;
    let mut notes = Vec::new();

    // Proofless deposits: per-slot matches with no encryption context.
    let mut cursor = None;
    loop {
        let page = indexer
            .get_encrypted_utxos_by_tags(vec![tag], cursor, None, None)
            .map_err(err)?;
        for item in &page.matches {
            if item.tx_viewing_pk.is_some() || item.salt.is_some() {
                continue;
            }
            let Some(output_data) = item.output_slot.output_data() else {
                continue;
            };
            // Proofless deposit outputs are framed as a Plaintext payload with
            // the Proofless scheme byte inside (see the event crate's
            // `decode_output_data`).
            let OutputDataEncoding::Plaintext(blob) = output_data else {
                continue;
            };
            let Some((&scheme_byte, body)) = blob.split_first() else {
                continue;
            };
            if EncryptedScheme::from_byte(scheme_byte).ok() != Some(EncryptedScheme::Proofless) {
                continue;
            }
            let output = ProoflessOutput::try_from_slice(body).map_err(err)?;
            let utxo_data = output
                .utxo_data
                .ok_or_else(|| err("pool deposit note carries no utxo data"))?;
            let booked = decode_pool_note(&Data::new(vec![DataRecord::UtxoData(utxo_data)]))?;
            notes.push(DiscoveredPoolNote {
                utxo_hash: item.output_slot.output_context.hash,
                amount: output.amount,
                blinding: output.blinding,
                booked,
            });
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    // Confidential change notes from settle/rebalance transactions.
    let mut cursor = None;
    loop {
        let page = indexer
            .get_shielded_transactions_by_tags(vec![tag], cursor, None, None)
            .map_err(err)?;
        for tx in &page.transactions {
            decode_pool_slots(tx, &tag, owner.viewing_key(), &mut notes)?;
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
    notes: &mut Vec<DiscoveredPoolNote>,
) -> Result<()> {
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
        let plaintext = Confidential::decode(body, &cx).map_err(err)?;
        let booked = decode_pool_note(&plaintext.data)?;
        notes.push(DiscoveredPoolNote {
            utxo_hash: slot.output_context.hash,
            amount: plaintext.amount,
            blinding: plaintext.blinding,
            booked,
        });
    }
    Ok(())
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
