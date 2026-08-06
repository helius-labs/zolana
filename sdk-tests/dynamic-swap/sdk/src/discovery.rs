use anyhow::{bail, Result};
use zolana_client::{IndexerRpcConfig, Rpc};
use zolana_interface::event::OutputDataEncoding;
use zolana_keypair::{ShieldedAddress, ViewingKey};
use zolana_transaction::{
    serialization::confidential::{Confidential, ConfidentialOutputPlaintext},
    DecodeCx, EncryptedScheme, ShieldedTransaction, UtxoSerialization,
};

use crate::{err, state::decode_order_note, state::EscrowTerms};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredOrder {
    pub order_utxo_hash: [u8; 32],
    pub plaintext: ConfidentialOutputPlaintext,
    pub terms: EscrowTerms,
}

/// Finds and decrypts an order addressed to the pair's escrow authority and
/// the maker's configured viewing key.
pub fn discover_order<I: Rpc>(
    indexer: &I,
    order_address: &ShieldedAddress,
    maker_viewing_key: &ViewingKey,
) -> Result<DiscoveredOrder> {
    let tag = order_address.confidential_view_tag().map_err(err)?;
    let mut cursor = None;
    loop {
        let page = indexer
            .get_shielded_transactions_by_tags(
                vec![tag],
                cursor,
                None,
                Some(IndexerRpcConfig::wait()),
            )
            .map_err(err)?;
        for tx in &page.transactions {
            if let Some((order_utxo_hash, plaintext)) =
                decrypt_matching_slot_for_recipient(tx, &tag, maker_viewing_key)?
            {
                let terms = decode_order_note(&plaintext.data)?;
                return Ok(DiscoveredOrder {
                    order_utxo_hash,
                    plaintext,
                    terms,
                });
            }
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => bail!("no order note found for maker viewing tag"),
        }
    }
}

/// Taker-side recovery of the exact same encrypted output. The caller retains
/// the transaction viewing key derived while constructing `create_escrow`.
pub fn decrypt_order_as_taker(
    tx: &ShieldedTransaction,
    tx_viewing_key: &ViewingKey,
    order_utxo_hash: &[u8; 32],
) -> Result<DiscoveredOrder> {
    let mut slot_index = 0u32;
    for slot in &tx.output_slots {
        let Some(output_data) = slot.output_data() else {
            continue;
        };
        let this_index = slot_index;
        slot_index += 1;
        if &slot.output_context.hash != order_utxo_hash {
            continue;
        }
        let OutputDataEncoding::Encrypted(blob) = output_data else {
            bail!("order output is not confidential");
        };
        let Some((&scheme, body)) = blob.split_first() else {
            bail!("order ciphertext is empty");
        };
        if EncryptedScheme::from_byte(scheme).map_err(err)? != EncryptedScheme::Confidential {
            bail!("order output uses a non-confidential encoding");
        }
        let salt = tx
            .salt
            .ok_or_else(|| err("order transaction is missing encryption salt"))?;
        let plaintext = Confidential::decrypt_with_tx_key(tx_viewing_key, body, salt, this_index)
            .map_err(err)?;
        let terms = decode_order_note(&plaintext.data)?;
        return Ok(DiscoveredOrder {
            order_utxo_hash: *order_utxo_hash,
            plaintext,
            terms,
        });
    }
    bail!("order output hash not found in transaction")
}

fn decrypt_matching_slot_for_recipient(
    tx: &ShieldedTransaction,
    tag: &[u8; 32],
    viewing_key: &ViewingKey,
) -> Result<Option<([u8; 32], ConfidentialOutputPlaintext)>> {
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
        let Some((&scheme, body)) = blob.split_first() else {
            continue;
        };
        if EncryptedScheme::from_byte(scheme).ok() != Some(EncryptedScheme::Confidential)
            || &slot.view_tag != tag
        {
            continue;
        }
        let plaintext =
            Confidential::decode(body, &DecodeCx::for_slot(viewing_key, tx, this_index))
                .map_err(err)?;
        return Ok(Some((slot.output_context.hash, plaintext)));
    }
    Ok(None)
}
