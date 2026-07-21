use anyhow::{bail, Result};
use zolana_client::{IndexerRpcConfig, Rpc};
use zolana_interface::event::OutputDataEncoding;
use zolana_keypair::ViewingKey;
use zolana_transaction::{
    serialization::confidential::{Confidential, ConfidentialOutputPlaintext},
    utxo::Blinding,
    DecodeCx, EncryptedScheme, ShieldedTransaction, UtxoSerialization,
};

use crate::{err, shared_address::SharedShieldedAddress, state::decode_escrow_note};

/// The escrow order + reservation UTXO state a settler recovers by scanning for
/// and decrypting the order UTXO's note -- no client-side tracking, and no
/// caller-supplied hash: `order_utxo_hash` is the committed leaf discovered by
/// the fetch. `recipient_owner_hash` is deliberately absent -- the settler
/// resolves it from the recipient's registered account and checks it against the
/// order UTXO's committed `data_hash`.
pub struct DiscoveredEscrow {
    pub order_utxo_hash: [u8; 32],
    pub order_amount: u64,
    pub order_blinding: Blinding,
    pub max_price: u64,
    pub reservation_blinding: Blinding,
}

/// Scans for the `create_escrow` transaction by the escrow_authority PDA's
/// public view tag and decrypts the order UTXO's note with the `owner`'s shared
/// viewing key, returning everything `settle` needs to rebuild both escrow UTXOs
/// (including the discovered order-UTXO leaf hash). Only the SPP `transact` query
/// and `Confidential::decode` do real work here; the rest is locating the order
/// slot by that view tag.
pub fn discover_escrow_note<I: Rpc>(
    indexer: &I,
    owner: &SharedShieldedAddress,
) -> Result<DiscoveredEscrow> {
    let tag = owner
        .shielded_address()?
        .confidential_view_tag()
        .map_err(err)?;
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
                decode_order_slot(tx, &tag, owner.viewing_key())?
            {
                let (max_price, reservation_blinding) = decode_escrow_note(&plaintext.data)?;
                return Ok(DiscoveredEscrow {
                    order_utxo_hash,
                    order_amount: plaintext.amount,
                    order_blinding: plaintext.blinding,
                    max_price,
                    reservation_blinding,
                });
            }
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => bail!("no escrow order note found for the escrow_authority view tag"),
        }
    }
}

/// Locate the confidential output slot addressed to the escrow_authority `tag`
/// (the reservation slot shares the tag but its ciphertext is dropped, so only
/// the order slot is data-bearing) and decrypt it with the shared viewing key,
/// returning its committed leaf hash and plaintext. The confidential-slot index
/// (counted over data-bearing slots, the same order the encrypter used) plus the
/// transaction's own `tx_viewing_pk`/`salt` form the `DecodeCx` the standard
/// confidential decode expects -- the same path a wallet scan uses.
fn decode_order_slot(
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
        let Some((&scheme_byte, body)) = blob.split_first() else {
            continue;
        };
        if EncryptedScheme::from_byte(scheme_byte).ok() != Some(EncryptedScheme::Confidential) {
            continue;
        }
        if &slot.view_tag != tag {
            continue;
        }
        let cx = DecodeCx::for_slot(viewing_key, tx, this_index);
        let plaintext = Confidential::decode(body, &cx).map_err(err)?;
        return Ok(Some((slot.output_context.hash, plaintext)));
    }
    Ok(None)
}
