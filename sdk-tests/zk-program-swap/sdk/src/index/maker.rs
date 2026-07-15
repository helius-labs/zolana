use std::time::Duration;

use anyhow::Result;
use zolana_client::Rpc;
use zolana_keypair::{P256Pubkey, ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{
    serialization::confidential::{Confidential, ConfidentialOutputPlaintext},
    AssetRegistry, ShieldedTransaction, Wallet,
};

use super::{
    poll::{collect_tagged, index_until},
    scan::{parse_order_data, resolve_mint, unified_slots},
};
use crate::{
    err,
    state::{OrderTerms, OrderUtxo},
};

/// An order rediscovered by its maker from its own create transaction.
#[derive(Debug)]
pub struct MakerOrder {
    pub order_utxo: OrderUtxo,
    pub taker_viewing_pubkey: P256Pubkey,
}

/// Maker-side order rediscovery: the per-transaction viewing key re-derives
/// from the maker's viewing key and the first input's nullifier (a match against
/// `tx_viewing_pk` proves the maker authored the transaction). Each unified slot
/// embeds its recipient viewing pubkey, so that key decrypts every slot from
/// the sender side directly; the opening is accepted only if the reconstructed
/// order utxo hash matches the slot's committed leaf.
pub fn scan_maker(
    tx: &ShieldedTransaction,
    wallet: &Wallet,
    keypair: &ShieldedKeypair,
) -> Result<Option<MakerOrder>> {
    let (Some(tx_viewing_pk), Some(salt)) = (tx.tx_viewing_pk, tx.salt) else {
        return Ok(None);
    };
    let Some(tx_viewing_key) = tx.nullifiers.iter().find_map(|nullifier| {
        keypair
            .get_transaction_viewing_key(nullifier)
            .ok()
            .filter(|key| key.pubkey() == tx_viewing_pk)
    }) else {
        return Ok(None);
    };
    let maker_address = wallet.identity;
    for (slot_index, slot, body) in unified_slots(tx) {
        let Ok(taker_viewing_pubkey) = Confidential::embedded_viewing_pk(&body) else {
            continue;
        };
        let Ok(plaintext) =
            Confidential::decrypt_with_tx_key(&tx_viewing_key, &body, salt, slot_index)
        else {
            continue;
        };
        let Some(order) = maker_order_candidate(
            &wallet.registry,
            maker_address,
            plaintext,
            taker_viewing_pubkey,
        ) else {
            continue;
        };
        let Ok(order_utxo_hash) = order
            .order_utxo
            .output_utxo(taker_viewing_pubkey)
            .and_then(|output| output.hash().map_err(err))
        else {
            continue;
        };
        if order_utxo_hash != slot.output_context.hash {
            continue;
        }
        return Ok(Some(order));
    }
    Ok(None)
}

fn maker_order_candidate(
    registry: &AssetRegistry,
    maker_address: ShieldedAddress,
    plaintext: ConfidentialOutputPlaintext,
    taker_viewing_pubkey: P256Pubkey,
) -> Option<MakerOrder> {
    let order_data = parse_order_data(&plaintext.data.records).ok()?;
    let source_mint = resolve_mint(registry, plaintext.asset_id).ok()?;
    let destination_mint = resolve_mint(registry, order_data.destination_asset_id).ok()?;
    Some(MakerOrder {
        order_utxo: OrderUtxo {
            terms: OrderTerms {
                destination_mint,
                destination_amount: order_data.destination_amount,
                destination: maker_address,
                taker: order_data.taker,
                expiry: order_data.expiry,
                take_mode: order_data.take_mode,
            },
            blinding: plaintext.blinding,
            source_mint,
            source_amount: plaintext.amount,
            destination_asset_id: order_data.destination_asset_id,
        },
        taker_viewing_pubkey,
    })
}

pub fn index_maker<I: Rpc>(
    wallet: &mut Wallet,
    keypair: &ShieldedKeypair,
    indexer: &I,
    timeout: Duration,
) -> Result<Vec<MakerOrder>> {
    index_until(
        wallet,
        keypair,
        indexer,
        timeout,
        "maker orders",
        |wallet| collect_tagged(wallet, indexer, |tx| scan_maker(tx, wallet, keypair)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::fixture::order_fixture;

    #[test]
    fn scan_maker_reconstructs_the_opening_from_the_makers_side() {
        let fixture = order_fixture();
        let order = scan_maker(&fixture.tx, &fixture.maker_wallet, &fixture.maker_keypair)
            .expect("scan")
            .expect("own order");
        assert_eq!(
            (order.order_utxo, order.taker_viewing_pubkey),
            (fixture.order_utxo, fixture.taker_keypair.viewing_pubkey())
        );
    }

    #[test]
    fn scan_maker_ignores_transactions_of_other_makers() {
        let fixture = order_fixture();
        assert!(
            scan_maker(&fixture.tx, &fixture.wallet, &fixture.taker_keypair)
                .expect("scan")
                .is_none()
        );
    }
}
