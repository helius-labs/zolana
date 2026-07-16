use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use borsh::BorshDeserialize;
use solana_address::Address;
use solana_pubkey::Pubkey;
use zolana_client::{resolve_registered_address, Rpc};
use zolana_keypair::{P256Pubkey, ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{
    serialization::confidential::Confidential, utxo::Blinding, DecodeCx, ShieldedTransaction,
    UtxoSerialization, Wallet,
};

use super::{
    poll::{collect_tagged, index_until},
    scan::{parse_order_data, resolve_mint, unified_slots},
};
use crate::{
    err,
    state::{OrderTerms, OrderUtxo, PlainTextData},
    MarkerData,
};

#[derive(Debug)]
pub struct TakerOrder {
    pub order_utxo: OrderUtxo,
    pub maker_pubkey: Pubkey,
}

pub struct TakerOrderCandidate {
    pub source_amount: u64,
    pub source_mint: Address,
    pub destination_mint: Address,
    pub order_utxo_blinding: Blinding,
    pub order_data: PlainTextData,
    pub maker_pubkey: Pubkey,
    pub order_utxo_hash: [u8; 32],
}

pub fn scan_taker(
    tx: &ShieldedTransaction,
    wallet: &Wallet,
    keypair: &ShieldedKeypair,
) -> Result<Option<TakerOrderCandidate>> {
    let taker_tag = wallet
        .identity
        .signing_pubkey
        .confidential_view_tag()
        .map_err(err)?;
    let Some(marker_message) = tx
        .messages
        .iter()
        .find(|message| message.view_tag == taker_tag)
    else {
        return Ok(None);
    };
    let marker = MarkerData::try_from_slice(&marker_message.data)
        .map_err(|e| anyhow!("marker payload: {e}"))?;
    let Some((slot_index, _, body)) =
        unified_slots(tx).find(|(_, slot, _)| slot.output_context.hash == marker.order_utxo_hash)
    else {
        bail!("marker without a unified order ciphertext in the same transaction");
    };
    let cx = DecodeCx::for_slot(&keypair.viewing_key, tx, slot_index);
    let order_utxo_plaintext = Confidential::decode(&body, &cx).map_err(err)?;
    let order_data = parse_order_data(&order_utxo_plaintext.data.records)?;
    Ok(Some(TakerOrderCandidate {
        source_amount: order_utxo_plaintext.amount,
        source_mint: resolve_mint(&wallet.registry, order_utxo_plaintext.asset_id)?,
        destination_mint: resolve_mint(&wallet.registry, order_data.destination_asset_id)?,
        order_utxo_blinding: order_utxo_plaintext.blinding,
        order_data,
        maker_pubkey: Pubkey::new_from_array(marker.maker_pubkey),
        order_utxo_hash: marker.order_utxo_hash,
    }))
}

impl TakerOrderCandidate {
    pub fn into_order(
        self,
        destination: ShieldedAddress,
        taker_viewing_pubkey: P256Pubkey,
    ) -> Result<TakerOrder> {
        let terms = OrderTerms {
            destination_mint: self.destination_mint,
            destination_amount: self.order_data.destination_amount,
            destination,
            taker: self.order_data.taker,
            expiry: self.order_data.expiry,
            take_mode: self.order_data.take_mode,
        };
        let order_utxo = OrderUtxo {
            terms,
            blinding: self.order_utxo_blinding,
            source_mint: self.source_mint,
            source_amount: self.source_amount,
            destination_asset_id: self.order_data.destination_asset_id,
        };
        let order_utxo_hash = order_utxo
            .output_utxo(taker_viewing_pubkey)?
            .hash()
            .map_err(err)?;
        if order_utxo_hash != self.order_utxo_hash {
            bail!("reconstructed order utxo hash does not match the committed leaf");
        }
        Ok(TakerOrder {
            order_utxo,
            maker_pubkey: self.maker_pubkey,
        })
    }
}

pub fn index_taker<I: Rpc, R: Rpc>(
    wallet: &mut Wallet,
    keypair: &ShieldedKeypair,
    indexer: &I,
    rpc: &R,
    timeout: Duration,
) -> Result<Vec<TakerOrder>> {
    index_until(
        wallet,
        keypair,
        indexer,
        timeout,
        "taker orders",
        |wallet| {
            let taker_viewing_pubkey = wallet.identity.viewing_pubkey;
            collect_tagged(wallet, indexer, |tx| {
                let Some(candidate) = scan_taker(tx, wallet, keypair)? else {
                    return Ok(None);
                };
                let maker_resolved_address =
                    resolve_registered_address(rpc, candidate.maker_pubkey).map_err(err)?;
                candidate
                    .into_order(maker_resolved_address.address, taker_viewing_pubkey)
                    .map(Some)
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use solana_keypair::Keypair;

    use super::*;
    use crate::index::fixture::order_fixture;

    #[test]
    fn scan_taker_reconstructs_terms_from_the_transaction() {
        let fixture = order_fixture();
        let candidate = scan_taker(&fixture.tx, &fixture.wallet, &fixture.taker_keypair)
            .expect("scan")
            .expect("order candidate");
        let order = candidate
            .into_order(
                fixture.maker_address,
                fixture.taker_keypair.viewing_pubkey(),
            )
            .expect("order");
        assert_eq!(
            (order.order_utxo, order.maker_pubkey),
            (fixture.order_utxo, fixture.maker_pubkey)
        );
    }

    #[test]
    fn into_order_rejects_a_wrong_maker_address() {
        let fixture = order_fixture();
        let candidate = scan_taker(&fixture.tx, &fixture.wallet, &fixture.taker_keypair)
            .expect("scan")
            .expect("order candidate");
        let taker_address = fixture
            .taker_keypair
            .shielded_address()
            .expect("taker address");
        let error = candidate
            .into_order(taker_address, fixture.taker_keypair.viewing_pubkey())
            .expect_err("wrong maker address must fail the hash check");
        assert!(error
            .to_string()
            .contains("does not match the committed leaf"));
    }

    #[test]
    fn scan_taker_ignores_transactions_for_other_takers() {
        let fixture = order_fixture();
        let other_keypair =
            ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([21u8; 32]))
                .expect("other keypair");
        let other_wallet = Wallet::new(
            other_keypair.shielded_address().expect("other address"),
            fixture.wallet.registry.clone(),
        )
        .expect("other wallet");
        assert!(scan_taker(&fixture.tx, &other_wallet, &other_keypair)
            .expect("scan")
            .is_none());
    }
}
