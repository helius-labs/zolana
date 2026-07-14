use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use borsh::BorshDeserialize;
use solana_address::Address;
use solana_pubkey::Pubkey;
use zolana_client::{resolve_registered_address, sync_wallet, Rpc};
use zolana_interface::event::OutputDataEncoding;
use zolana_keypair::{P256Pubkey, ShieldedAddress};
use zolana_transaction::{
    serialization::{
        confidential::TransferRecipientPlaintext, confidential_unified::ConfidentialUnified,
    },
    utxo::Blinding,
    AssetRegistry, DataRecord, DecodeCx, EncryptedScheme, ShieldedTransaction, UtxoSerialization,
    Wallet, SOL_ASSET_ID, SOL_MINT,
};

use crate::{
    err,
    order::{OrderTerms, OrderUtxo, PlainTextData},
    MarkerData,
};

#[derive(Debug)]
pub struct DiscoveredOrder {
    pub escrow: OrderUtxo,
    pub maker_pubkey: Pubkey,
}

pub struct OrderCandidate {
    pub source_amount: u64,
    pub source_mint: Address,
    pub destination_mint: Address,
    pub escrow_blinding: Blinding,
    pub order_data: PlainTextData,
    pub maker_pubkey: Pubkey,
    pub escrow_utxo_hash: [u8; 32],
}

fn resolve_mint(registry: &AssetRegistry, asset_id: u64) -> Result<Address> {
    if asset_id == SOL_ASSET_ID {
        return Ok(SOL_MINT);
    }
    registry.resolve(asset_id).map_err(err)
}

/// Decryption slot index of the output slot at `position`: ciphertext slots are
/// indexed over data-bearing slots only.
fn encrypted_slot_index(tx: &ShieldedTransaction, position: usize) -> u32 {
    tx.output_slots
        .iter()
        .take(position + 1)
        .filter(|slot| slot.output_data().is_some())
        .count()
        .saturating_sub(1) as u32
}

pub fn scan_order(tx: &ShieldedTransaction, wallet: &Wallet) -> Result<Option<OrderCandidate>> {
    let taker_tag = wallet
        .keypair
        .signing_pubkey()
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
    let Some((escrow_position, escrow_slot)) = tx
        .output_slots
        .iter()
        .enumerate()
        .find(|(_, slot)| slot.output_context.hash == marker.escrow_utxo_hash)
    else {
        bail!("marker without an escrow slot in the same transaction");
    };
    let Some(OutputDataEncoding::Encrypted(blob)) = escrow_slot.output_data() else {
        bail!("escrow slot payload is not encrypted");
    };
    let (scheme_byte, body) = blob
        .split_first()
        .ok_or_else(|| anyhow!("empty escrow slot payload"))?;
    if EncryptedScheme::from_byte(*scheme_byte).map_err(err)?
        != EncryptedScheme::ConfidentialUnified
    {
        bail!("escrow slot is not a unified confidential ciphertext");
    }
    let cx = DecodeCx::for_slot(
        &wallet.keypair.viewing_key,
        tx,
        encrypted_slot_index(tx, escrow_position),
    );
    let escrow_plaintext = ConfidentialUnified::decode(body, &cx).map_err(err)?;
    let order_bytes = escrow_plaintext
        .data
        .records
        .iter()
        .find_map(|record| match record {
            DataRecord::UtxoData(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("escrow plaintext carries no utxo data record"))?;
    let order_data = PlainTextData::deserialize(order_bytes)?;
    Ok(Some(OrderCandidate {
        source_amount: escrow_plaintext.amount,
        source_mint: resolve_mint(&wallet.registry, escrow_plaintext.asset_id)?,
        destination_mint: resolve_mint(&wallet.registry, order_data.destination_asset_id)?,
        escrow_blinding: escrow_plaintext.blinding,
        order_data,
        maker_pubkey: Pubkey::new_from_array(marker.maker_pubkey),
        escrow_utxo_hash: marker.escrow_utxo_hash,
    }))
}

impl OrderCandidate {
    pub fn into_order(
        self,
        destination: ShieldedAddress,
        taker_viewing_pubkey: P256Pubkey,
    ) -> Result<DiscoveredOrder> {
        let terms = OrderTerms {
            destination_mint: self.destination_mint,
            destination_amount: self.order_data.destination_amount,
            destination,
            taker: self.order_data.taker,
            expiry: self.order_data.expiry,
            fill_mode: self.order_data.fill_mode,
        };
        let escrow = OrderUtxo {
            terms,
            blinding: self.escrow_blinding,
            source_mint: self.source_mint,
            source_amount: self.source_amount,
            destination_asset_id: self.order_data.destination_asset_id,
        };
        let escrow_utxo_hash = escrow
            .output_utxo(taker_viewing_pubkey)?
            .hash()
            .map_err(err)?;
        if escrow_utxo_hash != self.escrow_utxo_hash {
            bail!("reconstructed escrow utxo hash does not match the committed leaf");
        }
        Ok(DiscoveredOrder {
            escrow,
            maker_pubkey: self.maker_pubkey,
        })
    }
}

const DISCOVER_POLL: Duration = Duration::from_millis(500);

pub fn discover_orders<I: Rpc, R: Rpc>(
    wallet: &mut Wallet,
    indexer: &I,
    rpc: &R,
    timeout: Duration,
) -> Result<Vec<DiscoveredOrder>> {
    let deadline = Instant::now() + timeout;
    loop {
        sync_wallet(wallet, indexer).map_err(err)?;
        let orders = collect_orders(wallet, indexer, rpc)?;
        if !orders.is_empty() {
            return Ok(orders);
        }
        if Instant::now() >= deadline {
            bail!("timed out discovering orders");
        }
        std::thread::sleep(DISCOVER_POLL);
    }
}

fn collect_orders<I: Rpc, R: Rpc>(
    wallet: &Wallet,
    indexer: &I,
    rpc: &R,
) -> Result<Vec<DiscoveredOrder>> {
    let owner_tag = wallet
        .keypair
        .signing_pubkey()
        .confidential_view_tag()
        .map_err(err)?;
    let taker_viewing_pubkey = wallet.keypair.viewing_pubkey();
    let mut orders = Vec::new();
    let mut cursor = None;
    loop {
        let page = indexer
            .get_shielded_transactions_by_tags(vec![owner_tag], cursor, None)
            .map_err(err)?;
        for tx in &page.transactions {
            let Some(candidate) = scan_order(tx, wallet)? else {
                continue;
            };
            let maker = resolve_registered_address(rpc, candidate.maker_pubkey).map_err(err)?;
            orders.push(candidate.into_order(maker.address, taker_viewing_pubkey)?);
        }
        let Some(next) = page.next_cursor else {
            return Ok(orders);
        };
        cursor = Some(next);
    }
}

/// An order rediscovered by its maker from her own create transaction.
#[derive(Debug)]
pub struct OwnOrder {
    pub escrow: OrderUtxo,
    pub taker_viewing_pk: P256Pubkey,
}

/// Maker-side order rediscovery: the per-transaction viewing key re-derives
/// from her viewing key and the first input's nullifier (a match against
/// `tx_viewing_pk` proves she authored the transaction). Each unified slot
/// embeds its recipient viewing pubkey, so that key decrypts every slot from
/// the sender side directly; the opening is accepted only if the reconstructed
/// escrow utxo hash matches the slot's committed leaf.
pub fn scan_own_order(tx: &ShieldedTransaction, wallet: &Wallet) -> Result<Option<OwnOrder>> {
    let (Some(tx_viewing_pk), Some(salt)) = (tx.tx_viewing_pk, tx.salt) else {
        return Ok(None);
    };
    let Some(tx_key) = tx.nullifiers.iter().find_map(|nullifier| {
        wallet
            .keypair
            .get_transaction_viewing_key(nullifier)
            .ok()
            .filter(|key| key.pubkey() == tx_viewing_pk)
    }) else {
        return Ok(None);
    };
    let maker_address = wallet.keypair.shielded_address().map_err(err)?;
    for (position, slot) in tx.output_slots.iter().enumerate() {
        let Some(OutputDataEncoding::Encrypted(blob)) = slot.output_data() else {
            continue;
        };
        let Some((scheme_byte, body)) = blob.split_first() else {
            continue;
        };
        if EncryptedScheme::from_byte(*scheme_byte).ok()
            != Some(EncryptedScheme::ConfidentialUnified)
        {
            continue;
        }
        let Ok(taker_viewing_pk) = ConfidentialUnified::embedded_viewing_pk(body) else {
            continue;
        };
        let slot_index = encrypted_slot_index(tx, position);
        let Ok(plaintext) =
            ConfidentialUnified::decrypt_with_tx_key(&tx_key, body, salt, slot_index)
        else {
            continue;
        };
        let Some(order) =
            own_order_candidate(&wallet.registry, maker_address, plaintext, taker_viewing_pk)
        else {
            continue;
        };
        let Ok(escrow_utxo_hash) = order
            .escrow
            .output_utxo(taker_viewing_pk)
            .and_then(|output| output.hash().map_err(err))
        else {
            continue;
        };
        if escrow_utxo_hash != slot.output_context.hash {
            continue;
        }
        return Ok(Some(order));
    }
    Ok(None)
}

fn own_order_candidate(
    registry: &AssetRegistry,
    maker_address: ShieldedAddress,
    plaintext: TransferRecipientPlaintext,
    taker_viewing_pk: P256Pubkey,
) -> Option<OwnOrder> {
    let order_bytes = plaintext
        .data
        .records
        .iter()
        .find_map(|record| match record {
            DataRecord::UtxoData(bytes) => Some(bytes.as_slice()),
            _ => None,
        })?;
    let order_data = PlainTextData::deserialize(order_bytes).ok()?;
    let source_mint = resolve_mint(registry, plaintext.asset_id).ok()?;
    let destination_mint = resolve_mint(registry, order_data.destination_asset_id).ok()?;
    Some(OwnOrder {
        escrow: OrderUtxo {
            terms: OrderTerms {
                destination_mint,
                destination_amount: order_data.destination_amount,
                destination: maker_address,
                taker: order_data.taker,
                expiry: order_data.expiry,
                fill_mode: order_data.fill_mode,
            },
            blinding: plaintext.blinding,
            source_mint,
            source_amount: plaintext.amount,
            destination_asset_id: order_data.destination_asset_id,
        },
        taker_viewing_pk,
    })
}

pub fn discover_own_orders<I: Rpc>(
    wallet: &mut Wallet,
    indexer: &I,
    timeout: Duration,
) -> Result<Vec<OwnOrder>> {
    let deadline = Instant::now() + timeout;
    loop {
        sync_wallet(wallet, indexer).map_err(err)?;
        let orders = collect_own_orders(wallet, indexer)?;
        if !orders.is_empty() {
            return Ok(orders);
        }
        if Instant::now() >= deadline {
            bail!("timed out discovering own orders");
        }
        std::thread::sleep(DISCOVER_POLL);
    }
}

fn collect_own_orders<I: Rpc>(wallet: &Wallet, indexer: &I) -> Result<Vec<OwnOrder>> {
    let owner_tag = wallet
        .keypair
        .signing_pubkey()
        .confidential_view_tag()
        .map_err(err)?;
    let mut orders = Vec::new();
    let mut cursor = None;
    loop {
        let page = indexer
            .get_shielded_transactions_by_tags(vec![owner_tag], cursor, None)
            .map_err(err)?;
        for tx in &page.transactions {
            if let Some(order) = scan_own_order(tx, wallet)? {
                orders.push(order);
            }
        }
        let Some(next) = page.next_cursor else {
            return Ok(orders);
        };
        cursor = Some(next);
    }
}

#[cfg(test)]
mod tests {
    use solana_signature::Signature;
    use swap_prover::FILL_MODE_DERIVED;
    use zolana_keypair::{constants::BLINDING_LEN, hash::sha256_be, ShieldedKeypair};
    use zolana_transaction::{
        instructions::{
            transact::{
                encode_slots, get_transaction_viewing_key, ConfidentialSlot, ExternalData,
                OutputContext, OutputSlot, OutputUtxo, PublicAmounts, Shape, SppProofInputs,
            },
            types::SppProofInputUtxo,
        },
        utxo::Utxo,
        Data,
    };

    use super::*;
    use crate::instructions::create_swap::{input_sum, OrderMarker};

    struct OrderFixture {
        tx: ShieldedTransaction,
        wallet: Wallet,
        maker_wallet: Wallet,
        escrow: OrderUtxo,
        maker_address: ShieldedAddress,
        maker_pubkey: Pubkey,
    }

    fn shielded_transaction(proof_inputs: &SppProofInputs) -> ShieldedTransaction {
        let external = &proof_inputs.external_data;
        let output_slots = external
            .outputs
            .iter()
            .zip(external.resolved_owner_tags.iter())
            .enumerate()
            .map(|(index, (output, view_tag))| OutputSlot {
                view_tag: *view_tag,
                output_context: OutputContext {
                    hash: output.utxo_hash,
                    tree: Address::default(),
                    leaf_index: index as u64,
                },
                payload: output.data.clone().unwrap_or_default(),
            })
            .collect();
        let nullifiers = proof_inputs
            .input_utxo_hashes()
            .expect("input commitments")
            .iter()
            .map(|commitment| commitment.nullifier)
            .collect();
        ShieldedTransaction {
            slot: 0,
            tx_signature: Signature::default(),
            tx_viewing_pk: P256Pubkey::from_bytes(external.tx_viewing_pk).ok(),
            salt: Some(external.salt),
            output_slots,
            messages: external.messages.clone(),
            nullifiers,
            proofless: false,
        }
    }

    fn order_fixture() -> OrderFixture {
        let maker_keypair = ShieldedKeypair::from_seed_ed25519(&[7u8; 32]).expect("maker keypair");
        let taker_keypair = ShieldedKeypair::from_seed_ed25519(&[13u8; 32]).expect("taker keypair");
        let maker_address = maker_keypair.shielded_address().expect("maker address");
        let taker_address = taker_keypair.shielded_address().expect("taker address");
        let source_mint = Address::new_from_array([9u8; 32]);
        let mut registry = AssetRegistry::default();
        registry.insert(2, source_mint).expect("register mint");

        let terms = OrderTerms {
            destination_mint: SOL_MINT,
            destination_amount: 250_000,
            destination: maker_address,
            taker: taker_address
                .solana_address()
                .expect("taker solana address"),
            expiry: 2_000_000_000,
            fill_mode: FILL_MODE_DERIVED,
        };
        let escrow = OrderUtxo {
            terms,
            blinding: [11u8; BLINDING_LEN],
            source_mint,
            source_amount: 400_000,
            destination_asset_id: SOL_ASSET_ID,
        };
        let escrow_output = escrow
            .output_utxo(taker_address.viewing_pubkey)
            .expect("escrow output");
        let maker_pubkey = Pubkey::new_from_array(
            *maker_address
                .solana_address()
                .expect("maker solana address")
                .as_array(),
        );

        let input_utxo = Utxo {
            owner: maker_keypair.signing_pubkey(),
            asset: source_mint,
            amount: 1_000_000,
            blinding: [5u8; BLINDING_LEN],
            zone_program_id: None,
            data: Data::default(),
        };
        let spend = SppProofInputUtxo::new(input_utxo, &maker_keypair);
        let input_utxos = vec![spend, SppProofInputUtxo::new_dummy()];

        let escrow_utxo_hash = escrow_output.hash().expect("escrow output hash");
        let change_amount =
            u64::try_from(input_sum(&input_utxos, &source_mint) - i128::from(escrow_output.amount))
                .expect("change amount");
        let change_slot = ConfidentialSlot::new(
            OutputUtxo {
                owner_address: Some(maker_address),
                asset: source_mint,
                amount: change_amount,
                blinding: [21u8; BLINDING_LEN],
                ..Default::default()
            },
            &registry,
        )
        .expect("change slot");
        let escrow_slot = ConfidentialSlot::new(escrow_output, &registry).expect("escrow slot");
        let marker_message = OrderMarker {
            escrow_utxo_hash,
            maker_pubkey,
            taker_address,
        }
        .message()
        .expect("marker message");
        let tx = get_transaction_viewing_key(&maker_keypair, &input_utxos)
            .expect("transaction viewing key");

        let encoded = encode_slots(&[change_slot, escrow_slot], &tx).expect("encode slots");

        let external_data = ExternalData::new(
            *tx.pubkey().as_bytes(),
            encoded.salt,
            encoded.outputs,
            encoded.resolved_owner_tags,
            vec![marker_message],
            u64::MAX,
        );
        let spp_proof_inputs = SppProofInputs {
            input_utxos,
            output_utxos: encoded.output_utxos,
            public_amounts: PublicAmounts::ZERO,
            external_data,
            payer_pubkey_hash: sha256_be(Address::default().as_array()),
            shape: Shape::IN2_OUT2,
            p256_signature: None,
        };

        OrderFixture {
            tx: shielded_transaction(&spp_proof_inputs),
            wallet: Wallet::new(taker_keypair, registry.clone()).expect("taker wallet"),
            maker_wallet: Wallet::new(maker_keypair, registry).expect("maker wallet"),
            escrow,
            maker_address,
            maker_pubkey,
        }
    }

    #[test]
    fn scan_order_reconstructs_terms_from_the_transaction() {
        let fixture = order_fixture();
        let candidate = scan_order(&fixture.tx, &fixture.wallet)
            .expect("scan")
            .expect("order candidate");
        let order = candidate
            .into_order(
                fixture.maker_address,
                fixture.wallet.keypair.viewing_pubkey(),
            )
            .expect("order");
        assert_eq!(
            (order.escrow, order.maker_pubkey),
            (fixture.escrow, fixture.maker_pubkey)
        );
    }

    #[test]
    fn into_order_rejects_a_wrong_maker_address() {
        let fixture = order_fixture();
        let candidate = scan_order(&fixture.tx, &fixture.wallet)
            .expect("scan")
            .expect("order candidate");
        let taker_address = fixture
            .wallet
            .keypair
            .shielded_address()
            .expect("taker address");
        let error = candidate
            .into_order(taker_address, fixture.wallet.keypair.viewing_pubkey())
            .expect_err("wrong maker address must fail the hash check");
        assert!(error
            .to_string()
            .contains("does not match the committed leaf"));
    }

    #[test]
    fn scan_own_order_reconstructs_the_opening_from_the_makers_side() {
        let fixture = order_fixture();
        let order = scan_own_order(&fixture.tx, &fixture.maker_wallet)
            .expect("scan")
            .expect("own order");
        assert_eq!(
            (order.escrow, order.taker_viewing_pk),
            (fixture.escrow, fixture.wallet.keypair.viewing_pubkey())
        );
    }

    #[test]
    fn scan_own_order_ignores_transactions_of_other_makers() {
        let fixture = order_fixture();
        assert!(scan_own_order(&fixture.tx, &fixture.wallet)
            .expect("scan")
            .is_none());
    }

    #[test]
    fn scan_order_ignores_transactions_for_other_takers() {
        let fixture = order_fixture();
        let other_keypair = ShieldedKeypair::from_seed_ed25519(&[21u8; 32]).expect("other keypair");
        let other_wallet =
            Wallet::new(other_keypair, fixture.wallet.registry.clone()).expect("other wallet");
        assert!(scan_order(&fixture.tx, &other_wallet)
            .expect("scan")
            .is_none());
    }
}
