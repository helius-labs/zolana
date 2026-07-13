use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use borsh::BorshDeserialize;
use solana_address::Address;
use solana_pubkey::Pubkey;
use zolana_client::{resolve_registered_address, sync_wallet, Rpc};
use zolana_interface::event::OutputData;
use zolana_keypair::{P256Pubkey, ShieldedAddress};
use zolana_transaction::{
    serialization::confidential::{
        ConfidentialRecipient, ConfidentialSenderBundle, TransferRecipientPlaintext,
        TransferSenderPlaintext,
    },
    utxo::Blinding,
    AssetRegistry, DataRecord, DecodeCx, EncryptedScheme, ShieldedTransaction, UtxoSerialization,
    Wallet, SOL_ASSET_ID, SOL_MINT,
};

use crate::{
    err,
    order::{marker_output_utxo, OrderTerms, OrderUtxo, PlainTextData},
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
    let taker_address = wallet.keypair.shielded_address().map_err(err)?;
    let marker_utxo_hash = marker_output_utxo(taker_address).hash().map_err(err)?;
    let Some(marker_slot) = tx
        .output_slots
        .iter()
        .find(|slot| slot.output_context.hash == marker_utxo_hash)
    else {
        return Ok(None);
    };
    let marker = MarkerData::try_from_slice(&marker_slot.payload)
        .map_err(|e| anyhow!("marker payload: {e}"))?;
    let Some((escrow_position, escrow_slot)) = tx
        .output_slots
        .iter()
        .enumerate()
        .find(|(_, slot)| slot.output_context.hash == marker.escrow_utxo_hash)
    else {
        bail!("marker without an escrow slot in the same transaction");
    };
    let Some(OutputData::Encrypted(blob)) = escrow_slot.output_data() else {
        bail!("escrow slot payload is not encrypted");
    };
    let (scheme_byte, body) = blob
        .split_first()
        .ok_or_else(|| anyhow!("empty escrow slot payload"))?;
    if EncryptedScheme::from_byte(*scheme_byte).map_err(err)?
        != EncryptedScheme::ConfidentialRecipient
    {
        bail!("escrow slot is not a recipient ciphertext");
    }
    let cx = DecodeCx::for_slot(
        &wallet.keypair.viewing_key,
        tx,
        encrypted_slot_index(tx, escrow_position),
    );
    let escrow_plaintext = ConfidentialRecipient::decode(body, &cx).map_err(err)?;
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

/// Maker-side order rediscovery, anchored at the maker's own change: the create
/// transaction carries her sender bundle, and the per-transaction viewing key
/// re-derives from her viewing key and the first input's nullifier (a match
/// against `tx_viewing_pk` proves she authored the transaction). That key
/// decrypts the taker-addressed escrow slot from the sender side, using the
/// taker viewing pubkey stored in the sender bundle; the opening is accepted
/// only if the reconstructed escrow utxo hash matches the slot's committed leaf.
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
    let Some(sender_plaintext) = decode_sender_bundle(tx, wallet) else {
        return Ok(None);
    };
    let maker_address = wallet.keypair.shielded_address().map_err(err)?;
    for (position, slot) in tx.output_slots.iter().enumerate() {
        let Some(OutputData::Encrypted(blob)) = slot.output_data() else {
            continue;
        };
        let Some((scheme_byte, body)) = blob.split_first() else {
            continue;
        };
        if EncryptedScheme::from_byte(*scheme_byte).ok()
            != Some(EncryptedScheme::ConfidentialRecipient)
        {
            continue;
        }
        let slot_index = encrypted_slot_index(tx, position);
        for taker_viewing_pk in &sender_plaintext.recipient_viewing_pks {
            let Ok(bytes) = tx_key.decrypt_slot_ephemeral(taker_viewing_pk, body, salt, slot_index)
            else {
                continue;
            };
            let Ok(plaintext) = TransferRecipientPlaintext::deserialize(&bytes) else {
                continue;
            };
            let Some(order) = own_order_candidate(
                &wallet.registry,
                maker_address,
                plaintext,
                *taker_viewing_pk,
            ) else {
                continue;
            };
            let Ok(escrow_utxo_hash) = order
                .escrow
                .output_utxo(*taker_viewing_pk)
                .and_then(|output| output.hash().map_err(err))
            else {
                continue;
            };
            if escrow_utxo_hash != slot.output_context.hash {
                continue;
            }
            return Ok(Some(order));
        }
    }
    Ok(None)
}

fn decode_sender_bundle(
    tx: &ShieldedTransaction,
    wallet: &Wallet,
) -> Option<TransferSenderPlaintext> {
    for (position, slot) in tx.output_slots.iter().enumerate() {
        let Some(OutputData::Encrypted(blob)) = slot.output_data() else {
            continue;
        };
        let Some((scheme_byte, body)) = blob.split_first() else {
            continue;
        };
        if EncryptedScheme::from_byte(*scheme_byte).ok()
            != Some(EncryptedScheme::ConfidentialSender)
        {
            continue;
        }
        let cx = DecodeCx::for_slot(
            &wallet.keypair.viewing_key,
            tx,
            encrypted_slot_index(tx, position),
        );
        if let Ok(plaintext) = ConfidentialSenderBundle::decode(body, &cx) {
            return Some(plaintext);
        }
    }
    None
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
    use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypair};
    use zolana_transaction::{
        derive_blinding,
        instructions::{
            transact::{
                OutputContext, OutputSlot, OutputUtxo, RecipientSlot, SenderSlot,
                SignedTransaction, Transaction,
            },
            types::SpendUtxo,
        },
        serialization::confidential::TransferSenderPlaintext,
        utxo::Utxo,
        Data,
    };

    use super::*;
    use crate::instructions::create_swap::{input_sum, MarkerEncrypt, CHANGE_POSITION};

    struct OrderFixture {
        tx: ShieldedTransaction,
        wallet: Wallet,
        maker_wallet: Wallet,
        escrow: OrderUtxo,
        maker_address: ShieldedAddress,
        maker_pubkey: Pubkey,
    }

    fn shielded_transaction(signed: &SignedTransaction) -> ShieldedTransaction {
        let external = &signed.external_data;
        let output_slots = external
            .output_utxo_hashes
            .iter()
            .zip(external.output_ciphertexts.iter())
            .enumerate()
            .map(|(index, (utxo_hash, ciphertext))| OutputSlot {
                view_tag: ciphertext.view_tag,
                output_context: OutputContext {
                    hash: *utxo_hash,
                    tree: Address::default(),
                    leaf_index: index as u64,
                },
                payload: ciphertext.data.clone(),
            })
            .collect();
        let nullifiers = signed
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
        let marker = marker_output_utxo(taker_address);
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
        let spend = SpendUtxo::from_keypair(input_utxo, &maker_keypair);
        let mut tx = Transaction::new(maker_address, vec![spend], Address::default());

        let escrow_address = escrow_output.owner_address.expect("escrow address");
        let escrow_utxo_hash = escrow_output.hash().expect("escrow output hash");
        let change_amount =
            u64::try_from(input_sum(&tx.inputs, &source_mint) - i128::from(escrow_output.amount))
                .expect("change amount");
        let sender_slot = SenderSlot {
            plaintext: TransferSenderPlaintext {
                owner_pubkey: tx.owner.signing_pubkey,
                spl_asset_id: registry.asset_id(&source_mint).expect("asset id"),
                spl_amount: change_amount,
                sol_amount: 0,
                blinding_seed: tx.blinding_seed,
                recipient_viewing_pks: vec![escrow_address.viewing_pubkey],
                spl_data: Data::default(),
                sol_data: Data::default(),
            },
            output: OutputUtxo {
                owner_address: Some(tx.owner),
                asset: source_mint,
                amount: change_amount,
                blinding: derive_blinding(&tx.blinding_seed, CHANGE_POSITION),
                ..Default::default()
            },
        };
        let escrow_slot = RecipientSlot::new(escrow_output, &registry).expect("escrow slot");
        let marker_slot = MarkerEncrypt {
            marker,
            escrow_utxo_hash,
            payer: maker_pubkey,
        }
        .encrypt()
        .expect("marker slot");
        tx.inputs.push(SpendUtxo::new_dummy());
        let signed = tx
            .sign_with_slots(&[&sender_slot, &escrow_slot, &marker_slot], &maker_keypair)
            .expect("escrow create sign");

        OrderFixture {
            tx: shielded_transaction(&signed),
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
