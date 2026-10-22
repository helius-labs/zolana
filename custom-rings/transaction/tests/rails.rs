//! The ring output rails, read back as a recipient and the ring program read them.

use custom_ring_interface::{
    stream::{DeliveredSlot, PackedSlot, RingSecret, RingTag, SlotSecret, TagIndex, TAG_LEN},
    RingOutput,
};
use solana_address::Address;
use solana_signature::Signature;
use zolana_event::{ring_confidential_packed_output_body, RingPackedBody};
use zolana_instruction::RingOutputBlinding;
use zolana_interface::instruction::instruction_data::transact::OwnerTag;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey};
use zolana_ring_transaction::{
    AnonymousSlot, AnonymousSlots, RingDelivery, RingOutputRail, StreamPayment, StreamPosition,
};
use zolana_transaction::{
    instructions::transact::{ConfidentialTransaction, Shape, SppProofInputs, SppProofOutputUtxo},
    serialization::{
        DecodeCx, RingDeliveredUtxo, RingDeliveryOpening, RingDeliverySlot, RingPacked,
        RingUtxoOwner, UtxoSerialization,
    },
    Data, Mint, TransactionError as E, Utxo, WalletUtxo,
};

const RING: Address = Address::new_from_array([42; 32]);
const TREE: u16 = 7;

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

fn address(owner: &ShieldedKeypair) -> ShieldedAddress {
    owner.shielded_address().unwrap()
}

fn ring_address(owner: &ShieldedKeypair) -> (ShieldedAddress, ViewingKey) {
    let key = owner.viewing_key.ring_address_key(&RING, 0).unwrap();
    let recipient = ShieldedAddress {
        viewing_pubkey: key.pubkey(),
        ..address(owner)
    };
    (recipient, key)
}

fn ring_transfer(owner: &ShieldedKeypair, compact: bool) -> (ConfidentialTransaction, ViewingKey) {
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: Mint::SOL,
        amount: 10,
        blinding: [3; 32],
        ring_program_id: Some(RING),
        data: Data::default(),
    };
    let nullifier_pubkey = address(owner).nullifier_pubkey;
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &[0; 32], &[0; 32], TREE)
        .unwrap();
    let nullifier = owner.nullifier(&utxo_hash, &utxo.blinding).unwrap();
    let input = WalletUtxo {
        nullifier,
        utxo,
        nullifier_pubkey,
        utxo_hash,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: None,
        tree_id: TREE,
        leaf_index: 1,
        latest_tree_id: None,
        slot: 1,
        tx_signature: Signature::from([1; 64]),
        slot_index: 0,
    };
    let tx_key = owner
        .viewing_key
        .get_transaction_viewing_key(&nullifier)
        .unwrap();
    let payer = address(owner).solana_address().unwrap();
    let transaction = match compact {
        true => ConfidentialTransaction::new_compact_with_ring(vec![input], payer, RING),
        false => ConfidentialTransaction::new_with_ring(vec![input], payer, RING),
    }
    .unwrap()
    .with_output_tree_id(TREE)
    .unwrap();
    (transaction, tx_key)
}

fn delivered_secret(
    reader: &ViewingKey,
    proof: &SppProofInputs,
    rail: &RingOutputRail,
    index: u32,
) -> SlotSecret {
    let tx_pk = rail.tx_viewing_key().pubkey();
    DeliveredSlot {
        agreement: &reader.ecdh(&tx_pk).unwrap(),
        tx_viewing_pk: tx_pk.as_bytes(),
        recipient_viewing_pk: reader.pubkey().as_bytes(),
        salt: &rail.salt(),
        output_index: index,
        first_nullifier: &proof.input_utxos[0].nullifier(),
    }
    .secret()
    .unwrap()
}

/// The UTXO a delivered body opens to under `secret`, `None` for another key's body.
fn open(
    proof: &SppProofInputs,
    wire: RingOutput<'_>,
    owner: &ShieldedAddress,
    secret: &SlotSecret,
    index: u32,
) -> Option<RingDeliveredUtxo> {
    let (tag, body) = match wire {
        RingOutput::Delivered { body, .. } => (None, body),
        RingOutput::Anonymous { tag, body, .. } => (Some(tag), body),
        _ => panic!("delivered slot expected"),
    };
    RingDeliverySlot {
        ring: RING,
        first_nullifier: proof.input_utxos[0].nullifier(),
        output_index: index,
        tag,
    }
    .open(RingDeliveryOpening {
        body,
        slot_secret: secret,
        owner: RingUtxoOwner {
            signing_pubkey: &owner.signing_pubkey,
            nullifier_pubkey: &owner.nullifier_pubkey,
        },
        commitment: wire.hash(),
        tree_id: TREE,
    })
    .unwrap()
}

#[test]
fn a_packed_ring_output_blinds_under_the_cras_secret_and_opens_for_its_owner_key() {
    let sender = keypair(1);
    let receiver = keypair(2);
    let recipient = address(&receiver);
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    let rail = RingOutputRail::new(tx_key.clone(), RingDelivery::Packed);
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let first_nullifier = proof.input_utxos[0].nullifier();
    let secret = PackedSlot {
        tx_viewing_secret: &tx_key.secret_bytes(),
        salt: &rail.salt(),
        output_index: 0,
        first_nullifier: &first_nullifier,
    }
    .secret()
    .unwrap();
    let blinding = RingOutputBlinding {
        first_nullifier,
        ring_secret: *RingSecret::confidential(&secret).unwrap().as_bytes(),
        output_index: 0,
    }
    .derive()
    .unwrap();
    assert_eq!(proof.output_utxos[0].blinding, blinding);
    assert_eq!(proof.external_data.salt, rail.salt());
    let resent = RingOutputRail::new(tx_key.clone(), RingDelivery::Packed);
    assert_ne!(
        resent.salt(),
        rail.salt(),
        "a resent attempt draws a fresh salt"
    );
    assert_eq!(
        proof.external_data.outputs[0].owner_tag,
        OwnerTag::Inline(recipient.viewing_pubkey.u())
    );
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    assert_eq!(published.len(), proof.output_utxos.len());
    assert!(published
        .iter()
        .all(|slot| matches!(slot.wire, RingOutput::Packed { .. })));
    let data = proof.external_data.outputs[0].data.as_deref().unwrap();
    let RingPackedBody { key, ciphertext } = ring_confidential_packed_output_body(data).unwrap();
    assert_eq!(key, recipient.viewing_pubkey.as_bytes());
    let opened = RingPacked::decode(
        &[&key[..], ciphertext].concat(),
        &DecodeCx {
            viewing_key: &receiver.viewing_key,
            tx_viewing_pk: Some(tx_key.pubkey()),
            salt: Some(rail.salt()),
            slot_index: 0,
            first_nullifier: Some(first_nullifier),
        },
    )
    .unwrap();
    assert_eq!((opened.amount, opened.blinding), (3, blinding));
}

#[test]
fn a_delivered_output_opens_only_for_the_key_its_owner_tag_names() {
    let sender = keypair(1);
    let receiver = keypair(2);
    let recipient = address(&receiver);
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    let rail = RingOutputRail::new(tx_key, RingDelivery::Delivered);
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    assert_eq!(published[0].recipient, Some(recipient.viewing_pubkey));
    let secret = delivered_secret(&receiver.viewing_key, &proof, &rail, 0);
    let opened = open(&proof, published[0].wire, &recipient, &secret, 0).unwrap();
    assert_eq!(
        (opened.utxo.amount, opened.utxo.blinding),
        (3, proof.output_utxos[0].blinding)
    );
    let stranger = delivered_secret(&keypair(3).viewing_key, &proof, &rail, 0);
    assert!(open(&proof, published[0].wire, &recipient, &stranger, 0).is_none());
}

#[test]
fn an_anonymous_payment_binds_its_tag_and_the_change_opens_under_the_change_key() {
    let sender = keypair(1);
    let receiver = keypair(2);
    let (recipient, address_key) = ring_address(&receiver);
    let change_key = sender.viewing_key.ring_change_key(&RING).unwrap();
    let tag = RingTag::from_bytes([7; TAG_LEN]);
    let slots = AnonymousSlots::new(change_key.pubkey())
        .with_payment(
            0,
            StreamPayment {
                recipient: recipient.viewing_pubkey,
                tag,
                position: StreamPosition::Inbox(TagIndex::new(0).unwrap()),
            },
        )
        .unwrap();
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    let rail = RingOutputRail::new(tx_key, RingDelivery::Anonymous(Box::new(slots)));
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    assert_eq!(
        proof.external_data.outputs[0].owner_tag,
        OwnerTag::Inline(tag.field())
    );
    let secret = delivered_secret(&address_key, &proof, &rail, 0);
    assert_eq!(
        open(&proof, published[0].wire, &recipient, &secret, 0).map(|opened| opened.utxo.amount),
        Some(3)
    );
    let Some(AnonymousSlot::Change { tag: change_tag }) = published[1].anonymous else {
        panic!("change slot expected")
    };
    assert_eq!(
        proof.external_data.outputs[1].owner_tag,
        OwnerTag::Inline(change_tag.field())
    );
    let change = delivered_secret(&change_key, &proof, &rail, 1);
    assert_eq!(
        open(&proof, published[1].wire, &address(&sender), &change, 1)
            .map(|opened| opened.utxo.amount),
        Some(7)
    );
    let tags: std::collections::HashSet<_> =
        proof.external_data.resolved_owner_tags.iter().collect();
    assert_eq!(tags.len(), proof.external_data.outputs.len());
}

#[test]
fn an_exit_naming_a_payment_key_is_refused() {
    let sender = keypair(1);
    let (recipient, _) = ring_address(&keypair(2));
    let slots = AnonymousSlots::new(sender.viewing_key.ring_change_key(&RING).unwrap().pubkey())
        .with_payment(
            0,
            StreamPayment {
                recipient: recipient.viewing_pubkey,
                tag: RingTag::from_bytes([7; TAG_LEN]),
                position: StreamPosition::Inbox(TagIndex::new(0).unwrap()),
            },
        )
        .unwrap();
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    tx.transfer_with_ring(&recipient, Mint::SOL, 2, None)
        .unwrap();
    let rail = RingOutputRail::new(tx_key, RingDelivery::Anonymous(Box::new(slots)));
    assert!(matches!(
        rail.encrypt(tx, &address(&sender)),
        Err(E::RingAddressExit { slot_index: 1 })
    ));
}

#[test]
fn an_anonymous_ring_output_to_another_owner_needs_a_stream_slot() {
    let sender = keypair(1);
    let (recipient, _) = ring_address(&keypair(2));
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    let rail = RingOutputRail::new(
        tx_key,
        RingDelivery::Anonymous(Box::new(AnonymousSlots::new(
            sender.viewing_key.ring_change_key(&RING).unwrap().pubkey(),
        ))),
    );
    assert!(matches!(
        rail.encrypt(tx, &address(&sender)),
        Err(E::UnplannedRingOutput { slot_index: 0 })
    ));
}

#[test]
fn a_payment_planned_on_another_owners_slot_is_refused() {
    let sender = keypair(1);
    let (recipient, _) = ring_address(&keypair(2));
    let (other, _) = ring_address(&keypair(3));
    let slots = AnonymousSlots::new(sender.viewing_key.ring_change_key(&RING).unwrap().pubkey())
        .with_payment(
            0,
            StreamPayment {
                recipient: other.viewing_pubkey,
                tag: RingTag::from_bytes([7; TAG_LEN]),
                position: StreamPosition::Inbox(TagIndex::new(0).unwrap()),
            },
        )
        .unwrap();
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    let rail = RingOutputRail::new(tx_key, RingDelivery::Anonymous(Box::new(slots)));
    assert!(matches!(
        rail.encrypt(tx, &address(&sender)),
        Err(E::RingPaymentSlot { slot_index: 0 })
    ));
}

#[test]
fn one_transfer_takes_one_pair_payment() {
    let (first, _) = ring_address(&keypair(2));
    let (second, _) = ring_address(&keypair(3));
    let pair = |recipient: &ShieldedAddress, byte| StreamPayment {
        recipient: recipient.viewing_pubkey,
        tag: RingTag::from_bytes([byte; TAG_LEN]),
        position: StreamPosition::Pair(TagIndex::new(0).unwrap()),
    };
    let slots = AnonymousSlots::new(
        keypair(1)
            .viewing_key
            .ring_change_key(&RING)
            .unwrap()
            .pubkey(),
    )
    .with_payment(0, pair(&first, 7))
    .unwrap();
    assert!(matches!(
        slots.with_payment(1, pair(&second, 8)),
        Err(E::RingPaymentSlot { slot_index: 1 })
    ));
}

#[test]
fn a_delivered_rail_refuses_output_data_and_compact_padding() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.add_output_utxo(
        SppProofOutputUtxo::new(Mint::SOL, 3, recipient)
            .unwrap()
            .with_ring_program_id(RING)
            .with_memo(vec![1]),
    )
    .unwrap();
    let rail = RingOutputRail::new(tx_key, RingDelivery::Delivered);
    assert!(matches!(
        rail.encrypt(tx, &address(&sender)),
        Err(E::DeliveredOutputData { slot_index: 0 })
    ));

    let (mut tx, tx_key) = ring_transfer(&sender, true);
    tx.transfer_sol(&recipient, 3).unwrap();
    tx.pad_utxos(Shape::IN1_OUT4, &address(&sender)).unwrap();
    let rail = RingOutputRail::new(tx_key, RingDelivery::Delivered);
    assert!(matches!(
        rail.encrypt(tx, &address(&sender)),
        Err(E::DeliveredCompactPadding { .. })
    ));
}
