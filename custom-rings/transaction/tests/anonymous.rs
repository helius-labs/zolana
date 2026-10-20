//! The anonymous rail's sealing, read back through the slot streams it publishes under.

use std::sync::Arc;

use borsh::BorshDeserialize;
use solana_address::Address;
use solana_signature::Signature;
use zolana_event::OutputDataEncoding;
use zolana_interface::instruction::instruction_data::transact::{
    ring_anonymous_encrypted_output_body, OwnerTag,
};
use zolana_keypair::{
    RingAddress, ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey, X25519Pubkey,
};
use zolana_ring_transaction::{AnonymousViewTags, RingAnonymousSlot, TransactSession};
use zolana_transaction::{
    instructions::transact::{
        ConfidentialTransaction, OutputEncryption, Shape, SppProofInputs, SppProofOutputUtxo,
    },
    Data, EncryptedScheme, Mint, TransactionError as E, Utxo, WalletUtxo,
};

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

fn payer(owner: &ShieldedKeypair) -> Address {
    owner.shielded_address().unwrap().solana_address().unwrap()
}

fn wallet_utxo(
    owner: &ShieldedKeypair,
    mint: Mint,
    amount: u64,
    tree_id: u16,
    nonce: u8,
) -> WalletUtxo {
    let mut blinding = [0; 32];
    blinding[31] = nonce;
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: mint,
        amount,
        blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    let nullifier_pubkey = owner.shielded_address().unwrap().nullifier_pubkey;
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree_id)
        .unwrap();
    WalletUtxo {
        nullifier: owner.nullifier(&utxo_hash, &blinding).unwrap(),
        utxo,
        nullifier_pubkey,
        utxo_hash,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: None,
        tree_id,
        leaf_index: u64::from(nonce),
        latest_tree_id: None,
        slot: u64::from(nonce),
        tx_signature: Signature::from([nonce; 64]),
        slot_index: 0,
    }
}

fn slot_len(proof: &SppProofInputs, index: usize) -> usize {
    proof
        .external_data
        .outputs
        .get(index)
        .and_then(|published| published.data.as_ref())
        .map(Vec::len)
        .unwrap()
}

fn encrypt_anonymous(
    transaction: ConfidentialTransaction,
    sender: &ShieldedAddress,
    tx_viewing_key: &ViewingKey,
    view_tags: &AnonymousViewTags,
) -> Result<SppProofInputs, E> {
    OutputEncryption {
        sender,
        tx_viewing_key,
        encoder: view_tags,
    }
    .encrypt(transaction)
}

const RING: Address = Address::new_from_array([42; 32]);

struct Payment<'a> {
    from: &'a ShieldedKeypair,
    to: ShieldedAddress,
}

impl Payment<'_> {
    fn seal(self, view_tags: &AnonymousViewTags) -> Result<SppProofInputs, E> {
        let input = wallet_utxo(self.from, Mint::SOL, 10, 7, 1);
        let key = self
            .from
            .viewing_key
            .get_transaction_viewing_key(&input.nullifier)
            .unwrap();
        let mut tx =
            ConfidentialTransaction::new_with_ring(vec![input], payer(self.from), RING).unwrap();
        tx.transfer_sol(&self.to, 3).unwrap();
        encrypt_anonymous(tx, &self.from.shielded_address().unwrap(), &key, view_tags)
    }
}

#[test]
fn anonymous_ring_encryption_publishes_derived_view_tags() {
    let owner = keypair(1);
    let recipient = keypair(2);
    let sender = owner.shielded_address().unwrap();
    let receiver = recipient.shielded_address().unwrap();
    let ring = Address::new_from_array([42; 32]);
    let address = RingAddress {
        recipient: receiver,
        ring_program_id: ring,
        inbox_secret: recipient.viewing_key.inbox_secret(0).unwrap(),
    };
    let pair_pk = owner
        .viewing_key
        .pair_key(&receiver.viewing_pubkey)
        .unwrap()
        .pubkey();
    let own_pair_pk = owner
        .viewing_key
        .pair_key(&owner.viewing_pubkey())
        .unwrap()
        .pubkey();
    let inbox_tag = address.inbox_secret.view_tag(3).unwrap();
    let pair_tag = owner
        .viewing_key
        .pair_send_view_tag(&receiver.viewing_pubkey, 5)
        .unwrap();
    for recipient_tag in [inbox_tag, pair_tag] {
        let view_tags = AnonymousViewTags::new(&owner.viewing_key)
            .with_slot(0, &address, recipient_tag)
            .unwrap();
        let input = wallet_utxo(&owner, Mint::SOL, 10, 7, 1);
        let first_nullifier = input.nullifier;
        let key = owner
            .viewing_key
            .get_transaction_viewing_key(&first_nullifier)
            .unwrap();
        let mut tx =
            ConfidentialTransaction::new_with_ring(vec![input], payer(&owner), ring).unwrap();
        tx.transfer_sol(&receiver, 3).unwrap();
        let proof = encrypt_anonymous(tx, &sender, &key, &view_tags).unwrap();
        assert_eq!(
            proof.blinding_seed,
            owner
                .viewing_key
                .ring_blinding_seed(&first_nullifier)
                .unwrap()
        );
        let change_tag = owner
            .viewing_key
            .ring_change_view_tag(&first_nullifier, 1)
            .unwrap();
        let expected = [
            (&recipient, 3, recipient_tag, pair_pk),
            (&owner, 7, change_tag, own_pair_pk),
        ];
        for (index, (reader, amount, tag, pair_pk)) in expected.into_iter().enumerate() {
            let output = &proof.external_data.outputs[index];
            assert_eq!(output.owner_tag, OwnerTag::Inline(tag));
            assert_eq!(proof.external_data.resolved_owner_tags[index], tag);
            let OutputDataEncoding::Encrypted(blob) =
                OutputDataEncoding::try_from_slice(output.data.as_ref().unwrap()).unwrap()
            else {
                panic!("encrypted output")
            };
            assert_eq!(blob[0], EncryptedScheme::RingAnonymous.as_byte());
            assert_eq!(blob.len(), 105);
            let recovered = RingAnonymousSlot {
                tx_viewing_pk: key.pubkey(),
                recipient_pk: reader.viewing_pubkey(),
                salt: proof.external_data.salt,
                slot: index as u8,
            }
            .open(&reader.viewing_key, &blob[1..])
            .unwrap();
            assert_eq!(recovered.amount, amount);
            assert_eq!(recovered.asset_address, [0; 32]);
            assert_eq!(recovered.blinding, proof.output_utxos[index].blinding);
            assert_eq!(recovered.pair_u, pair_pk.u());
        }
    }
}

#[test]
fn anonymous_ring_padding_publishes_random_tags() {
    let owner = keypair(1);
    let sender = owner.shielded_address().unwrap();
    let ring = Address::new_from_array([42; 32]);
    let mut tags = Vec::new();
    for _ in 0..2 {
        let input = wallet_utxo(&owner, Mint::SOL, 10, 7, 1);
        let key = owner
            .viewing_key
            .get_transaction_viewing_key(&input.nullifier)
            .unwrap();
        let mut tx =
            ConfidentialTransaction::new_with_ring(vec![input], payer(&owner), ring).unwrap();
        tx.transfer_sol(&sender, 3).unwrap();
        tx.pad_utxos(Shape::IN2_OUT4, &sender).unwrap();
        let proof = encrypt_anonymous(
            tx,
            &sender,
            &key,
            &AnonymousViewTags::new(&owner.viewing_key),
        )
        .unwrap();
        let solana_key = sender.signing_pubkey.confidential_view_tag().unwrap();
        let real_len = slot_len(&proof, 0);
        for index in 2..4 {
            let tag = proof.external_data.resolved_owner_tags[index];
            assert_ne!(tag, solana_key);
            assert_eq!(tag[0], 0);
            assert_ne!(tag, [0; 32]);
            assert_eq!(
                proof.external_data.outputs[index].owner_tag,
                OwnerTag::Inline(tag)
            );
            assert_eq!(slot_len(&proof, index), real_len);
            let OutputDataEncoding::Encrypted(blob) = OutputDataEncoding::try_from_slice(
                proof.external_data.outputs[index].data.as_ref().unwrap(),
            )
            .unwrap() else {
                panic!("encrypted output")
            };
            assert_eq!(blob[0], EncryptedScheme::RingAnonymous.as_byte());
            assert_eq!(blob.len(), 105);
            tags.push(tag);
        }
    }
    tags.sort();
    tags.dedup();
    assert_eq!(tags.len(), 4);
}

#[test]
fn anonymous_change_tags_and_blinding_seed_follow_the_key_derivation_vectors() {
    #[derive(serde::Deserialize)]
    struct Vectors {
        ring_derivation: RingDerivation,
    }
    #[derive(serde::Deserialize)]
    struct RingDerivation {
        viewing_secret: String,
        recipient_viewing_pubkey: String,
        pair_pubkey: String,
        first_nullifier: String,
        change_view_tags: Vec<SlotTag>,
        blinding_seed: String,
    }
    #[derive(serde::Deserialize)]
    struct SlotTag {
        slot: u8,
        tag: String,
    }
    let bytes32 = |text: &str| -> [u8; 32] { hex::decode(text).unwrap().try_into().unwrap() };
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../../test-vectors/key_derivation.json")).unwrap();
    let ring = vectors.ring_derivation;
    let sender = ViewingKey::from_bytes(&bytes32(&ring.viewing_secret));
    let first_nullifier = bytes32(&ring.first_nullifier);
    let view_tags = AnonymousViewTags::new(&sender);
    assert!(!ring.change_view_tags.is_empty());
    for case in &ring.change_view_tags {
        let keys = view_tags.change_keys(&first_nullifier, case.slot).unwrap();
        assert_eq!(keys.tag, bytes32(&case.tag));
        assert_eq!(
            keys.pair_pk,
            sender.pair_key(&sender.pubkey()).unwrap().pubkey()
        );
    }
    assert_eq!(
        view_tags.blinding_seed(&first_nullifier).unwrap(),
        bytes32(&ring.blinding_seed)
    );
    assert_eq!(
        view_tags.blinding_seed(&first_nullifier).unwrap(),
        AnonymousViewTags::new(&sender)
            .blinding_seed(&first_nullifier)
            .unwrap()
    );
    let recipient = X25519Pubkey::from_bytes(
        hex::decode(&ring.recipient_viewing_pubkey)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        sender.pair_key(&recipient).unwrap().pubkey().as_bytes()[..],
        hex::decode(&ring.pair_pubkey).unwrap()[..]
    );
}

#[test]
fn anonymous_ring_encryption_refuses_a_recipient_without_keys() {
    let owner = keypair(1);
    let receiver = keypair(2).shielded_address().unwrap();
    let sender = owner.shielded_address().unwrap();
    let input = wallet_utxo(&owner, Mint::SOL, 10, 7, 1);
    let key = owner
        .viewing_key
        .get_transaction_viewing_key(&input.nullifier)
        .unwrap();
    let ring = Address::new_from_array([42; 32]);
    let mut tx = ConfidentialTransaction::new_with_ring(vec![input], payer(&owner), ring).unwrap();
    tx.transfer_sol(&receiver, 3).unwrap();
    assert!(matches!(
        encrypt_anonymous(
            tx,
            &sender,
            &key,
            &AnonymousViewTags::new(&owner.viewing_key)
        ),
        Err(E::UnknownAnonymousRecipient { slot_index: 0 })
    ));
}

#[test]
fn anonymous_ring_encryption_refuses_another_wallets_viewing_key() {
    let owner = keypair(1);
    let sender = owner.shielded_address().unwrap();
    let input = wallet_utxo(&owner, Mint::SOL, 10, 7, 1);
    let key = owner
        .viewing_key
        .get_transaction_viewing_key(&input.nullifier)
        .unwrap();
    let ring = Address::new_from_array([42; 32]);
    let mut tx = ConfidentialTransaction::new_with_ring(vec![input], payer(&owner), ring).unwrap();
    tx.transfer_sol(&sender, 3).unwrap();
    assert!(matches!(
        encrypt_anonymous(
            tx,
            &sender,
            &key,
            &AnonymousViewTags::new(&keypair(2).viewing_key)
        ),
        Err(E::AnonymousViewTagsSenderMismatch)
    ));
}

#[test]
fn anonymous_slot_tags_bind_the_recipient_address_to_its_slot() {
    let owner = keypair(1);
    let recipient = keypair(2);
    let sender = owner.shielded_address().unwrap();
    let receiver = recipient.shielded_address().unwrap();
    let ring = Address::new_from_array([42; 32]);
    let address = RingAddress {
        recipient: receiver,
        ring_program_id: ring,
        inbox_secret: recipient.viewing_key.inbox_secret(0).unwrap(),
    };
    let other = RingAddress {
        recipient: keypair(3).shielded_address().unwrap(),
        ..address.clone()
    };
    let tag = address.inbox_secret.view_tag(0).unwrap();
    for (slot, address, expected) in [
        (
            1,
            &address,
            Some(E::UnknownAnonymousRecipient { slot_index: 0 }),
        ),
        (
            0,
            &other,
            Some(E::UnknownAnonymousRecipient { slot_index: 0 }),
        ),
        (0, &address, None),
    ] {
        let input = wallet_utxo(&owner, Mint::SOL, 10, 7, 1);
        let key = owner
            .viewing_key
            .get_transaction_viewing_key(&input.nullifier)
            .unwrap();
        let mut tx =
            ConfidentialTransaction::new_with_ring(vec![input], payer(&owner), ring).unwrap();
        tx.transfer_sol(&receiver, 3).unwrap();
        let view_tags = AnonymousViewTags::new(&owner.viewing_key)
            .with_slot(slot, address, tag)
            .unwrap();
        let result = encrypt_anonymous(tx, &sender, &key, &view_tags);
        match expected {
            Some(error) => assert_eq!(result.err(), Some(error)),
            None => assert_eq!(result.unwrap().external_data.resolved_owner_tags[0], tag),
        }
    }
}

#[test]
fn two_payments_to_one_address_publish_their_own_reserved_tags() {
    let owner = keypair(1);
    let recipient = keypair(2);
    let sender = owner.shielded_address().unwrap();
    let receiver = recipient.shielded_address().unwrap();
    let ring = Address::new_from_array([42; 32]);
    let address = RingAddress {
        recipient: receiver,
        ring_program_id: ring,
        inbox_secret: recipient.viewing_key.inbox_secret(0).unwrap(),
    };
    let input = wallet_utxo(&owner, Mint::SOL, 10, 7, 1);
    let key = owner
        .viewing_key
        .get_transaction_viewing_key(&input.nullifier)
        .unwrap();
    let mut tx = ConfidentialTransaction::new_with_ring(vec![input], payer(&owner), ring).unwrap();
    tx.transfer_sol(&receiver, 3).unwrap();
    tx.transfer_sol(&receiver, 2).unwrap();
    let tags = [
        address.inbox_secret.view_tag(4).unwrap(),
        address.inbox_secret.view_tag(5).unwrap(),
    ];
    let view_tags = AnonymousViewTags::new(&owner.viewing_key)
        .with_slot(0, &address, tags[0])
        .unwrap()
        .with_slot(1, &address, tags[1])
        .unwrap();
    let proof = encrypt_anonymous(tx.clone(), &sender, &key, &view_tags).unwrap();
    assert_eq!(&proof.external_data.resolved_owner_tags[..2], &tags);
    let same = AnonymousViewTags::new(&owner.viewing_key)
        .with_slot(0, &address, tags[0])
        .unwrap()
        .with_slot(1, &address, tags[0])
        .unwrap();
    assert_eq!(
        encrypt_anonymous(tx, &sender, &key, &same).err(),
        Some(E::DuplicateAnonymousTag {
            first: 0,
            second: 1
        })
    );
}

#[test]
fn a_self_payment_publishes_its_address_tag_beside_the_change_tag() {
    let owner = keypair(1);
    let sender = owner.shielded_address().unwrap();
    let own = RingAddress {
        recipient: sender,
        ring_program_id: RING,
        inbox_secret: owner.viewing_key.inbox_secret(7).unwrap(),
    };
    let tag = own.inbox_secret.view_tag(0).unwrap();
    let view_tags = AnonymousViewTags::new(&owner.viewing_key)
        .with_slot(0, &own, tag)
        .unwrap();
    let proof = Payment {
        from: &owner,
        to: sender,
    }
    .seal(&view_tags)
    .unwrap();
    let change = owner
        .viewing_key
        .ring_change_view_tag(&proof.input_utxos[0].nullifier, 1)
        .unwrap();
    assert_eq!(
        &proof.external_data.resolved_owner_tags[..2],
        &[tag, change]
    );
}

#[test]
fn a_payment_to_another_viewing_key_of_the_sender_opens_only_under_it() {
    let owner = keypair(1);
    let other = keypair(2);
    let sibling = RingAddress {
        recipient: ShieldedAddress {
            viewing_pubkey: other.viewing_pubkey(),
            ..owner.shielded_address().unwrap()
        },
        ring_program_id: RING,
        inbox_secret: other.viewing_key.inbox_secret(0).unwrap(),
    };
    let tag = sibling.inbox_secret.view_tag(0).unwrap();
    let view_tags = AnonymousViewTags::new(&owner.viewing_key)
        .with_slot(0, &sibling, tag)
        .unwrap();
    let proof = Payment {
        from: &owner,
        to: sibling.recipient,
    }
    .seal(&view_tags)
    .unwrap();
    let external = &proof.external_data;
    assert_eq!(external.resolved_owner_tags[0], tag);
    let body =
        ring_anonymous_encrypted_output_body(external.outputs[0].data.as_deref().unwrap()).unwrap();
    let open = |reader: &ShieldedKeypair| {
        RingAnonymousSlot {
            tx_viewing_pk: X25519Pubkey::from_bytes(external.tx_viewing_pk).unwrap(),
            recipient_pk: reader.viewing_pubkey(),
            salt: external.salt,
            slot: 0,
        }
        .open(&reader.viewing_key, body)
    };
    let opened = open(&other).unwrap();
    assert_eq!(opened.amount, 3);
    assert_eq!(opened.blinding, proof.output_utxos[0].blinding);
    assert_eq!(
        opened.pair_u,
        owner
            .viewing_key
            .pair_key(&other.viewing_pubkey())
            .unwrap()
            .pubkey()
            .u()
    );
    assert_ne!(open(&owner).ok(), Some(opened));
}

#[test]
fn change_is_only_the_senders_unpaid_output() {
    let owner = keypair(1);
    let other = keypair(2);
    let sender = owner.shielded_address().unwrap();
    let foreign = other.shielded_address().unwrap();
    let elsewhere = RingAddress {
        recipient: foreign,
        ring_program_id: RING,
        inbox_secret: other.viewing_key.inbox_secret(0).unwrap(),
    };
    let unpaid = AnonymousViewTags::new(&owner.viewing_key);
    let paid_elsewhere = unpaid
        .clone()
        .with_slot(0, &elsewhere, elsewhere.inbox_secret.view_tag(0).unwrap())
        .unwrap();
    let other_viewing_key = ShieldedAddress {
        viewing_pubkey: foreign.viewing_pubkey,
        ..sender
    };
    let other_nullifier_key = ShieldedAddress {
        nullifier_pubkey: foreign.nullifier_pubkey,
        ..sender
    };
    for (to, view_tags) in [
        (other_viewing_key, &unpaid),
        (other_nullifier_key, &unpaid),
        (sender, &paid_elsewhere),
    ] {
        assert_eq!(
            Payment { from: &owner, to }.seal(view_tags).err(),
            Some(E::UnknownAnonymousRecipient { slot_index: 0 })
        );
    }
}

#[test]
fn a_payment_on_a_padding_or_missing_slot_is_refused() {
    let owner = keypair(1);
    let other = keypair(2);
    let sender = owner.shielded_address().unwrap();
    let elsewhere = RingAddress {
        recipient: other.shielded_address().unwrap(),
        ring_program_id: RING,
        inbox_secret: other.viewing_key.inbox_secret(0).unwrap(),
    };
    let tag = elsewhere.inbox_secret.view_tag(0).unwrap();
    for slot_index in [3, 9] {
        let input = wallet_utxo(&owner, Mint::SOL, 10, 7, 1);
        let key = owner
            .viewing_key
            .get_transaction_viewing_key(&input.nullifier)
            .unwrap();
        let mut tx =
            ConfidentialTransaction::new_with_ring(vec![input], payer(&owner), RING).unwrap();
        tx.transfer_sol(&sender, 3).unwrap();
        tx.pad_utxos(Shape::IN2_OUT4, &sender).unwrap();
        let view_tags = AnonymousViewTags::new(&owner.viewing_key)
            .with_slot(slot_index, &elsewhere, tag)
            .unwrap();
        assert_eq!(
            encrypt_anonymous(tx, &sender, &key, &view_tags).err(),
            Some(E::AnonymousPaymentSlot { slot_index })
        );
    }
}

/// A retry of the same outputs keeps its salt, other outputs under the sealed key are refused.
#[test]
fn a_session_seals_one_stream_per_transaction_key() {
    let owner = keypair(1);
    let recipient = keypair(2);
    let sender = owner.shielded_address().unwrap();
    let receiver = recipient.shielded_address().unwrap();
    let ring = Address::new_from_array([42; 32]);
    let address = RingAddress {
        recipient: receiver,
        ring_program_id: ring,
        inbox_secret: recipient.viewing_key.inbox_secret(0).unwrap(),
    };
    let input = wallet_utxo(&owner, Mint::SOL, 10, 7, 1);
    let key = owner
        .viewing_key
        .get_transaction_viewing_key(&input.nullifier)
        .unwrap();
    let tags = |session: &Arc<TransactSession>| {
        AnonymousViewTags::new(&owner.viewing_key)
            .with_slot(0, &address, address.inbox_secret.view_tag(4).unwrap())
            .unwrap()
            .with_session(Arc::clone(session))
    };
    let session = Arc::new(TransactSession::new());
    let mut tx =
        ConfidentialTransaction::new_with_ring(vec![input.clone()], payer(&owner), ring).unwrap();
    tx.transfer_sol(&receiver, 3).unwrap();
    let first = encrypt_anonymous(tx.clone(), &sender, &key, &tags(&session)).unwrap();
    let retry = encrypt_anonymous(tx, &sender, &key, &tags(&session)).unwrap();
    assert_eq!(retry.external_data.salt, first.external_data.salt);
    let mut other =
        ConfidentialTransaction::new_with_ring(vec![input], payer(&owner), ring).unwrap();
    other.transfer_sol(&receiver, 4).unwrap();
    assert_eq!(
        encrypt_anonymous(other.clone(), &sender, &key, &tags(&session)).err(),
        Some(E::AnonymousStreamReuse)
    );
    let fresh = encrypt_anonymous(other, &sender, &key, &tags(&Arc::default())).unwrap();
    assert_ne!(fresh.external_data.salt, first.external_data.salt);
}

#[test]
fn anonymous_ring_encryption_refuses_memos_and_compact_padding() {
    let owner = keypair(1);
    let sender = owner.shielded_address().unwrap();
    let ring = Address::new_from_array([42; 32]);
    let input = wallet_utxo(&owner, Mint::SOL, 10, 7, 1);
    let key = owner
        .viewing_key
        .get_transaction_viewing_key(&input.nullifier)
        .unwrap();
    let mut tx =
        ConfidentialTransaction::new_with_ring(vec![input.clone()], payer(&owner), ring).unwrap();
    tx.add_output_utxo(
        SppProofOutputUtxo::new(Mint::SOL, 3, sender)
            .unwrap()
            .with_ring_program_id(ring)
            .with_memo(vec![1, 2, 3]),
    )
    .unwrap();
    assert_eq!(
        encrypt_anonymous(
            tx,
            &sender,
            &key,
            &AnonymousViewTags::new(&owner.viewing_key)
        )
        .err(),
        Some(E::AnonymousOutputData { slot_index: 0 })
    );
    let mut compact =
        ConfidentialTransaction::new_compact_with_ring(vec![input], payer(&owner), ring).unwrap();
    compact.transfer_sol(&sender, 3).unwrap();
    compact.pad_utxos(Shape::IN2_OUT4, &sender).unwrap();
    assert_eq!(
        encrypt_anonymous(
            compact,
            &sender,
            &key,
            &AnonymousViewTags::new(&owner.viewing_key)
        )
        .err(),
        Some(E::AnonymousCompactPadding { slot_index: 2 })
    );
}

#[test]
fn anonymous_ring_exit_publishes_the_default_ring_owner() {
    let owner = keypair(1);
    let recipient = keypair(2);
    let sender = owner.shielded_address().unwrap();
    let receiver = recipient.shielded_address().unwrap();
    let ring = Address::new_from_array([42; 32]);
    let input = wallet_utxo(&owner, Mint::SOL, 10, 7, 1);
    let first_nullifier = input.nullifier;
    let key = owner
        .viewing_key
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap();
    let mut tx = ConfidentialTransaction::new_with_ring(vec![input], payer(&owner), ring).unwrap();
    tx.transfer_with_ring(&receiver, Mint::SOL, 3, None)
        .unwrap();
    let proof = encrypt_anonymous(
        tx,
        &sender,
        &key,
        &AnonymousViewTags::new(&owner.viewing_key),
    )
    .unwrap();
    let exit = &proof.external_data.outputs[0];
    let owner_key = receiver.signing_pubkey.confidential_view_tag().unwrap();
    assert_eq!(exit.owner_tag, OwnerTag::Inline(owner_key));
    assert_eq!(proof.external_data.resolved_owner_tags[0], owner_key);
    let OutputDataEncoding::Encrypted(blob) =
        OutputDataEncoding::try_from_slice(exit.data.as_ref().unwrap()).unwrap()
    else {
        panic!("encrypted output")
    };
    assert_eq!(blob[0], EncryptedScheme::Confidential.as_byte());
    proof
        .external_data
        .validate_ring_output_markers(&proof.output_utxos)
        .unwrap();
    let change = &proof.external_data.outputs[1];
    assert_eq!(
        change.owner_tag,
        OwnerTag::Inline(
            owner
                .viewing_key
                .ring_change_view_tag(&first_nullifier, 1)
                .unwrap()
        )
    );
}
