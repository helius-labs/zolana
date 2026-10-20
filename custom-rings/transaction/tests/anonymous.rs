use borsh::BorshDeserialize;
use solana_address::Address;
use solana_signature::Signature;
use zolana_event::OutputDataEncoding;
use zolana_interface::instruction::instruction_data::transact::OwnerTag;
use zolana_keypair::{ShieldedKeypair, SigningKey, X25519Pubkey};
use zolana_ring_transaction::{AnonymousViewTags, RingAnonymous};
use zolana_transaction::{
    instructions::transact::{ConfidentialTransaction, OutputEncryption, Shape, SppProofInputs},
    Data, DecodeCx, EncryptedScheme, Mint, TransactionError, Utxo, UtxoSerialization, WalletUtxo,
};

const RING: Address = Address::new_from_array([42; 32]);

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

fn wallet_utxo(owner: &ShieldedKeypair, amount: u64) -> WalletUtxo {
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: Mint::SOL,
        amount,
        blinding: [1; 32],
        ring_program_id: None,
        data: Data::default(),
    };
    let nullifier_pubkey = owner.shielded_address().unwrap().nullifier_pubkey;
    let utxo_hash = utxo.hash(&nullifier_pubkey, &[0; 32], &[0; 32], 7).unwrap();
    WalletUtxo {
        nullifier: owner.nullifier(&utxo_hash, &utxo.blinding).unwrap(),
        utxo,
        nullifier_pubkey,
        utxo_hash,
        data_hash: None,
        ring_data_hash: None,
        tree_id: 7,
        leaf_index: 1,
        slot: 1,
        tx_signature: Signature::from([1; 64]),
        slot_index: 0,
        latest_tree_id: None,
        tx_viewing_key: None,
    }
}

fn transfer(
    owner: &ShieldedKeypair,
    view_tags: &AnonymousViewTags,
) -> Result<Encrypted, TransactionError> {
    let sender = owner.shielded_address().unwrap();
    let receiver = keypair(2).shielded_address().unwrap();
    let input = wallet_utxo(owner, 10);
    let tx_viewing_key = owner
        .viewing_key
        .get_transaction_viewing_key(&input.nullifier)
        .unwrap();
    let payer = sender.solana_address().unwrap();
    let mut transaction = ConfidentialTransaction::new_with_ring(vec![input], payer, RING).unwrap();
    transaction.transfer_sol(&receiver, 3).unwrap();
    transaction.pad_utxos(Shape::IN1_OUT4, &sender).unwrap();
    let proof = OutputEncryption {
        sender: &sender,
        tx_viewing_key: &tx_viewing_key,
        encoder: view_tags,
    }
    .encrypt(transaction)?;
    Ok(Encrypted {
        proof,
        tx_viewing_pk: tx_viewing_key.pubkey(),
    })
}

struct Encrypted {
    proof: SppProofInputs,
    tx_viewing_pk: X25519Pubkey,
}

#[test]
fn anonymous_outputs_publish_view_tags_and_frame_dummies_alike() {
    let owner = keypair(1);
    let recipient = keypair(2);
    let receiver = recipient.shielded_address().unwrap();
    let sender_tag = owner.get_sender_view_tag(0).unwrap();
    let Encrypted {
        proof,
        tx_viewing_pk,
    } = transfer(
        &owner,
        &AnonymousViewTags::new(sender_tag).with_bootstrap_tag(receiver.viewing_pubkey),
    )
    .unwrap();
    let outputs = &proof.external_data.outputs;
    let lengths: Vec<_> = outputs
        .iter()
        .map(|output| output.data.as_ref().unwrap().len())
        .collect();
    assert_eq!(lengths.len(), 4);
    assert!(lengths.iter().all(|len| *len == lengths[0]), "{lengths:?}");
    for (index, (reader, amount, tag)) in [
        (&recipient, 3, receiver.viewing_pubkey.u()),
        (&owner, 7, sender_tag),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(outputs[index].owner_tag, OwnerTag::Inline(tag));
        assert_eq!(proof.external_data.resolved_owner_tags[index], tag);
        let OutputDataEncoding::Encrypted(blob) =
            OutputDataEncoding::try_from_slice(outputs[index].data.as_ref().unwrap()).unwrap()
        else {
            panic!("encrypted output")
        };
        assert_eq!(blob[0], EncryptedScheme::RingAnonymous.as_byte());
        let plaintext = RingAnonymous::decode(
            &blob[1..],
            &DecodeCx {
                viewing_key: &reader.viewing_key,
                tx_viewing_pk: Some(tx_viewing_pk),
                salt: Some(proof.external_data.salt),
                slot_index: index as u32,
                first_nullifier: None,
            },
        )
        .unwrap();
        assert_eq!(plaintext.amount, amount);
        assert_eq!(plaintext.ring_program_id, Some(RING));
    }
}

#[test]
fn a_recipient_without_a_chosen_tag_is_rejected() {
    let owner = keypair(1);
    let sender_tag = owner.get_sender_view_tag(0).unwrap();
    assert_eq!(
        transfer(&owner, &AnonymousViewTags::new(sender_tag)).err(),
        Some(TransactionError::RecipientViewTagUnset { slot_index: 0 })
    );
}
