use borsh::BorshDeserialize;
use cucumber::then;
use zolana_interface::instruction::instruction_data::transact::OutputCiphertext;
use zolana_keypair::viewing_key::random_salt;
use zolana_keypair::{constants::BLINDING_LEN, PublicKey};
use zolana_transaction::{
    data::{Data, DataRecord},
    serialization::anonymous::{
        AnonymousRecipient, AnonymousRecipientEncode, AnonymousSenderBundle, AnonymousSenderEncode,
        AnonymousTransferSenderPlaintext,
    },
    serialization::confidential::TransferRecipientPlaintext,
    serialization::split::{Split, SplitBundlePlaintext, SplitEncode},
    serialization::{DecodeCx, OwnerCx, UtxoSerialization},
    utxo::Utxo,
    Address, AssetRegistry, TransactionError,
};

use crate::TransactionWorld;

const SPL_ASSET_ID: u64 = 2;

fn spl_mint() -> Address {
    Address::new_from_array([5u8; 32])
}

fn registry() -> AssetRegistry {
    AssetRegistry::new([(SPL_ASSET_ID, spl_mint())]).unwrap()
}

fn input_utxo(owner: PublicKey, asset: Address, amount: u64, seed: u8) -> Utxo {
    Utxo {
        owner,
        asset,
        amount,
        blinding: [seed; BLINDING_LEN],
        zone_program_id: None,
        data: Data::default(),
    }
}

fn body(ciphertext: &OutputCiphertext) -> Vec<u8> {
    let output_data = zolana_event::OutputData::try_from_slice(&ciphertext.data).unwrap();
    let blob = match output_data {
        zolana_event::OutputData::Encrypted(blob)
        | zolana_event::OutputData::VerifiablyEncrypted(blob)
        | zolana_event::OutputData::Plaintext(blob) => blob,
    };
    blob.get(1..).expect("scheme byte").to_vec()
}

#[then(expr = "a transfer from {string} to {string} round-trips the change and recipient utxos")]
fn standard_transfer_round_trips(world: &mut TransactionWorld, sender: String, recipient: String) {
    let registry = registry();
    let sender = world.kp(&sender);
    let alice = world.kp(&recipient);
    let sender_nullifier_pk = sender.nullifier_key.pubkey().unwrap();

    let input_sol = input_utxo(sender.signing_pubkey(), Address::default(), 1_000_000, 10);
    let input_spl = input_utxo(sender.signing_pubkey(), spl_mint(), 100, 11);
    let sol_nullifier = input_sol
        .nullifier(
            &input_sol
                .hash(&sender_nullifier_pk, &[0u8; 32], &[0u8; 32])
                .unwrap(),
            &sender.nullifier_key,
        )
        .unwrap();
    let spl_nullifier = input_spl
        .nullifier(
            &input_spl
                .hash(&sender_nullifier_pk, &[0u8; 32], &[0u8; 32])
                .unwrap(),
            &sender.nullifier_key,
        )
        .unwrap();
    assert_ne!(sol_nullifier, spl_nullifier);
    let first_nullifier = sol_nullifier;

    let recipient_utxo = Utxo {
        owner: alice.signing_pubkey(),
        asset: spl_mint(),
        amount: 30,
        blinding: [1u8; BLINDING_LEN],
        zone_program_id: None,
        data: Data::new(vec![DataRecord::ProgramData(vec![1, 2, 3])]),
    };

    let sender_pt = AnonymousTransferSenderPlaintext {
        owner_pubkey: sender.signing_pubkey(),
        spl_asset_id: SPL_ASSET_ID,
        spl_amount: 70,
        sol_amount: 999_000,
        blinding_seed: [2u8; BLINDING_LEN],
        recipient_viewing_pks: vec![alice.viewing_pubkey()],
        spl_data: Data::default(),
        sol_data: Data::default(),
    };
    let expected_change = sender_pt.clone().into_utxos(&registry, None).unwrap();
    assert_eq!(expected_change.len(), 2);

    let salt = random_salt();
    let tx = sender
        .viewing_key
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap();
    let tx_viewing_pk = tx.pubkey();

    let sender_owner_cx = OwnerCx {
        owner: sender.signing_pubkey(),
        assets: &registry,
        zone_program_id: None,
    };
    let sender_ciphertext = AnonymousSenderBundle::encode(
        &expected_change,
        &sender_owner_cx,
        sender.get_sender_view_tag(0).unwrap(),
        &AnonymousSenderEncode {
            tx: tx.clone(),
            self_pubkey: sender.viewing_pubkey(),
            salt,
            slot_index: 0,
            blinding_seed: [2u8; BLINDING_LEN],
            recipient_viewing_pks: vec![alice.viewing_pubkey()],
        },
    )
    .unwrap();

    let recipient_owner_cx = OwnerCx {
        owner: recipient_utxo.owner,
        assets: &registry,
        zone_program_id: None,
    };
    let recipient_ciphertext = AnonymousRecipient::encode(
        core::slice::from_ref(&recipient_utxo),
        &recipient_owner_cx,
        alice.viewing_key.recipient_bootstrap_view_tag(),
        &AnonymousRecipientEncode {
            tx: tx.clone(),
            recipient_pubkey: alice.viewing_pubkey(),
            sender_pubkey: sender.viewing_pubkey(),
            salt,
            slot_index: 1,
        },
    )
    .unwrap();

    let sender_dcx = DecodeCx {
        viewing_key: &sender.viewing_key,
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some(salt),
        slot_index: 0,
        first_nullifier: Some(first_nullifier),
    };
    let recovered_sender =
        AnonymousSenderBundle::decode(&body(&sender_ciphertext), &sender_dcx).unwrap();
    assert_eq!(
        AnonymousSenderBundle::into_utxos(recovered_sender, &sender_owner_cx).unwrap(),
        expected_change
    );

    let recipient_dcx = DecodeCx {
        viewing_key: &alice.viewing_key,
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some(salt),
        slot_index: 1,
        first_nullifier: Some(first_nullifier),
    };
    let recovered_plaintext =
        AnonymousRecipient::decode(&body(&recipient_ciphertext), &recipient_dcx).unwrap();
    let recovered_recipient =
        AnonymousRecipient::into_utxos(recovered_plaintext, &recipient_owner_cx)
            .unwrap()
            .into_iter()
            .next()
            .expect("recipient utxo");
    assert_eq!(recovered_recipient, recipient_utxo);
}

#[then(expr = "a zone-owned recipient utxo for {string} round-trips")]
fn zone_owned_round_trips(world: &mut TransactionWorld, name: String) {
    let registry = registry();
    let kp = world.kp(&name);
    let zone_program_id = Some(Address::new_from_array([9u8; 32]));
    let utxo = Utxo {
        owner: kp.signing_pubkey(),
        asset: spl_mint(),
        amount: 30,
        blinding: [1u8; BLINDING_LEN],
        zone_program_id,
        data: Data::new(vec![DataRecord::ZoneData(vec![4, 5, 6])]),
    };
    let pt = utxo.to_recipient_plaintext(&registry).unwrap();
    let recovered = pt
        .into_utxo(kp.signing_pubkey(), &registry, zone_program_id)
        .unwrap();
    assert_eq!(recovered, utxo);
}

#[then(expr = "zone data without a zone program id is rejected for {string}")]
fn zone_data_without_id_rejected(world: &mut TransactionWorld, name: String) {
    let registry = registry();
    let kp = world.kp(&name);
    let pt = TransferRecipientPlaintext {
        asset_id: SPL_ASSET_ID,
        amount: 30,
        blinding: [1u8; BLINDING_LEN],
        data: Data::new(vec![DataRecord::ZoneData(vec![1])]),
    };
    assert_eq!(
        pt.into_utxo(kp.signing_pubkey(), &registry, None)
            .unwrap_err(),
        TransactionError::MissingZoneProgramId
    );
}

#[then(expr = "a zone program id without zone data is not set for {string}")]
fn zone_id_without_data_not_set(world: &mut TransactionWorld, name: String) {
    let registry = registry();
    let kp = world.kp(&name);
    let pt = TransferRecipientPlaintext {
        asset_id: SPL_ASSET_ID,
        amount: 30,
        blinding: [1u8; BLINDING_LEN],
        data: Data::new(vec![DataRecord::ProgramData(vec![1])]),
    };
    let utxo = pt
        .into_utxo(
            kp.signing_pubkey(),
            &registry,
            Some(Address::new_from_array([9u8; 32])),
        )
        .unwrap();
    assert_eq!(utxo.zone_program_id, None);
}

#[then(expr = "sender data on a zero-amount output is rejected for {string}")]
fn data_without_output_rejected(world: &mut TransactionWorld, name: String) {
    let registry = registry();
    let owner_pubkey = world.kp(&name).signing_pubkey();
    let spl_only = AnonymousTransferSenderPlaintext {
        owner_pubkey,
        spl_asset_id: SPL_ASSET_ID,
        spl_amount: 0,
        sol_amount: 5,
        blinding_seed: [2u8; BLINDING_LEN],
        recipient_viewing_pks: vec![],
        spl_data: Data::new(vec![DataRecord::ProgramData(vec![1])]),
        sol_data: Data::default(),
    };
    assert_eq!(
        spl_only.into_utxos(&registry, None).unwrap_err(),
        TransactionError::DataWithoutOutput
    );
    let sol_only = AnonymousTransferSenderPlaintext {
        owner_pubkey,
        spl_asset_id: SPL_ASSET_ID,
        spl_amount: 5,
        sol_amount: 0,
        blinding_seed: [2u8; BLINDING_LEN],
        recipient_viewing_pks: vec![],
        spl_data: Data::default(),
        sol_data: Data::new(vec![DataRecord::ProgramData(vec![1])]),
    };
    assert_eq!(
        sol_only.into_utxos(&registry, None).unwrap_err(),
        TransactionError::DataWithoutOutput
    );
}

#[then(expr = "a split by {string} round-trips through utxos")]
fn split_round_trips(world: &mut TransactionWorld, name: String) {
    let registry = registry();
    let owner = world.kp(&name);

    let split_pt = SplitBundlePlaintext {
        owner_pubkey: owner.signing_pubkey(),
        num_outputs: 4,
        asset_id: SPL_ASSET_ID,
        asset_amount: 200,
        blinding_seed: [3u8; BLINDING_LEN],
        data: Data::default(),
    };
    let expected = split_pt.clone().into_utxos(&registry, None).unwrap();
    assert_eq!(expected.len(), 4);

    let nf = [11u8; 32];
    let salt = random_salt();
    let tx = owner.viewing_key.get_transaction_viewing_key(&nf).unwrap();
    let tx_viewing_pk = tx.pubkey();
    let owner_cx = OwnerCx {
        owner: owner.signing_pubkey(),
        assets: &registry,
        zone_program_id: None,
    };
    let ciphertext = Split::encode(
        &expected,
        &owner_cx,
        owner.get_sender_view_tag(0).unwrap(),
        &SplitEncode {
            tx: tx.clone(),
            recipient_pubkey: owner.viewing_pubkey(),
            salt,
            slot_index: 0,
            blinding_seed: [3u8; BLINDING_LEN],
        },
    )
    .unwrap();
    let dcx = DecodeCx {
        viewing_key: &owner.viewing_key,
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some(salt),
        slot_index: 0,
        first_nullifier: Some(nf),
    };
    let recovered =
        Split::into_utxos(Split::decode(&body(&ciphertext), &dcx).unwrap(), &owner_cx).unwrap();

    assert_eq!(recovered, expected);
}
