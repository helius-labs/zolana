#[path = "../tests/common/mod.rs"]
mod common;

use std::hint::black_box;

use common::{build_transfer, keypair_from_index, unique31, unique_nullifier, TransferSpec};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::serialization::anonymous::{
    AnonymousRecipient, AnonymousSenderBundle, AnonymousSenderEncode,
};
use zolana_transaction::serialization::split::{Split, SplitEncode};
use zolana_transaction::{
    AssetRegistry, Data, DecodeCx, OwnerCx, Utxo, UtxoSerialization, SOL_MINT,
};

const SENDER_SLOT_COUNT: usize = 2;

fn sample_utxo(owner: &ShieldedKeypair, counter: &mut u64) -> Utxo {
    Utxo {
        owner: owner.signing_pubkey(),
        asset: SOL_MINT,
        amount: 100,
        blinding: unique31(counter, 0xBB),
        zone_program_id: None,
        data: Data::default(),
    }
}

fn sender_bundle_body(recipient_count: u16) -> (ShieldedKeypair, Vec<u8>, Option<[u8; 32]>) {
    let assets = AssetRegistry::default();
    let alice = keypair_from_index(0);
    let recipients: Vec<ShieldedKeypair> = (1..=recipient_count).map(keypair_from_index).collect();
    let mut counter = 0u64;
    let first_nullifier = unique_nullifier(&mut counter);

    let tx_key = alice
        .viewing_key
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap();
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&first_nullifier[..16]);
    let blinding_seed = unique31(&mut counter, 0xCC);

    let change = vec![Utxo {
        owner: alice.signing_pubkey(),
        asset: SOL_MINT,
        amount: 50,
        blinding: blinding_seed,
        zone_program_id: None,
        data: Data::default(),
    }];

    let owner_cx = OwnerCx {
        owner: alice.signing_pubkey(),
        assets: &assets,
        zone_program_id: None,
    };
    let cx = AnonymousSenderEncode {
        tx: tx_key,
        self_pubkey: alice.viewing_pubkey(),
        salt,
        slot_index: 0,
        blinding_seed,
        recipient_viewing_pks: recipients.iter().map(|r| r.viewing_pubkey()).collect(),
    };
    let plaintext = AnonymousSenderBundle::from_utxos(&change, &owner_cx, &cx).unwrap();
    let bytes = AnonymousSenderBundle::serialize(&plaintext).unwrap();
    let body = AnonymousSenderBundle::encrypt(&bytes, &cx).unwrap();
    (alice, body, Some(first_nullifier))
}

fn primitives(c: &mut Criterion) {
    let alice = keypair_from_index(0);
    let bob = keypair_from_index(1);
    let bob_viewing = bob.viewing_pubkey();
    let mut counter = 0u64;
    let first_nullifier = unique_nullifier(&mut counter);
    let utxo = sample_utxo(&alice, &mut counter);
    let nullifier_pk = alice.nullifier_key.pubkey().unwrap();
    let utxo_hash = utxo.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32]).unwrap();

    let mut group = c.benchmark_group("primitives");
    group.bench_function("ecdh", |b| {
        b.iter(|| alice.viewing_key.ecdh(black_box(&bob_viewing)).unwrap())
    });
    group.bench_function("recipient_shared_view_tag", |b| {
        b.iter(|| {
            alice
                .get_recipient_shared_view_tag(black_box(&bob_viewing), 1_000)
                .unwrap()
        })
    });
    group.bench_function("send_shared_view_tag", |b| {
        b.iter(|| {
            alice
                .get_send_shared_view_tag(black_box(&bob_viewing), 1_000)
                .unwrap()
        })
    });
    group.bench_function("sender_view_tag", |b| {
        b.iter(|| alice.get_sender_view_tag(black_box(1_000)).unwrap())
    });
    group.bench_function("recipient_request_view_tag", |b| {
        b.iter(|| {
            alice
                .get_recipient_request_view_tag(black_box(1_000))
                .unwrap()
        })
    });
    group.bench_function("transaction_viewing_key", |b| {
        b.iter(|| {
            alice
                .get_transaction_viewing_key(black_box(&first_nullifier))
                .unwrap()
        })
    });
    group.bench_function("utxo_hash", |b| {
        b.iter(|| {
            utxo.hash(black_box(&nullifier_pk), &[0u8; 32], &[0u8; 32])
                .unwrap()
        })
    });
    group.bench_function("nullifier", |b| {
        b.iter(|| {
            utxo.nullifier(black_box(&utxo_hash), &alice.nullifier_key)
                .unwrap()
        })
    });
    group.finish();
}

fn decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt");
    for recipient_count in [1u16, 2, 4, 8] {
        let (alice, body, first_nullifier) = sender_bundle_body(recipient_count);
        let mut salt = [0u8; 16];
        if let Some(nullifier) = first_nullifier {
            salt.copy_from_slice(&nullifier[..16]);
        }
        let tx_viewing_pk = alice
            .viewing_key
            .get_transaction_viewing_key(&first_nullifier.unwrap())
            .unwrap()
            .pubkey();
        group.bench_with_input(
            BenchmarkId::new("decrypt_transfer", recipient_count),
            &recipient_count,
            |b, _| {
                b.iter(|| {
                    let cx = DecodeCx {
                        viewing_key: &alice.viewing_key,
                        tx_viewing_pk: Some(tx_viewing_pk),
                        salt: Some(salt),
                        slot_index: 0,
                        first_nullifier,
                    };
                    AnonymousSenderBundle::decode(black_box(&body), &cx).unwrap()
                })
            },
        );
    }

    let assets = AssetRegistry::default();
    let alice = keypair_from_index(0);
    let bob = keypair_from_index(1);
    let mut counter = 0u64;
    let (tx, _, _) = build_transfer(
        &assets,
        TransferSpec {
            sender: &bob,
            recipient: &alice,
            amount: 100,
            slot_tag: alice.recipient_bootstrap_view_tag(),
            sender_view_tag: bob.get_sender_view_tag(0).unwrap(),
            first_nullifier: unique_nullifier(&mut counter),
            change_amount: 0,
            blinding: unique31(&mut counter, 0xBB),
            blinding_seed: unique31(&mut counter, 0xCC),
        },
    );
    let recipient_slot = tx
        .output_slots
        .get(SENDER_SLOT_COUNT)
        .expect("recipient slot");
    let recipient_body = match recipient_slot.output_data().expect("recipient output data") {
        zolana_event::OutputData::Encrypted(blob)
        | zolana_event::OutputData::VerifiablyEncrypted(blob)
        | zolana_event::OutputData::Plaintext(blob) => blob
            .get(1..)
            .map(<[u8]>::to_vec)
            .expect("recipient ciphertext body"),
    };
    group.bench_function("decrypt_transfer_recipient", |b| {
        b.iter(|| {
            let cx = DecodeCx::for_slot(&alice.viewing_key, &tx, SENDER_SLOT_COUNT as u32);
            AnonymousRecipient::decode(black_box(&recipient_body), &cx).unwrap()
        })
    });

    let split_nullifier = unique_nullifier(&mut counter);
    let split_tx_key = alice
        .viewing_key
        .get_transaction_viewing_key(&split_nullifier)
        .unwrap();
    let split_tx_viewing_pk = split_tx_key.pubkey();
    let mut split_salt = [0u8; 16];
    split_salt.copy_from_slice(&split_nullifier[..16]);
    let split_blinding_seed = unique31(&mut counter, 0xCC);
    let split_outputs: Vec<Utxo> = (0..8u8)
        .map(|i| Utxo {
            owner: alice.signing_pubkey(),
            asset: SOL_MINT,
            amount: 100,
            blinding: zolana_transaction::derive_blinding(&split_blinding_seed, i),
            zone_program_id: None,
            data: Data::default(),
        })
        .collect();
    let split_owner_cx = OwnerCx {
        owner: alice.signing_pubkey(),
        assets: &assets,
        zone_program_id: None,
    };
    let split_cx = SplitEncode {
        tx: split_tx_key,
        recipient_pubkey: alice.viewing_pubkey(),
        salt: split_salt,
        slot_index: 0,
        blinding_seed: split_blinding_seed,
    };
    let split_plaintext = Split::from_utxos(&split_outputs, &split_owner_cx, &split_cx).unwrap();
    let split_bytes = Split::serialize(&split_plaintext).unwrap();
    let split_body = Split::encrypt(&split_bytes, &split_cx).unwrap();
    group.bench_function("decrypt_split", |b| {
        b.iter(|| {
            let cx = DecodeCx {
                viewing_key: &alice.viewing_key,
                tx_viewing_pk: Some(split_tx_viewing_pk),
                salt: Some(split_salt),
                slot_index: 0,
                first_nullifier: Some(split_nullifier),
            };
            Split::decode(black_box(&split_body), &cx).unwrap()
        })
    });
    group.finish();
}

criterion_group!(benches, primitives, decrypt);
criterion_main!(benches);
