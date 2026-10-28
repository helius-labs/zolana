#[path = "../tests/transfer_fixtures/mod.rs"]
mod transfer_fixtures;

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use spr_keypair::ShieldedKeypair;
use spr_transaction::{
    serialization::confidential::Confidential, AssetRegistry, Data, DecodeCx, Mint, Utxo,
    UtxoSerialization,
};
use transfer_fixtures::{
    build_unified_transfer, keypair_from_index, unique31, unique_nullifier, UnifiedTransferSpec,
};

const RECIPIENT_SLOT_INDEX: usize = 2;

fn sample_utxo(owner: &ShieldedKeypair, counter: &mut u64) -> Utxo {
    Utxo {
        owner: owner.signing_pubkey(),
        asset: Mint::SOL,
        amount: 100,
        blinding: unique31(counter, 0xBB),
        ring_program_id: None,
        data: Data::default(),
    }
}

fn primitives(c: &mut Criterion) {
    let alice = keypair_from_index(0);
    let bob = keypair_from_index(1);
    let bob_viewing = bob.viewing_pubkey();
    let mut counter = 0u64;
    let first_nullifier = unique_nullifier(&mut counter);
    let utxo = sample_utxo(&alice, &mut counter);
    let nullifier_pk = alice.nullifier_key.pubkey().unwrap();
    let utxo_hash = utxo
        .hash(
            &nullifier_pk,
            &[0u8; 32],
            &[0u8; 32],
            transfer_fixtures::TEST_TREE_ID,
        )
        .unwrap();

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
            utxo.hash(
                black_box(&nullifier_pk),
                &[0u8; 32],
                &[0u8; 32],
                transfer_fixtures::TEST_TREE_ID,
            )
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
    let assets = AssetRegistry::default();
    let alice = keypair_from_index(0);
    let bob = keypair_from_index(1);
    let mut counter = 0u64;
    let (tx, _, _) = build_unified_transfer(
        &assets,
        UnifiedTransferSpec {
            sender: &bob,
            recipient: &alice,
            amount: 100,
            first_nullifier: unique_nullifier(&mut counter),
            change_amount: 0,
            blinding: unique31(&mut counter, 0xBB),
            change_blinding: unique31(&mut counter, 0xCC),
        },
    );
    let recipient_slot = tx
        .output_slots
        .get(RECIPIENT_SLOT_INDEX)
        .expect("recipient slot");
    let recipient_body = match recipient_slot.output_data().expect("recipient output data") {
        spr_event::OutputDataEncoding::Encrypted(blob)
        | spr_event::OutputDataEncoding::VerifiablyEncrypted(blob)
        | spr_event::OutputDataEncoding::Plaintext(blob) => blob
            .get(1..)
            .map(<[u8]>::to_vec)
            .expect("recipient ciphertext body"),
    };
    group.bench_function("decrypt_transfer_recipient", |b| {
        b.iter(|| {
            let cx = DecodeCx::for_slot(&alice.viewing_key, &tx, RECIPIENT_SLOT_INDEX as u32);
            Confidential::decode(black_box(&recipient_body), &cx).unwrap()
        })
    });

    let mut split_input = sample_utxo(&alice, &mut counter);
    split_input.amount = 800;
    let (split_tx, _) =
        transfer_fixtures::split_transaction(&alice, &split_input, 8, unique31(&mut counter, 0xCC));
    let bodies: Vec<_> = split_tx
        .output_slots
        .iter()
        .map(|slot| {
            let spr_event::OutputDataEncoding::Encrypted(blob) = slot.output_data().unwrap() else {
                panic!("encrypted output expected")
            };
            blob.get(1..).unwrap().to_vec()
        })
        .collect();
    group.bench_function("decrypt_self_outputs", |b| {
        b.iter(|| {
            bodies
                .iter()
                .enumerate()
                .map(|(index, body)| {
                    let cx = DecodeCx::for_slot(&alice.viewing_key, &split_tx, index as u32);
                    Confidential::decode(black_box(body), &cx).unwrap()
                })
                .collect::<Vec<_>>()
        })
    });
    group.finish();
}

criterion_group!(benches, primitives, decrypt);
criterion_main!(benches);
