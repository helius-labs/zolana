#[path = "../tests/common/mod.rs"]
mod common;

use std::hint::black_box;

use common::{build_transfer, keypair_from_index, unique31, unique_nullifier, TransferSpec};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::split::SplitBundlePlaintext;
use zolana_transaction::transfer::{
    RecipientOutput, TransferEncryptedUtxos, TransferSenderPlaintext, SENDER_SLOT_COUNT,
};
use zolana_transaction::{
    AssetRegistry, Data, TransactionEncryption, Utxo, SOL_ASSET_ID, SOL_MINT,
};

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

fn transfer_blob(recipient_count: u16) -> (ShieldedKeypair, TransferEncryptedUtxos, [u8; 32]) {
    let assets = AssetRegistry::default();
    let alice = keypair_from_index(0);
    let recipients: Vec<ShieldedKeypair> = (1..=recipient_count).map(keypair_from_index).collect();
    let mut counter = 0u64;
    let first_nullifier = unique_nullifier(&mut counter);
    let outputs: Vec<RecipientOutput> = recipients
        .iter()
        .map(|recipient| {
            let utxo = sample_utxo(recipient, &mut counter);
            RecipientOutput {
                view_tag: recipient.recipient_bootstrap_view_tag(),
                plaintext: utxo
                    .to_recipient_plaintext(alice.viewing_pubkey(), &assets)
                    .unwrap(),
            }
        })
        .collect();
    let sender_plaintext = TransferSenderPlaintext {
        owner_pubkey: alice.signing_pubkey(),
        spl_asset_id: 0,
        spl_amount: 0,
        sol_amount: 50,
        blinding_seed: unique31(&mut counter, 0xCC),
        recipient_viewing_pks: recipients.iter().map(|r| r.viewing_pubkey()).collect(),
        spl_data: Data::default(),
        sol_data: Data::default(),
    };
    let blob = alice
        .viewing_key
        .encrypt_transfer(&first_nullifier, &sender_plaintext, &outputs)
        .unwrap();
    (alice, blob, first_nullifier)
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
        let (alice, blob, first_nullifier) = transfer_blob(recipient_count);
        group.bench_with_input(
            BenchmarkId::new("decrypt_transfer", recipient_count),
            &recipient_count,
            |b, _| {
                b.iter(|| {
                    alice
                        .viewing_key
                        .decrypt_transfer(black_box(&first_nullifier), black_box(&blob))
                        .unwrap()
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
    let recipient_blob = TransferEncryptedUtxos::from_output_ciphertexts(
        tx.tx_viewing_pk,
        tx.salt,
        &tx.output_slots,
        SENDER_SLOT_COUNT,
    )
    .unwrap();
    group.bench_function("decrypt_transfer_recipient", |b| {
        b.iter(|| {
            alice
                .viewing_key
                .decrypt_transfer_recipient(black_box(&recipient_blob), 0)
                .unwrap()
        })
    });

    let bundle = SplitBundlePlaintext {
        owner_pubkey: alice.signing_pubkey(),
        num_outputs: 8,
        asset_id: SOL_ASSET_ID,
        asset_amount: 100,
        blinding_seed: unique31(&mut counter, 0xCC),
        data: Data::default(),
    };
    let split_nullifier = unique_nullifier(&mut counter);
    let split_blob = alice
        .viewing_key
        .encrypt_split(&split_nullifier, &bundle)
        .unwrap();
    group.bench_function("decrypt_split", |b| {
        b.iter(|| {
            alice
                .viewing_key
                .decrypt_split(black_box(&split_blob))
                .unwrap()
        })
    });
    group.finish();
}

criterion_group!(benches, primitives, decrypt);
criterion_main!(benches);
