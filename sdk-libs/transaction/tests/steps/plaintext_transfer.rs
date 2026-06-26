use cucumber::{then, when};
use zolana_keypair::{constants::BLINDING_LEN, PublicKey, ShieldedKeypair};
use zolana_transaction::{
    data::{Data, DataRecord},
    serialization::plaintext::{
        TransferPlaintextRecipient, TransferPlaintextSender, TransferPlaintextSplChange,
        TransferPlaintextUtxos,
    },
    utxo::derive_blinding,
    Address, AssetRegistry, TransactionError, TRANSFER_PLAINTEXT,
};

use crate::TransactionWorld;

const SEED: [u8; BLINDING_LEN] = [1u8; BLINDING_LEN];

fn registry() -> AssetRegistry {
    AssetRegistry::new([(2u64, Address::new_from_array([9u8; 32]))]).unwrap()
}

fn owner_tag(kp: &ShieldedKeypair) -> [u8; 32] {
    kp.signing_pubkey().as_p256().unwrap().x()
}

#[when(expr = "{string} builds a plaintext transfer to {string} and {string}")]
fn build(world: &mut TransactionWorld, sender: String, r1: String, r2: String) {
    let utxos = TransferPlaintextUtxos {
        type_prefix: TRANSFER_PLAINTEXT,
        blinding_seed: SEED,
        sender: Some(TransferPlaintextSender {
            owner_pubkey: world.kp(&sender).signing_pubkey(),
            spl: Some(TransferPlaintextSplChange {
                amount: 100,
                asset_id: 2,
            }),
            sol_amount: Some(50),
            spl_data: Data::default(),
            sol_data: Data::default(),
        }),
        recipient_slots: vec![
            TransferPlaintextRecipient {
                owner_pubkey: world.kp(&r1).signing_pubkey(),
                asset_id: 2,
                amount: 40,
                data: Data::default(),
            },
            TransferPlaintextRecipient {
                owner_pubkey: world.kp(&r2).signing_pubkey(),
                asset_id: 1,
                amount: 10,
                data: Data::default(),
            },
        ],
    };
    world.sender_name = Some(sender);
    world.recipient_names = vec![r1, r2];
    world.plaintext_transfer = Some(utxos);
}

#[then(expr = "the plaintext transfer blob deserializes back unchanged")]
fn round_trips(world: &mut TransactionWorld) {
    let blob = world.plaintext_transfer.as_ref().unwrap();
    let bytes = blob.serialize().unwrap();
    assert_eq!(&TransferPlaintextUtxos::deserialize(&bytes).unwrap(), blob);
}

#[then(expr = "the plaintext transfer derives four sequential output blindings")]
fn sequential_blindings(world: &mut TransactionWorld) {
    let outputs = world
        .plaintext_transfer
        .clone()
        .unwrap()
        .into_utxos(&registry(), None)
        .unwrap();
    assert_eq!(outputs.len(), 4);
    for (i, utxo) in outputs.iter().enumerate() {
        let position = u8::try_from(i).unwrap();
        assert_eq!(utxo.blinding, derive_blinding(&SEED, position));
    }
}

#[then(expr = "the plaintext sender change is indexed by {string}")]
fn sender_indexed(world: &mut TransactionWorld, name: String) {
    let indexed = world
        .plaintext_transfer
        .clone()
        .unwrap()
        .into_indexed_utxos(&registry(), None)
        .unwrap();
    let tag = owner_tag(world.kp(&name));
    assert_eq!(indexed.first().expect("spl change present").0, tag);
    assert_eq!(indexed.get(1).expect("sol change present").0, tag);
}

#[then(expr = "plaintext recipient output {int} is indexed by {string}")]
fn recipient_indexed(world: &mut TransactionWorld, idx: usize, name: String) {
    let indexed = world
        .plaintext_transfer
        .clone()
        .unwrap()
        .into_indexed_utxos(&registry(), None)
        .unwrap();
    let tag = owner_tag(world.kp(&name));
    let entry = indexed.get(2 + idx).expect("recipient output present");
    assert_eq!(entry.0, tag);
}

#[then(expr = "the plaintext transfer outputs have amounts {int}, {int}, {int}, {int}")]
fn output_amounts(world: &mut TransactionWorld, a: u64, b: u64, c: u64, d: u64) {
    let outputs = world
        .plaintext_transfer
        .clone()
        .unwrap()
        .into_utxos(&registry(), None)
        .unwrap();
    let amounts: Vec<u64> = outputs.iter().map(|utxo| utxo.amount).collect();
    assert_eq!(amounts, vec![a, b, c, d]);
}

#[then(expr = "the plaintext transfer rejects a wrong discriminator")]
fn rejects_bad_discriminator(world: &mut TransactionWorld) {
    let mut blob = world.plaintext_transfer.clone().unwrap();
    let bad = TRANSFER_PLAINTEXT.wrapping_add(1);
    blob.type_prefix = bad;
    let bytes = blob.serialize().unwrap();
    assert_eq!(
        TransferPlaintextUtxos::deserialize(&bytes).unwrap_err(),
        TransactionError::BadDiscriminator(bad)
    );
}

#[then(expr = "plaintext sender data without an output is rejected for {string}")]
fn sender_data_without_output(world: &mut TransactionWorld, name: String) {
    let utxos = TransferPlaintextUtxos {
        type_prefix: TRANSFER_PLAINTEXT,
        blinding_seed: SEED,
        sender: Some(TransferPlaintextSender {
            owner_pubkey: world.kp(&name).signing_pubkey(),
            spl: None,
            sol_amount: Some(50),
            spl_data: Data::new(vec![DataRecord::ProgramData(vec![1, 2, 3])]),
            sol_data: Data::default(),
        }),
        recipient_slots: vec![],
    };
    assert_eq!(
        utxos.into_utxos(&registry(), None).unwrap_err(),
        TransactionError::DataWithoutOutput
    );
}

#[then(expr = "an ed25519 plaintext recipient is indexed by its raw key")]
fn ed25519_recipient_indexed(_world: &mut TransactionWorld) {
    let raw = [7u8; 32];
    let utxos = TransferPlaintextUtxos {
        type_prefix: TRANSFER_PLAINTEXT,
        blinding_seed: SEED,
        sender: None,
        recipient_slots: vec![TransferPlaintextRecipient {
            owner_pubkey: PublicKey::from_ed25519(&raw),
            asset_id: 2,
            amount: 5,
            data: Data::default(),
        }],
    };
    let indexed = utxos.into_indexed_utxos(&registry(), None).unwrap();
    let entry = indexed.first().expect("recipient output present");
    assert_eq!(entry.0, raw);
    assert_eq!(entry.1.blinding, derive_blinding(&SEED, 2));
}
