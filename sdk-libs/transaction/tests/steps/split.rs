use std::collections::HashSet;

use borsh::BorshDeserialize;
use cucumber::{then, when};
use zolana_keypair::{constants::BLINDING_LEN, viewing_key::random_salt};
use zolana_transaction::{
    data::{Data, DataRecord},
    serialization::{
        split::{Split, SplitBundlePlaintext, SplitEncode},
        DecodeCx, OwnerCx, UtxoSerialization,
    },
    Address, AssetRegistry, OutputContext, OutputSlot, ShieldedTransaction, TransactionError,
};

use crate::TransactionWorld;

const SPLIT_ASSET_ID: u64 = 2;
const SPLIT_BLINDING_SEED: [u8; BLINDING_LEN] = [3u8; BLINDING_LEN];

fn registry() -> AssetRegistry {
    AssetRegistry::new([(SPLIT_ASSET_ID, Address::new_from_array([5u8; 32]))]).unwrap()
}

fn build_split_tx(
    owner_kp: &zolana_keypair::ShieldedKeypair,
    bundle: &SplitBundlePlaintext,
    first_nullifier: [u8; 32],
) -> ShieldedTransaction {
    let registry = registry();
    let salt = random_salt();
    let tx = owner_kp
        .viewing_key
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap();
    let tx_viewing_pk = tx.pubkey();
    let utxos = bundle.clone().into_utxos(&registry, None).unwrap();
    let owner_cx = OwnerCx {
        owner: owner_kp.signing_pubkey(),
        assets: &registry,
        zone_program_id: None,
    };
    let view_tag = owner_kp.get_sender_view_tag(0).unwrap();
    let ciphertext = Split::encode(
        &utxos,
        &owner_cx,
        view_tag,
        &SplitEncode {
            tx: tx.clone(),
            recipient_pubkey: owner_kp.viewing_pubkey(),
            salt,
            slot_index: 0,
            blinding_seed: SPLIT_BLINDING_SEED,
        },
    )
    .unwrap();

    ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some(salt),
        output_slots: vec![OutputSlot {
            view_tag: ciphertext.view_tag,
            output_context: OutputContext {
                hash: [0u8; 32],
                tree: Default::default(),
                leaf_index: 0,
            },
            payload: ciphertext.data,
        }],
        messages: Vec::new(),
        nullifiers: vec![first_nullifier],
        proofless: false,
    }
}

fn decode_split(
    world: &TransactionWorld,
    owner: &str,
) -> Result<SplitBundlePlaintext, TransactionError> {
    let tx = world.split_tx.as_ref().unwrap();
    let payload = &tx.output_slots.first().expect("split slot").payload;
    let output_data = zolana_event::OutputDataEncoding::try_from_slice(payload).unwrap();
    let blob = match output_data {
        zolana_event::OutputDataEncoding::Encrypted(blob)
        | zolana_event::OutputDataEncoding::VerifiablyEncrypted(blob)
        | zolana_event::OutputDataEncoding::Plaintext(blob) => blob,
    };
    let body = blob.get(1..).expect("scheme byte");
    let cx = DecodeCx::for_slot(&world.kp(owner).viewing_key, tx, 0);
    Split::decode(body, &cx)
}

#[when(expr = "{string} splits into {int} outputs of {int}")]
fn build_split(world: &mut TransactionWorld, owner: String, num_outputs: u8, amount: u64) {
    let bundle = SplitBundlePlaintext {
        owner_pubkey: world.kp(&owner).signing_pubkey(),
        num_outputs,
        asset_id: SPLIT_ASSET_ID,
        asset_amount: amount,
        blinding_seed: SPLIT_BLINDING_SEED,
        data: Data::default(),
    };
    let owner_kp = world.fresh_keypair(&owner);
    let tx = build_split_tx(&owner_kp, &bundle, [11u8; 32]);
    world.sender_name = Some(owner);
    world.split_bundle = Some(bundle);
    world.split_tx = Some(tx);
}

#[then(expr = "the split blob deserializes back unchanged")]
fn split_round_trips(world: &mut TransactionWorld) {
    let tx = world.split_tx.as_ref().unwrap();
    let payload = &tx.output_slots.first().expect("split slot").payload;
    let parsed = zolana_event::OutputDataEncoding::try_from_slice(payload).unwrap();
    assert_eq!(&borsh::to_vec(&parsed).unwrap(), payload);
}

#[then(expr = "the split has {int} distinct output blindings")]
fn split_blindings(world: &mut TransactionWorld, count: usize) {
    let bundle = world.split_bundle.as_ref().unwrap();
    let blindings = bundle.output_blindings();
    assert_eq!(blindings.len(), count);
    let mut seen = HashSet::new();
    for blinding in blindings {
        assert!(seen.insert(blinding));
    }
}

#[then(expr = "split data with zero outputs is rejected for {string}")]
fn split_data_zero_outputs(world: &mut TransactionWorld, owner: String) {
    let registry = AssetRegistry::new([(2, Address::new_from_array([5u8; 32]))]).unwrap();
    let bundle = SplitBundlePlaintext {
        owner_pubkey: world.kp(&owner).signing_pubkey(),
        num_outputs: 0,
        asset_id: 2,
        asset_amount: 0,
        blinding_seed: [3u8; BLINDING_LEN],
        data: Data::new(vec![DataRecord::UtxoData(vec![1])]),
    };
    assert_eq!(
        bundle.into_utxos(&registry, None).unwrap_err(),
        TransactionError::DataWithoutOutput
    );
}

#[then(expr = "{string} decrypts the split and reads {int} outputs of {int}")]
fn split_decrypt(world: &mut TransactionWorld, owner: String, count: u8, amount: u64) {
    let bundle = decode_split(world, &owner).unwrap();
    assert_eq!(bundle.num_outputs, count);
    assert_eq!(bundle.asset_amount, amount);
}
