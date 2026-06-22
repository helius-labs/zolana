use std::collections::HashSet;

use cucumber::{then, when};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_transaction::{
    asset::AssetRegistry,
    data::{Data, DataRecord},
    split::SplitBundlePlaintext,
    Address, TransactionEncryption, TransactionError,
};

use crate::TransactionWorld;

#[when(expr = "{string} splits into {int} outputs of {int}")]
fn build_split(world: &mut TransactionWorld, owner: String, num_outputs: u8, amount: u64) {
    let bundle = SplitBundlePlaintext {
        owner_pubkey: world.kp(&owner).signing_pubkey(),
        num_outputs,
        asset_id: 2,
        asset_amount: amount,
        blinding_seed: [3u8; BLINDING_LEN],
        data: Data::default(),
    };
    let blob = world
        .kp(&owner)
        .viewing_key
        .encrypt_split(&[11u8; 32], &bundle)
        .unwrap();
    world.sender_name = Some(owner);
    world.split_bundle = Some(bundle);
    world.split_blob = Some(blob);
}

#[then(expr = "the split blob deserializes back unchanged")]
fn split_round_trips(world: &mut TransactionWorld) {
    let blob = world.split_blob.as_ref().unwrap();
    let bytes = blob.serialize().unwrap();
    let parsed = zolana_transaction::split::SplitEncryptedUtxos::deserialize(&bytes).unwrap();
    assert_eq!(&parsed, blob);
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
        data: Data::new(vec![DataRecord::ProgramData(vec![1])]),
    };
    assert_eq!(
        bundle.into_utxos(&registry, None).unwrap_err(),
        TransactionError::DataWithoutOutput
    );
}

#[then(expr = "{string} decrypts the split and reads {int} outputs of {int}")]
fn split_decrypt(world: &mut TransactionWorld, owner: String, count: u8, amount: u64) {
    let blob = world.split_blob.as_ref().unwrap();
    let bundle = world.kp(&owner).viewing_key.decrypt_split(blob).unwrap();
    assert_eq!(bundle.num_outputs, count);
    assert_eq!(bundle.asset_amount, amount);
}
