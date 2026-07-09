use cucumber::then;
use rings_keypair::{
    constants::BLINDING_LEN,
    hash::{hash_field, owner_hash, poseidon},
};
use rings_transaction::{
    data::Data,
    utxo::{utxo_hash, Utxo, UTXO_DOMAIN},
    Address,
};

use crate::TransactionWorld;

fn fe<const N: usize>(bytes: [u8; N]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - N..].copy_from_slice(&bytes);
    out
}

fn bare_utxo(world: &TransactionWorld, name: &str) -> Utxo {
    Utxo {
        owner: world.kp(name).signing_pubkey(),
        asset: Address::default(),
        amount: 1000,
        blinding: [3u8; BLINDING_LEN],
        zone_program_id: None,
        data: Data::default(),
    }
}

#[then(expr = "the utxo hash for {string} is deterministic and changes with the amount")]
fn utxo_hash_props(world: &mut TransactionWorld, name: String) {
    let npk = world
        .kp(&name)
        .nullifier_key
        .pubkey()
        .expect("nullifier public key");
    let mut utxo = bare_utxo(world, &name);
    let first = utxo
        .hash(&npk, &[0u8; 32], &[0u8; 32])
        .expect("first UTXO hash");
    let repeated = utxo
        .hash(&npk, &[0u8; 32], &[0u8; 32])
        .expect("repeated UTXO hash");
    assert_eq!(first, repeated);
    utxo.amount += 1;
    let changed = utxo
        .hash(&npk, &[0u8; 32], &[0u8; 32])
        .expect("changed UTXO hash");
    assert_ne!(first, changed);
}

#[then(expr = "the utxo hash for {string} nests the owner commitment per spec")]
fn utxo_hash_nesting(world: &mut TransactionWorld, name: String) {
    let npk = world
        .kp(&name)
        .nullifier_key
        .pubkey()
        .expect("nullifier public key");
    let zone_program_id = Address::new_from_array([7u8; 32]);
    let mut utxo = bare_utxo(world, &name);
    utxo.zone_program_id = Some(zone_program_id);
    let data_hash = [4u8; 32];
    let zone_data_hash = [5u8; 32];
    let actual = utxo
        .hash(&npk, &data_hash, &zone_data_hash)
        .expect("UTXO hash");

    let owner = owner_hash(&utxo.owner, &npk).expect("owner hash");
    let owner_utxo_hash = poseidon(&[&owner, &fe(utxo.blinding)]).expect("owner UTXO hash");
    let asset = hash_field(utxo.asset.as_array()).expect("asset field");
    let zone_program_id_field =
        hash_field(zone_program_id.as_array()).expect("zone program id field");
    let zone_hash = poseidon(&[&zone_data_hash, &zone_program_id_field]).expect("zone hash");
    let expected = poseidon(&[
        &fe(UTXO_DOMAIN.to_be_bytes()),
        &asset,
        &fe(utxo.amount.to_be_bytes()),
        &data_hash,
        &zone_hash,
        &owner_utxo_hash,
    ])
    .expect("expected UTXO hash");
    assert_eq!(actual, expected);
    let from_helper = utxo_hash(
        utxo.asset,
        utxo.amount,
        &data_hash,
        &zone_data_hash,
        utxo.zone_program_id,
        &owner_utxo_hash,
    )
    .expect("UTXO hash helper");
    assert_eq!(actual, from_helper);
}

#[then(expr = "the utxo nullifier for {string} matches the keypair nullifier")]
fn utxo_nullifier(world: &mut TransactionWorld, name: String) {
    let kp = world.kp(&name);
    let npk = kp.nullifier_key.pubkey().expect("nullifier public key");
    let utxo = bare_utxo(world, &name);
    let utxo_hash = utxo.hash(&npk, &[0u8; 32], &[0u8; 32]).expect("UTXO hash");
    let from_utxo = utxo
        .nullifier(&utxo_hash, &kp.nullifier_key)
        .expect("UTXO nullifier");
    let from_keypair = kp
        .nullifier(&utxo_hash, &utxo.blinding)
        .expect("keypair nullifier");
    assert_eq!(from_utxo, from_keypair);
}
