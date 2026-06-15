use cucumber::then;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::hash::{hash_field, owner_hash, poseidon};
use zolana_transaction::data::Data;
use zolana_transaction::utxo::{utxo_commitment, Utxo, UTXO_DOMAIN};
use zolana_transaction::Address;

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
    let npk = world.kp(&name).nullifier_key.pubkey().unwrap();
    let mut utxo = bare_utxo(world, &name);
    let first = utxo.hash(&npk, &[0u8; 32], &[0u8; 32]).unwrap();
    assert_eq!(first, utxo.hash(&npk, &[0u8; 32], &[0u8; 32]).unwrap());
    utxo.amount += 1;
    assert_ne!(first, utxo.hash(&npk, &[0u8; 32], &[0u8; 32]).unwrap());
}

#[then(expr = "the utxo hash for {string} nests the owner commitment per spec")]
fn utxo_hash_nesting(world: &mut TransactionWorld, name: String) {
    let npk = world.kp(&name).nullifier_key.pubkey().unwrap();
    let utxo = bare_utxo(world, &name);
    let program_data_hash = [4u8; 32];
    let zone_data_hash = [5u8; 32];
    let actual = utxo
        .hash(&npk, &program_data_hash, &zone_data_hash)
        .unwrap();

    let owner = owner_hash(&utxo.owner, &npk).unwrap();
    let owner_utxo_hash = poseidon(&[&owner, &fe(utxo.blinding)]).unwrap();
    let asset = hash_field(utxo.asset.as_array()).unwrap();
    let zone_program_id = [0u8; 32];
    let expected = poseidon(&[
        &fe(UTXO_DOMAIN.to_be_bytes()),
        &asset,
        &fe(utxo.amount.to_be_bytes()),
        &program_data_hash,
        &zone_data_hash,
        &zone_program_id,
        &owner_utxo_hash,
    ])
    .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        actual,
        utxo_commitment(
            utxo.asset,
            utxo.amount,
            &program_data_hash,
            &zone_data_hash,
            utxo.zone_program_id,
            &owner_utxo_hash,
        )
        .unwrap()
    );
}

#[then(expr = "the utxo nullifier for {string} matches the keypair nullifier")]
fn utxo_nullifier(world: &mut TransactionWorld, name: String) {
    let kp = world.kp(&name);
    let npk = kp.nullifier_key.pubkey().unwrap();
    let utxo = bare_utxo(world, &name);
    let utxo_hash = utxo.hash(&npk, &[0u8; 32], &[0u8; 32]).unwrap();
    let from_utxo = utxo.nullifier(&utxo_hash, &kp.nullifier_key).unwrap();
    let from_keypair = kp.nullifier(&utxo_hash, &utxo.blinding).unwrap();
    assert_eq!(from_utxo, from_keypair);
}
