use cucumber::then;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_transaction::data::Data;
use zolana_transaction::utxo::Utxo;
use zolana_transaction::Address;

use crate::TransactionWorld;

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
