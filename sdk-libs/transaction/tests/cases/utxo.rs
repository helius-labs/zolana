use zolana_hasher::{hash_chain::create_hash_chain_4_from_slice, primitives::hash_bytes};
use zolana_keypair::hash::{owner_hash, poseidon};
use zolana_transaction::{
    data::Data,
    instructions::transact::PrivateTxHash,
    utxo::{ProofInputUtxo, Utxo, UTXO_DOMAIN},
    Address,
};

use crate::{cases::TEST_TREE_ID, TransactionWorld};

/// A non-zero tree id, so a preimage that dropped the id would not still match.
const NESTING_TREE_ID: u16 = 7;

pub(crate) fn fe<const N: usize>(bytes: [u8; N]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - N..].copy_from_slice(&bytes);
    out
}

pub(crate) fn bare_utxo(world: &TransactionWorld, name: &str) -> Utxo {
    Utxo {
        owner: world.kp(name).signing_pubkey(),
        asset: Address::default(),
        amount: 1000,
        blinding: [3u8; 32],
        ring_program_id: None,
        data: Data::default(),
    }
}

pub(crate) fn utxo_hash_props(world: &mut TransactionWorld, name: String) {
    let npk = world
        .kp(&name)
        .nullifier_key
        .pubkey()
        .expect("nullifier public key");
    let mut utxo = bare_utxo(world, &name);
    let first = utxo
        .hash(&npk, &[0u8; 32], &[0u8; 32], TEST_TREE_ID)
        .expect("first UTXO hash");
    let repeated = utxo
        .hash(&npk, &[0u8; 32], &[0u8; 32], TEST_TREE_ID)
        .expect("repeated UTXO hash");
    assert_eq!(first, repeated);
    // The same body in another tree is another commitment.
    let elsewhere = utxo
        .hash(&npk, &[0u8; 32], &[0u8; 32], NESTING_TREE_ID)
        .expect("other-tree UTXO hash");
    assert_ne!(first, elsewhere);
    utxo.amount += 1;
    let changed = utxo
        .hash(&npk, &[0u8; 32], &[0u8; 32], TEST_TREE_ID)
        .expect("changed UTXO hash");
    assert_ne!(first, changed);
}

pub(crate) fn utxo_hash_nesting(world: &mut TransactionWorld, name: String) {
    let npk = world
        .kp(&name)
        .nullifier_key
        .pubkey()
        .expect("nullifier public key");
    let ring_program_id = Address::new_from_array([7u8; 32]);
    let mut utxo = bare_utxo(world, &name);
    utxo.ring_program_id = Some(ring_program_id);
    let data_hash = [4u8; 32];
    let ring_data_hash = [5u8; 32];
    let actual = utxo
        .hash(&npk, &data_hash, &ring_data_hash, NESTING_TREE_ID)
        .expect("UTXO hash");

    let owner = owner_hash(&utxo.owner, &npk).expect("owner hash");
    let owner_utxo_hash = poseidon(&[&owner, &fe(utxo.blinding)]).expect("owner UTXO hash");
    let asset = hash_bytes(utxo.asset.as_array()).expect("asset field");
    let ring_program_id_field =
        hash_bytes(ring_program_id.as_array()).expect("ring program id field");
    let ring_hash = poseidon(&[&ring_data_hash, &ring_program_id_field]).expect("ring hash");
    // Poseidon(domain, tree_id, asset, amount, data_hash, ring_hash,
    // owner_utxo_hash) -- the raw u16 tree id is the second element.
    let expected = poseidon(&[
        &fe(UTXO_DOMAIN.to_be_bytes()),
        &fe(NESTING_TREE_ID.to_be_bytes()),
        &asset,
        &fe(utxo.amount.to_be_bytes()),
        &data_hash,
        &ring_hash,
        &owner_utxo_hash,
    ])
    .expect("expected UTXO hash");
    assert_eq!(actual, expected);
    let from_helper = ProofInputUtxo::new(
        owner,
        &utxo.asset,
        utxo.amount,
        &utxo.blinding,
        NESTING_TREE_ID,
    )
    .expect("proof input utxo")
    .with_data_hash(data_hash)
    .with_ring(ring_data_hash, &utxo.ring_program_id)
    .expect("ring fields")
    .hash()
    .expect("UTXO hash helper");
    assert_eq!(actual, from_helper);
}

/// `private_tx_hash = Poseidon(hash_chain_4(inputs), hash_chain_4(outputs),
/// hash_chain_4(addresses), external_data_hash, private_tx_blinding)`. The
/// blinding is the fifth element and is never published, so an observer cannot
/// test candidate input commitments against the published hash.
pub(crate) fn private_tx_hash_is_blinded() {
    let input_hashes = [fe([1u8; 31]), fe([2u8; 31])];
    let output_hashes = [fe([3u8; 31]), fe([4u8; 31]), fe([5u8; 31])];
    let external_data_hash = fe([6u8; 31]);
    let blinding = fe([7u8; 31]);

    let actual = PrivateTxHash::new(
        &input_hashes,
        &output_hashes,
        &external_data_hash,
        &blinding,
    )
    .hash()
    .expect("private tx hash");

    // Address slots are unused here, so the address chain folds the same number
    // of zero elements as there are inputs.
    let expected = poseidon(&[
        &create_hash_chain_4_from_slice(&input_hashes).expect("input chain"),
        &create_hash_chain_4_from_slice(&output_hashes).expect("output chain"),
        &create_hash_chain_4_from_slice(&[[0u8; 32]; 2]).expect("address chain"),
        &external_data_hash,
        &blinding,
    ])
    .expect("expected private tx hash");
    assert_eq!(actual, expected);

    let unblinded = PrivateTxHash::new(
        &input_hashes,
        &output_hashes,
        &external_data_hash,
        &[0u8; 32],
    )
    .hash()
    .expect("unblinded private tx hash");
    assert_ne!(actual, unblinded);
}

pub(crate) fn utxo_nullifier(world: &mut TransactionWorld, name: String) {
    let kp = world.kp(&name);
    let npk = kp.nullifier_key.pubkey().expect("nullifier public key");
    let utxo = bare_utxo(world, &name);
    let utxo_hash = utxo
        .hash(&npk, &[0u8; 32], &[0u8; 32], TEST_TREE_ID)
        .expect("UTXO hash");
    let from_utxo = utxo
        .nullifier(&utxo_hash, &kp.nullifier_key)
        .expect("UTXO nullifier");
    let from_keypair = kp
        .nullifier(&utxo_hash, &utxo.blinding)
        .expect("keypair nullifier");
    assert_eq!(from_utxo, from_keypair);
}
