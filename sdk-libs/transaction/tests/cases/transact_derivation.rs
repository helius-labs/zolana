use serde::Deserialize;
use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice,
    primitives::{hash_bytes, p256_owner_identity, right_align, solana_owner_identity},
    Hasher, Poseidon,
};
use zolana_interface::{
    tree_slot::{
        tree_id_field, tree_slots_hash_chain, TreeSlot, ZERO_TREE_SLOT_SUFFIX_CHAINS,
    },
    INPUT_TREES,
};
use zolana_keypair::NullifierKey;
use zolana_transaction::{
    instructions::merge::merge_private_tx_blinding,
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding,
        derive_transact_output_blinding, ProofInputUtxo,
    },
};

#[derive(Deserialize)]
struct TransactDerivationVectors {
    owner_identity: OwnerIdentity,
    blinding_seed: BlindingSeed,
    tree_slots: TreeSlots,
    dummy_utxo_hash: DummyUtxoHash,
}

#[derive(Deserialize)]
struct OwnerIdentity {
    solana_pubkey: String,
    solana_owner_identity: String,
    p256_x: String,
    p256_owner_identity: String,
    hash_bytes_33_input: String,
    hash_bytes_33: String,
}

#[derive(Deserialize)]
struct BlindingSeed {
    first_nullifier: u8,
    blinding_seed: u8,
    output_blinding_seed: String,
    private_tx_blinding: String,
    output_index: u32,
    output_blinding: String,
    /// `TXOB` over the derived output seed, the form the circuit checks for every slot.
    output_blinding_derived: String,
    merge_nullifier_secret: u8,
    merge_private_tx_blinding: String,
}

#[derive(Deserialize)]
struct TreeSlots {
    tree_id: u16,
    tree_id_field: String,
    utxo_root: u8,
    nullifier_root: u8,
    slot_hash: String,
    single_tree_chain: String,
    zero_suffix_chains: Vec<String>,
}

#[derive(Deserialize)]
struct DummyUtxoHash {
    tree_id: u16,
    blinding: u8,
    hash: String,
}

fn vectors() -> TransactDerivationVectors {
    serde_json::from_str(include_str!(
        "../../../../test-vectors/transact_derivation.json"
    ))
    .unwrap()
}

fn small(value: u8) -> [u8; 32] {
    right_align(&[value])
}

fn array<const N: usize>(hex_bytes: &str) -> [u8; N] {
    hex::decode(hex_bytes).unwrap().try_into().unwrap()
}

/// The TypeScript SDK asserts the same section, so the tagged identity
/// encoding cannot drift between the two SDKs without a vector failing.
pub(crate) fn owner_identities_match_shared_vectors() {
    let section = vectors().owner_identity;
    let solana_pubkey: [u8; 32] = array(&section.solana_pubkey);
    let p256_x: [u8; 32] = array(&section.p256_x);
    assert_eq!(
        hex::encode(solana_owner_identity(&solana_pubkey).unwrap()),
        section.solana_owner_identity
    );
    assert_eq!(
        hex::encode(p256_owner_identity(&p256_x).unwrap()),
        section.p256_owner_identity
    );
    let input: [u8; 33] = array(&section.hash_bytes_33_input);
    assert_eq!(hex::encode(hash_bytes(&input).unwrap()), section.hash_bytes_33);
}

pub(crate) fn blinding_seed_family_matches_shared_vectors() {
    let section = vectors().blinding_seed;
    let first_nullifier = small(section.first_nullifier);
    let blinding_seed = small(section.blinding_seed);
    let output_seed = derive_output_blinding_seed(&first_nullifier, &blinding_seed).unwrap();
    assert_eq!(hex::encode(output_seed), section.output_blinding_seed);
    assert_eq!(
        hex::encode(
            derive_transact_output_blinding(&first_nullifier, &output_seed, section.output_index)
                .unwrap()
        ),
        section.output_blinding_derived
    );
    assert_eq!(
        hex::encode(derive_private_tx_blinding(&first_nullifier, &blinding_seed).unwrap()),
        section.private_tx_blinding
    );
    assert_eq!(
        hex::encode(
            derive_transact_output_blinding(&first_nullifier, &blinding_seed, section.output_index)
                .unwrap()
        ),
        section.output_blinding
    );
    let mut secret = [0u8; 31];
    secret[30] = section.merge_nullifier_secret;
    let key = NullifierKey::from_secret(secret);
    assert_eq!(
        hex::encode(merge_private_tx_blinding(&key, &first_nullifier).unwrap()),
        section.merge_private_tx_blinding
    );
}

pub(crate) fn tree_slot_chain_matches_shared_vectors() {
    let section = vectors().tree_slots;
    assert_eq!(
        hex::encode(tree_id_field(section.tree_id)),
        section.tree_id_field
    );
    let slot0 = TreeSlot::new(
        section.tree_id,
        small(section.utxo_root),
        small(section.nullifier_root),
    );
    assert_eq!(hex::encode(slot0.hash().unwrap()), section.slot_hash);
    let mut slots = [TreeSlot::ZERO; INPUT_TREES];
    slots[0] = slot0;
    assert_eq!(
        hex::encode(tree_slots_hash_chain(&slots).unwrap()),
        section.single_tree_chain
    );
    let suffixes: Vec<String> = ZERO_TREE_SLOT_SUFFIX_CHAINS
        .iter()
        .map(hex::encode)
        .collect();
    assert_eq!(suffixes, section.zero_suffix_chains);
    let last_suffix = ZERO_TREE_SLOT_SUFFIX_CHAINS
        .last()
        .expect("suffix chains are non-empty");
    assert_eq!(
        hex::encode(create_hash_chain_from_slice(&[slot0.hash().unwrap(), *last_suffix]).unwrap()),
        section.single_tree_chain
    );
}

pub(crate) fn dummy_utxo_hash_matches_shared_vectors() {
    let section = vectors().dummy_utxo_hash;
    let dummy = ProofInputUtxo::new_dummy(&small(section.blinding), section.tree_id);
    assert_eq!(hex::encode(dummy.hash().unwrap()), section.hash);
    // The recomputation pins the 7-element preimage the vector encodes.
    let zero = [0u8; 32];
    let expected = Poseidon::hashv(&[
        &small(1),
        &tree_id_field(section.tree_id),
        &zero,
        &zero,
        &zero,
        &Poseidon::hashv(&[&zero, &zero]).unwrap(),
        &Poseidon::hashv(&[&zero, &small(section.blinding)]).unwrap(),
    ])
    .unwrap();
    assert_eq!(hex::encode(expected), section.hash);
}
