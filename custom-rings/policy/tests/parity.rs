//! Pins the entry math to the canonical UTXO types.

use solana_address::address;
use zolana_hasher::primitives::{right_align, solana_owner_identity};
use zolana_interface::{tree_slot::tree_id_field, ADDRESS_DOMAIN};
use zolana_keypair::{hash::owner_hash, NullifierKey, PublicKey};
use zolana_ring_policy::{
    entry_nullifier, entry_seed, mutation_private_tx_hash, EntryState, ListEntry, ListId,
    ListNamespace, Member,
};
use zolana_transaction::{instructions::transact::PrivateTxHash, ProofInputUtxo, SOL_MINT};

const TEST_PDA: solana_address::Address = address!("6ZKEgsScJbL6JVDpbHLCFCUiPEVgmMSt1j6NudNLqEvh");
const TREE_ID: u16 = 5;

#[test]
fn record_commitments_match_the_canonical_utxo_types() {
    let owner = ListNamespace::new(TEST_PDA.as_array()).unwrap();
    let nullifier_key = NullifierKey::from_secret([0u8; 31]);
    let expected_owner_hash = owner_hash(
        &PublicKey::from_pda(&TEST_PDA),
        &nullifier_key.pubkey().unwrap(),
    )
    .unwrap();
    assert_eq!(owner.owner_hash, expected_owner_hash);

    let member = Member::owner_tag(&[7u8; 32]).unwrap();
    assert_eq!(
        member.as_bytes(),
        &solana_owner_identity(&[7u8; 32]).unwrap()
    );

    let seed = entry_seed(ListId::Block, &member).unwrap();
    let address_input = ProofInputUtxo {
        domain: right_align(&ADDRESS_DOMAIN.to_be_bytes()),
        tree_id: tree_id_field(TREE_ID),
        owner_hash: expected_owner_hash,
        blinding: seed,
        ..ProofInputUtxo::default()
    };
    let address_utxo_hash = owner.address_utxo_hash(&seed, TREE_ID).unwrap();
    assert_eq!(address_utxo_hash, address_input.hash().unwrap());
    assert_eq!(
        owner.address(ListId::Block, &member, TREE_ID).unwrap(),
        nullifier_key.nullifier(&address_utxo_hash, &seed).unwrap()
    );

    let entry = ListEntry {
        list_id: ListId::Block,
        member,
        state: EntryState::Active,
        version: 9,
        content_hash: [0u8; 32],
        blinding: [3u8; 32],
    };
    let address = owner
        .address(entry.list_id, &entry.member, TREE_ID)
        .unwrap();
    let output = ProofInputUtxo::new(
        expected_owner_hash,
        &SOL_MINT,
        0,
        &entry.blinding(),
        TREE_ID,
    )
    .unwrap()
    .with_data_hash(entry.data_hash(&address).unwrap());
    let utxo_hash = entry.utxo_hash(&owner, &address, TREE_ID).unwrap();
    assert_eq!(utxo_hash, output.hash().unwrap());
    assert_eq!(
        entry_nullifier(&utxo_hash, &entry.blinding()).unwrap(),
        nullifier_key
            .nullifier(&utxo_hash, &entry.blinding())
            .unwrap()
    );
}

/// The program folds a claim's address as the slot's nullifier, as SPP does.
#[test]
fn the_mutation_private_tx_hash_matches_the_transact_preimage() {
    let input = [1u8; 32];
    let output = [2u8; 32];
    let address = [3u8; 32];
    let external = [4u8; 32];
    let blinding = [5u8; 32];
    assert_eq!(
        mutation_private_tx_hash(input, output, address, &external, &blinding).unwrap(),
        PrivateTxHash {
            input_hashes: &[input],
            output_hashes: &[output],
            address_nullifiers: Some(&[address]),
            external_data_hash: &external,
            blinding: &blinding,
        }
        .hash()
        .unwrap()
    );
    assert_eq!(
        mutation_private_tx_hash(input, output, [0u8; 32], &external, &blinding).unwrap(),
        PrivateTxHash {
            input_hashes: &[input],
            output_hashes: &[output],
            address_nullifiers: None,
            external_data_hash: &external,
            blinding: &blinding,
        }
        .hash()
        .unwrap()
    );
}
