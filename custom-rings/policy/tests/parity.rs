//! Pins the entry math to the canonical UTXO types.

use solana_address::address;
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_interface::ADDRESS_DOMAIN;
use zolana_keypair::{hash::owner_hash, NullifierKey, PublicKey};
use zolana_ring_policy::{
    entry_nullifier, entry_seed, EntryState, ListEntry, ListId, ListNamespace, Member,
};
use zolana_transaction::{ProofInputUtxo, SOL_MINT};

const TEST_PDA: solana_address::Address = address!("6ZKEgsScJbL6JVDpbHLCFCUiPEVgmMSt1j6NudNLqEvh");

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
    assert_eq!(member.as_bytes(), &hash_bytes(&[7u8; 32]).unwrap());

    let seed = entry_seed(ListId::Block, &member).unwrap();
    let address_input = ProofInputUtxo {
        domain: right_align(&ADDRESS_DOMAIN.to_be_bytes()),
        owner_hash: expected_owner_hash,
        blinding: seed,
        ..ProofInputUtxo::default()
    };
    let address_utxo_hash = owner.address_utxo_hash(&seed).unwrap();
    assert_eq!(address_utxo_hash, address_input.hash().unwrap());
    assert_eq!(
        owner.address(ListId::Block, &member).unwrap(),
        nullifier_key.nullifier(&address_utxo_hash, &seed).unwrap()
    );

    let entry = ListEntry {
        list_id: ListId::Block,
        member,
        state: EntryState::Active,
        version: 9,
        content_hash: [0u8; 32],
    };
    let address = owner.address(entry.list_id, &entry.member).unwrap();
    let output = ProofInputUtxo::new(expected_owner_hash, &SOL_MINT, 0, &entry.blinding())
        .unwrap()
        .with_data_hash(entry.data_hash(&address).unwrap());
    let utxo_hash = entry.utxo_hash(&owner, &address).unwrap();
    assert_eq!(utxo_hash, output.hash().unwrap());
    assert_eq!(
        entry_nullifier(&utxo_hash, &entry.blinding()).unwrap(),
        nullifier_key
            .nullifier(&utxo_hash, &entry.blinding())
            .unwrap()
    );
}
