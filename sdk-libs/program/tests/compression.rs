#![cfg(feature = "compression")]

use solana_address::{address, Address};
use zolana_client::ProofInputUtxo;
use zolana_hasher::{
    primitives::{right_align, BN254_SCALAR_MODULUS_BE},
    Hasher, Poseidon,
};
use zolana_interface::{tree_slot::tree_id_field, ADDRESS_DOMAIN};
use zolana_keypair::{hash::owner_hash, NullifierKey, PublicKey};
use zolana_program::compression::{
    AddressSeed, CompressedAccountError, DataUtxo, NewAddress, PdaOwner, NO_RING_HASH,
    ZERO_NULLIFIER_PUBKEY,
};
use zolana_transaction::SOL_MINT;

const TEST_PDA: Address = address!("6ZKEgsScJbL6JVDpbHLCFCUiPEVgmMSt1j6NudNLqEvh");

/// Non-zero so a dropped tree id would change every commitment below.
const TEST_TREE_ID: u16 = 3;

fn zero_secret_nullifier_key() -> NullifierKey {
    NullifierKey::from_secret([0u8; 31])
}

#[test]
fn constants_are_the_hashes_they_name() {
    let zero = [0u8; 32];
    assert_eq!(ZERO_NULLIFIER_PUBKEY, Poseidon::hashv(&[&zero]).unwrap());
    assert_eq!(NO_RING_HASH, Poseidon::hashv(&[&zero, &zero]).unwrap());
    assert_eq!(
        ZERO_NULLIFIER_PUBKEY,
        zero_secret_nullifier_key().pubkey().unwrap()
    );
}

#[test]
fn pda_owner_hash_is_the_keypair_owner_hash_under_secret_zero() {
    let owner = PdaOwner::new(&TEST_PDA).unwrap();
    let expected = owner_hash(
        &PublicKey::from_pda(&TEST_PDA),
        &zero_secret_nullifier_key().pubkey().unwrap(),
    )
    .unwrap();

    assert_eq!(*owner.owner_hash(), expected);
}

#[test]
fn new_address_is_the_nullifier_of_an_address_slot() {
    let owner = PdaOwner::new(&TEST_PDA).unwrap();
    let seed = AddressSeed::owner(&owner);
    let address = NewAddress::derive(&owner, seed, TEST_TREE_ID).unwrap();
    let slot = ProofInputUtxo {
        domain: right_align(&ADDRESS_DOMAIN.to_be_bytes()),
        tree_id: tree_id_field(TEST_TREE_ID),
        owner_hash: *owner.owner_hash(),
        blinding: *seed.as_bytes(),
        ..ProofInputUtxo::default()
    };
    let slot_hash = slot.hash().unwrap();

    assert_eq!(*address.utxo_hash(), slot_hash);
    assert_eq!(
        *address.address(),
        zero_secret_nullifier_key()
            .nullifier(&slot_hash, seed.as_bytes())
            .unwrap()
    );
}

#[test]
fn addresses_are_distinct_per_seed_and_tree() {
    let owner = PdaOwner::new(&TEST_PDA).unwrap();
    let other_seed = AddressSeed::new(right_align(&[7u8])).unwrap();
    let base = NewAddress::derive(&owner, AddressSeed::owner(&owner), TEST_TREE_ID).unwrap();
    let other_tree =
        NewAddress::derive(&owner, AddressSeed::owner(&owner), TEST_TREE_ID + 1).unwrap();
    let other = NewAddress::derive(&owner, other_seed, TEST_TREE_ID).unwrap();

    assert_ne!(base.address(), other_tree.address());
    assert_ne!(base.address(), other.address());
}

#[test]
fn address_seed_rejects_a_non_canonical_scalar() {
    let mut below_modulus = BN254_SCALAR_MODULUS_BE;
    if let Some(last) = below_modulus.last_mut() {
        *last -= 1;
    }

    assert_eq!(
        AddressSeed::new(BN254_SCALAR_MODULUS_BE),
        Err(CompressedAccountError::NonCanonicalAddressSeed)
    );
    assert_eq!(
        AddressSeed::new(below_modulus).map(|seed| *seed.as_bytes()),
        Ok(below_modulus)
    );
}

#[test]
fn data_utxo_key_is_the_proof_input_utxo_hash_and_its_zero_secret_nullifier() {
    let owner = PdaOwner::new(&TEST_PDA).unwrap();
    let data_hash = right_align(&[9u8]);
    let blinding = right_align(&[5u8]);
    let key = DataUtxo {
        owner: &owner,
        data_hash,
        blinding,
    }
    .key(TEST_TREE_ID)
    .unwrap();
    let expected_hash =
        ProofInputUtxo::new(*owner.owner_hash(), &SOL_MINT, 0, &blinding, TEST_TREE_ID)
            .unwrap()
            .with_data_hash(data_hash)
            .hash()
            .unwrap();

    assert_eq!(*key.hash(), expected_hash);
    assert_eq!(
        *key.nullifier(),
        zero_secret_nullifier_key()
            .nullifier(&expected_hash, &blinding)
            .unwrap()
    );
}

#[test]
fn data_utxo_rejects_a_zero_data_hash() {
    let owner = PdaOwner::new(&TEST_PDA).unwrap();
    let utxo = DataUtxo {
        owner: &owner,
        data_hash: [0u8; 32],
        blinding: right_align(&[5u8]),
    };

    assert_eq!(
        utxo.hash(TEST_TREE_ID),
        Err(CompressedAccountError::ZeroDataHash)
    );
    assert_eq!(
        utxo.key(TEST_TREE_ID).map(|key| *key.hash()),
        Err(CompressedAccountError::ZeroDataHash)
    );
}

#[test]
fn data_utxo_rejects_a_non_canonical_data_hash() {
    let owner = PdaOwner::new(&TEST_PDA).unwrap();
    let utxo = DataUtxo {
        owner: &owner,
        data_hash: BN254_SCALAR_MODULUS_BE,
        blinding: right_align(&[5u8]),
    };

    assert_eq!(
        utxo.hash(TEST_TREE_ID),
        Err(CompressedAccountError::HashingFailed)
    );
}
