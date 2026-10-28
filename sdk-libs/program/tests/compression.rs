#![cfg(feature = "compression")]

use solana_address::{address, Address};
use spr_client::ProofInputUtxo;
use spr_hasher::{
    primitives::{right_align, BN254_SCALAR_MODULUS_BE},
    Hasher, Poseidon,
};
use spr_interface::{
    tree_slot::tree_id_field, ADDRESS_DOMAIN, SOL_ASSET_FIELD, ZERO_NULLIFIER_PUBKEY,
};
use spr_keypair::{hash::owner_hash, NullifierKey, PublicKey};
use spr_program::program::{
    AddressSeed, CompressedAccountError, NewAddress, PdaOwner, UniqueDataUtxo, UtxoMeta,
};
use spr_transaction::SOL_MINT;

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
    assert_eq!(SOL_ASSET_FIELD, Poseidon::hashv(&[&zero, &zero]).unwrap());
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
    let address = NewAddress::derive_with_tree_id(&owner, seed, TEST_TREE_ID).unwrap();
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
    let base =
        NewAddress::derive_with_tree_id(&owner, AddressSeed::owner(&owner), TEST_TREE_ID).unwrap();
    let other_tree =
        NewAddress::derive_with_tree_id(&owner, AddressSeed::owner(&owner), TEST_TREE_ID + 1)
            .unwrap();
    let other = NewAddress::derive_with_tree_id(&owner, other_seed, TEST_TREE_ID).unwrap();

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

struct HashState([u8; 32]);

impl spr_program::hasher::DataHasher for HashState {
    fn hash(&self) -> Result<[u8; 32], spr_hasher::HasherError> {
        Ok(self.0)
    }
}

#[test]
fn unique_state_nullifier_matches_the_protocol_input() {
    let owner = PdaOwner::new(&TEST_PDA).unwrap();
    let meta = UtxoMeta {
        address: right_align(&[6u8]),
        blinding: right_align(&[5u8]),
        tree_context: spr_interface::instruction::instruction_data::transact::TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        },
    };
    for state_hash in [right_align(&[9u8]), [0u8; 32]] {
        let utxo =
            UniqueDataUtxo::new_mut(&owner, &meta, HashState(state_hash), TEST_TREE_ID).unwrap();
        let expected_data_hash =
            Poseidon::hashv(&[&right_align(b"UNIQ"), &meta.address, &state_hash]).unwrap();
        let expected_hash = ProofInputUtxo::new(
            *owner.owner_hash(),
            &SOL_MINT,
            0,
            &meta.blinding,
            TEST_TREE_ID,
        )
        .unwrap()
        .with_data_hash(expected_data_hash)
        .hash()
        .unwrap();
        let expected_nullifier = zero_secret_nullifier_key()
            .nullifier(&expected_hash, &meta.blinding)
            .unwrap();
        assert_eq!(
            (utxo.data_hash().unwrap(), *utxo.input_nullifier()),
            (expected_data_hash, expected_nullifier)
        );
    }
}

#[test]
fn unique_state_rejects_a_non_canonical_state_hash() {
    let owner = PdaOwner::new(&TEST_PDA).unwrap();
    let meta = UtxoMeta {
        address: right_align(&[6u8]),
        blinding: right_align(&[5u8]),
        tree_context: spr_interface::instruction::instruction_data::transact::TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        },
    };
    assert_eq!(
        UniqueDataUtxo::new_mut(
            &owner,
            &meta,
            HashState(BN254_SCALAR_MODULUS_BE),
            TEST_TREE_ID
        )
        .map(|utxo| *utxo.input_nullifier()),
        Err(CompressedAccountError::HashingFailed)
    );
}
