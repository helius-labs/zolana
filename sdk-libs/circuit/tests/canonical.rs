//! Native protocol values against the canonical implementations the SPP
//! program, the instruction builders and the wallet use.

use proptest::prelude::*;
use solana_address::Address;
use spr_circuit::protocol::{NewAddress, PublicTransfer, UniqueDataUtxo, Utxo};
use spr_circuit::{
    Field, UtxoOwner, from_bytes, hash_bytes, nonzero_hash_chain, poseidon, to_bytes,
};
use spr_hasher::hash_chain::create_nonzero_hash_chain_from_slice;
use spr_hasher::primitives::{hash_bytes as canonical_hash_bytes, solana_owner_identity};
use spr_hasher::{Hasher, Poseidon};
use spr_instruction::ADDRESS_TREE_ID;
use spr_interface::DUMMY_DOMAIN;
use spr_keypair::{NullifierKey, PublicKey, constants::BLINDING_LEN};
use spr_transaction::utxo::SppProofInputUtxo;
use spr_transaction::{Data, Mint};

const SOLANA_TAG: u8 = 0x53;

/// A canonical BN254 scalar: the top byte stays clear.
fn scalar(bytes: [u8; 32]) -> [u8; 32] {
    let mut bytes = bytes;
    bytes[0] = 0;
    bytes
}

fn owner(key: &PublicKey, nullifier_pk: &[u8; 32]) -> UtxoOwner {
    UtxoOwner::from_preimage(
        SOLANA_TAG,
        &key.confidential_view_tag().unwrap(),
        nullifier_pk,
    )
    .unwrap()
}

fn keys(seed: u8) -> [(PublicKey, [u8; 32]); 2] {
    let nullifier_pk = NullifierKey::from_secret([seed; BLINDING_LEN])
        .pubkey()
        .unwrap();
    [
        (PublicKey::from_ed25519(&[seed; 32]), nullifier_pk),
        (
            PublicKey::from_pda(&Address::new_from_array([seed; 32])),
            nullifier_pk,
        ),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn poseidon_matches_the_on_chain_poseidon(
        inputs in prop::collection::vec(any::<[u8; 32]>().prop_map(scalar), 1..=12)
    ) {
        let fields: Vec<_> = inputs.iter().map(|bytes| from_bytes(bytes).unwrap()).collect();
        let slices: Vec<&[u8]> = inputs.iter().map(|bytes| bytes.as_slice()).collect();
        prop_assert_eq!(to_bytes(&poseidon(&fields).unwrap()), Poseidon::hashv(&slices).unwrap());
    }

    #[test]
    fn hash_bytes_matches_the_canonical_packing(key in any::<[u8; 32]>(), viewing in any::<[u8; 32]>(), prefix in any::<u8>()) {
        let mut viewing_pubkey = [prefix; 33];
        viewing_pubkey[1..].copy_from_slice(&viewing);
        prop_assert_eq!(
            (to_bytes(&hash_bytes(&key).unwrap()), to_bytes(&hash_bytes(&viewing_pubkey).unwrap())),
            (canonical_hash_bytes(&key).unwrap(), canonical_hash_bytes(&viewing_pubkey).unwrap())
        );
    }

    #[test]
    fn nonzero_hash_chain_matches_the_canonical_chain(
        values in prop::collection::vec(prop_oneof![Just([0u8; 32]), any::<[u8; 32]>().prop_map(scalar)], 0..12)
    ) {
        let fields: Vec<_> = values.iter().map(|bytes| from_bytes(bytes).unwrap()).collect();
        prop_assert_eq!(
            to_bytes(&nonzero_hash_chain(&fields).unwrap()),
            create_nonzero_hash_chain_from_slice(&values).unwrap()
        );
    }

    #[test]
    fn utxo_hash_matches_the_wallet_commitment(
        seed in 1u8..=u8::MAX,
        mint in any::<[u8; 32]>(),
        amount in any::<u64>(),
        blinding in any::<[u8; 32]>().prop_map(scalar),
        data_hash in any::<[u8; 32]>().prop_map(scalar),
        ring_data_hash in any::<[u8; 32]>().prop_map(scalar),
        ring_program in proptest::option::of(any::<[u8; 32]>()),
        tree_id in any::<u16>(),
    ) {
        for (key, nullifier_pk) in keys(seed) {
            let ring_program_id = ring_program.map(Address::new_from_array);
            let native = spr_transaction::Utxo {
                owner: key,
                asset: Mint::new(Address::new_from_array(mint), 0),
                amount,
                blinding,
                ring_program_id,
                data: Data::default(),
            };
            let utxo = Utxo {
                owner: owner(&key, &nullifier_pk),
                asset: mint,
                amount,
                blinding: from_bytes(&blinding).unwrap(),
                data_hash: from_bytes(&data_hash).unwrap(),
                ring_data_hash: from_bytes(&ring_data_hash).unwrap(),
                ring_program_id: ring_program.map_or(Field::zero(), |id| hash_bytes(&id).unwrap()),
                tree_id,
                ..Utxo::default()
            };
            prop_assert_eq!(
                to_bytes(&utxo.hash().unwrap()),
                native.hash(&nullifier_pk, &data_hash, &ring_data_hash, tree_id).unwrap()
            );
        }
    }

    #[test]
    fn a_dummy_hash_matches_the_wallet_dummy(blinding in any::<[u8; 32]>().prop_map(scalar), tree_id in any::<u16>()) {
        let dummy = Utxo { blinding: from_bytes(&blinding).unwrap(), tree_id, ..Utxo::dummy() };
        prop_assert_eq!(dummy.domain, DUMMY_DOMAIN);
        prop_assert_eq!(
            to_bytes(&dummy.hash().unwrap()),
            SppProofInputUtxo::dummy_with_blinding(blinding, tree_id).unwrap().hash()
        );
    }

    #[test]
    fn public_transfer_hash_matches_the_instruction_hash(
        mint in any::<[u8; 32]>(), account in any::<[u8; 32]>(), amount in any::<u64>(), is_deposit in any::<bool>()
    ) {
        let transfer = PublicTransfer { asset: mint, is_deposit, amount, account };
        let canonical = spr_instruction::PublicTransfer {
            mint: Address::new_from_array(mint),
            is_deposit,
            amount,
            account: Address::new_from_array(account),
        };
        prop_assert_eq!(to_bytes(&transfer.hash().unwrap()), canonical.hash().unwrap());
    }
}

#[test]
fn owner_identity_and_hash_match_the_keypair() {
    for seed in [1, 7, u8::MAX] {
        for (key, nullifier_pk) in keys(seed) {
            let owner = owner(&key, &nullifier_pk);
            assert_eq!(
                (
                    to_bytes(&owner.key().identity().unwrap()),
                    to_bytes(&owner.hash().unwrap()),
                ),
                (
                    solana_owner_identity(&key.confidential_view_tag().unwrap()).unwrap(),
                    spr_keypair::hash::owner_hash(&key, &nullifier_pk).unwrap(),
                )
            );
        }
    }
}

#[test]
fn the_address_owner_nullifier_key_is_the_program_owner_key() {
    assert_eq!(
        to_bytes(&poseidon(&[Field::zero()]).unwrap()),
        NullifierKey::from_secret([0; BLINDING_LEN])
            .pubkey()
            .unwrap()
    );
}

#[test]
fn derived_addresses_match_the_wallet_address_slot() {
    let program_nullifier_pk = NullifierKey::from_secret([0; BLINDING_LEN])
        .pubkey()
        .unwrap();
    for seed in [1u8, 9, u8::MAX] {
        let key = PublicKey::from_pda(&Address::new_from_array([seed; 32]));
        let address_seed = scalar([seed.wrapping_add(3); 32]);
        let canonical = SppProofInputUtxo::new_address(key, address_seed, ADDRESS_TREE_ID)
            .unwrap()
            .nullifier;
        let program_owner = owner(&key, &program_nullifier_pk);
        let reserved =
            NewAddress::new(&program_owner, &from_bytes(&address_seed).unwrap()).unwrap();
        // A unique state's address ignores its owner's nullifier key.
        let user_owner = UtxoOwner::new(*program_owner.key(), Field::from(5u64));
        let unique =
            UniqueDataUtxo::<u64>::new_init(&user_owner, &from_bytes(&address_seed).unwrap())
                .unwrap();
        assert_eq!(
            [to_bytes(&reserved.address()), to_bytes(&unique.address())],
            [canonical, canonical]
        );
    }
}
