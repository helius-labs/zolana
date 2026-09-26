use solana_address::Address;
use zk_program_sdk::{
    circuit::{self, constant, Bits, ConstraintSystem, Field},
    conversion::{field_bytes, to_bytes, Allocator, FromCircuit, ProofInput},
    Bytes, Owner,
};
use zolana_hasher::primitives::{
    hash_bytes, p256_owner_identity, solana_owner_identity, P256_OWNER_TAG, SOLANA_OWNER_TAG,
};
use zolana_keypair::{hash::owner_hash, PublicKey, ShieldedKeypair, SigningKey};

fn pattern<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(index % 256)
            .unwrap_or_default()
            .wrapping_mul(37)
            .wrapping_add(11);
    }
    bytes
}

fn bytes_hashes<const N: usize>() -> ([u8; 32], [u8; 32], bool, [u8; 32]) {
    let bytes = Bytes(pattern::<N>());
    let native = bytes.instantiate(&Allocator::native()).unwrap();
    let cs = ConstraintSystem::new_ref();
    let allocated = bytes.instantiate(&Allocator::R1cs(cs.clone())).unwrap();
    (
        to_bytes(&native.hash_bytes().unwrap()).unwrap(),
        to_bytes(&allocated.hash_bytes().unwrap()).unwrap(),
        cs.is_satisfied().unwrap(),
        hash_bytes(&bytes.0).unwrap(),
    )
}

fn owner_hashes(owner: &Owner) -> ([u8; 32], [u8; 32], bool, Owner) {
    let native = owner.instantiate(&Allocator::native()).unwrap();
    let cs = ConstraintSystem::new_ref();
    let allocated = owner.instantiate(&Allocator::R1cs(cs.clone())).unwrap();
    (
        to_bytes(&native.key().identity().unwrap()).unwrap(),
        to_bytes(&allocated.hash().unwrap()).unwrap(),
        cs.is_satisfied().unwrap(),
        Owner::from_circuit(&native).unwrap(),
    )
}

#[test]
fn bytes_hash_like_the_native_hash_bytes() {
    let check = |(native, allocated, satisfied, expected): ([u8; 32], [u8; 32], bool, [u8; 32])| {
        (native == expected, allocated == expected, satisfied)
    };

    assert_eq!(
        (
            check(bytes_hashes::<5>()),
            check(bytes_hashes::<31>()),
            check(bytes_hashes::<32>()),
            check(bytes_hashes::<33>()),
            check(bytes_hashes::<63>()),
        ),
        (
            (true, true, true),
            (true, true, true),
            (true, true, true),
            (true, true, true),
            (true, true, true),
        )
    );
}

#[test]
fn owners_hash_like_their_keys_for_every_curve() {
    let ed25519 = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[5u8; 32]))
        .unwrap()
        .shielded_address()
        .unwrap();
    let p256 = ShieldedKeypair::new_p256()
        .unwrap()
        .shielded_address()
        .unwrap();
    let pda = PublicKey::from_pda(&Address::new_from_array([9u8; 32]));
    let pda_nullifier_pk = field_bytes(&Field::from(77u64));
    let owners = [
        Owner::try_from(&ed25519).unwrap(),
        Owner::try_from(&p256).unwrap(),
        Owner::try_from((&pda, pda_nullifier_pk)).unwrap(),
    ];

    assert_eq!(
        owners.map(|owner| owner_hashes(&owner)),
        [
            (
                solana_owner_identity(&ed25519.signing_pubkey.confidential_view_tag().unwrap())
                    .unwrap(),
                ed25519.owner_hash().unwrap(),
                true,
                Owner {
                    tag: SOLANA_OWNER_TAG,
                    key: ed25519.signing_pubkey.confidential_view_tag().unwrap(),
                    nullifier_pk: ed25519.nullifier_pubkey,
                },
            ),
            (
                p256_owner_identity(&p256.signing_pubkey.confidential_view_tag().unwrap()).unwrap(),
                p256.owner_hash().unwrap(),
                true,
                Owner {
                    tag: P256_OWNER_TAG,
                    key: p256.signing_pubkey.confidential_view_tag().unwrap(),
                    nullifier_pk: p256.nullifier_pubkey,
                },
            ),
            (
                solana_owner_identity(&pda.confidential_view_tag().unwrap()).unwrap(),
                owner_hash(&pda, &pda_nullifier_pk).unwrap(),
                true,
                Owner {
                    tag: SOLANA_OWNER_TAG,
                    key: pda.confidential_view_tag().unwrap(),
                    nullifier_pk: pda_nullifier_pk,
                },
            ),
        ]
    );
}

#[test]
fn a_tag_outside_s_and_p_and_a_byte_above_255_are_refused() {
    let other_tag = Owner {
        tag: b'A',
        key: [1u8; 32],
        nullifier_pk: field_bytes(&Field::from(3u64)),
    };
    let other_tag_in_r1cs = {
        let cs = ConstraintSystem::new_ref();
        let _owner: circuit::Owner = other_tag.instantiate(&Allocator::R1cs(cs.clone())).unwrap();
        cs.is_satisfied().unwrap()
    };
    let wide_byte_in_r1cs = {
        let cs = ConstraintSystem::new_ref();
        let byte = Allocator::R1cs(cs.clone())
            .private_input(&constant(256u64))
            .unwrap();
        byte.check_bits(8).unwrap();
        cs.is_satisfied().unwrap()
    };

    assert_eq!(
        (
            other_tag
                .instantiate(&Allocator::native())
                .err()
                .map(|e| e.to_string()),
            other_tag_in_r1cs,
            constant(256u64).check_bits(8).err().map(|e| e.to_string()),
            wide_byte_in_r1cs,
        ),
        (
            Some("the owner tag is neither S nor P".to_string()),
            false,
            Some("a value does not fit in 8 bits".to_string()),
            false,
        )
    );
}
