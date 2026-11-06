use spr_circuit::protocol::{NewAddress, UniqueDataUtxo};
use spr_circuit::{Field, SigningPubkey, UtxoOwner, checked, poseidon, to_bytes};

use crate::support::{assert_requirement, owner, program_owner};

const ADDRESS: &str = "protocol/utxo/address.rs";
const UNIQUE: &str = "protocol/utxo/unique.rs";

fn untagged() -> UtxoOwner {
    UtxoOwner::new(
        SigningPubkey::new(b'X', [1; 32]),
        poseidon(&[Field::zero()]).unwrap(),
    )
}

#[test]
fn an_address_reservation_requires_a_solana_program_owner() {
    let anchor = "pub fn new(owner";
    assert_requirement(
        checked(|| NewAddress::new(&untagged(), &Field::one()).map(drop)),
        ADDRESS,
        anchor,
        "require_eq(owner.key().tag(), crate::owner::SOLANA_OWNER_TAG)",
    );
    assert_requirement(
        checked(|| NewAddress::new(&owner(1), &Field::one()).map(drop)),
        ADDRESS,
        anchor,
        "require_eq(owner.nullifier_pk(), poseidon(&[Field::zero()])?)",
    );
}

#[test]
fn a_unique_state_requires_a_solana_owner() {
    assert_requirement(
        checked(|| UniqueDataUtxo::<u64>::new_init(&untagged(), &Field::one()).map(drop)),
        UNIQUE,
        "pub fn new_init(owner",
        "require_eq(owner.key().tag(), crate::owner::SOLANA_OWNER_TAG)",
    );
}

#[test]
fn addresses_bind_the_signing_key_and_seed_but_not_the_nullifier_key() {
    let address = |owner: &UtxoOwner, seed: u64| {
        to_bytes(
            &UniqueDataUtxo::<u64>::new_init(owner, &Field::from(seed))
                .unwrap()
                .address(),
        )
    };
    let reserved = NewAddress::new(&program_owner(1), &Field::from(5u64))
        .unwrap()
        .address();
    assert_eq!(address(&owner(1), 5), to_bytes(&reserved));
    assert_eq!(address(&program_owner(1), 5), to_bytes(&reserved));
    assert_ne!(address(&owner(1), 6), to_bytes(&reserved));
    assert_ne!(address(&owner(2), 5), to_bytes(&reserved));
}
