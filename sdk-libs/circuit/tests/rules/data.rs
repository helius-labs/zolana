use spr_circuit::hasher::{CLOSED_DATA_HASH_DOMAIN, DATA_HASH_DOMAIN, UNIQUE_DATA_HASH_DOMAIN};
use spr_circuit::protocol::{DataUtxo, UniqueDataUtxo, Utxo, UtxoTrait};
use spr_circuit::{Field, checked, poseidon, to_bytes};

use crate::support::{SOL, USDC, assert_requirement, owner, utxo};

const DATA: &str = "protocol/utxo/data.rs";
const SPEND: &str = "fn spend_with_hash(";

fn domain(tag: u32) -> Field {
    Field::from(tag)
}

fn state_input(state: u64, amount: u64) -> Utxo {
    Utxo {
        data_hash: poseidon(&[domain(DATA_HASH_DOMAIN), Field::from(state)]).unwrap(),
        ..utxo(owner(1), USDC, amount)
    }
}

fn unique_input(address: Field, state: u64, amount: u64) -> Utxo {
    Utxo {
        data_hash: poseidon(&[domain(UNIQUE_DATA_HASH_DOMAIN), address, Field::from(state)])
            .unwrap(),
        ..utxo(owner(1), USDC, amount)
    }
}

#[test]
fn a_spent_state_keeps_its_owner_asset_balance_and_value() {
    let mut state = DataUtxo::new_mut(&state_input(7, 5), &7u64).unwrap();
    *state += 1;
    let output = state.output().unwrap().unwrap();
    assert_eq!(
        (
            output.owner,
            output.asset,
            output.amount,
            to_bytes(&output.data_hash)
        ),
        (
            owner(1),
            USDC,
            5,
            to_bytes(&poseidon(&[domain(DATA_HASH_DOMAIN), Field::from(8u64)]).unwrap()),
        )
    );
}

#[test]
fn a_state_input_must_have_the_utxo_domain() {
    let dummy = Utxo {
        data_hash: state_input(7, 0).data_hash,
        ..Utxo::dummy()
    };
    assert_requirement(
        checked(|| DataUtxo::new_mut(&dummy, &7u64).map(drop)),
        DATA,
        SPEND,
        "require_eq(input.domain, UTXO_DOMAIN)",
    );
}

#[test]
fn a_state_input_must_commit_to_the_claimed_state() {
    let call = "require_eq(input.data_hash, expected)";
    let input = state_input(7, 5);
    assert_requirement(
        checked(|| DataUtxo::new_mut(&input, &8u64).map(drop)),
        DATA,
        SPEND,
        call,
    );
    assert_requirement(
        checked(|| DataUtxo::new_mut_with_hash(&input, &Field::from(7u64)).map(drop)),
        DATA,
        SPEND,
        call,
    );
    assert!(DataUtxo::new_mut_with_hash(&input, &input.data_hash).is_ok());
}

#[test]
fn ordinary_and_unique_data_hashes_are_separate_domains() {
    let call = "require_eq(input.data_hash, expected)";
    let address = Field::from(99u64);
    assert_requirement(
        checked(|| UniqueDataUtxo::new_mut(&state_input(7, 5), &address, &7u64).map(drop)),
        DATA,
        SPEND,
        call,
    );
    assert_requirement(
        checked(|| DataUtxo::new_mut(&unique_input(address, 7, 5), &7u64).map(drop)),
        DATA,
        SPEND,
        call,
    );
    assert_requirement(
        checked(|| {
            UniqueDataUtxo::new_mut(&unique_input(address, 7, 5), &Field::from(98u64), &7u64)
                .map(drop)
        }),
        DATA,
        SPEND,
        call,
    );
    assert!(UniqueDataUtxo::new_mut(&unique_input(address, 7, 5), &address, &7u64).is_ok());
}

#[test]
fn the_asset_is_chosen_only_for_an_untouched_new_state() {
    let call = "require(self.spent.is_none() && self.balance.is_untouched())";
    let anchor = "pub fn with_asset(";
    assert_requirement(
        checked(|| {
            DataUtxo::new_mut(&state_input(7, 5), &7u64)?
                .with_asset(&SOL)
                .map(drop)
        }),
        DATA,
        anchor,
        call,
    );
    assert_requirement(
        checked(|| {
            let mut state = DataUtxo::<u64>::new_init(&owner(1));
            state.deposit(&3, &[9; 32])?;
            state.with_asset(&USDC).map(drop)
        }),
        DATA,
        anchor,
        call,
    );
    let fresh = DataUtxo::<u64>::new_init(&owner(1))
        .with_asset(&USDC)
        .unwrap();
    assert_eq!((fresh.asset(), fresh.amount(), *fresh), (USDC, Ok(0), 0));
}

#[test]
fn closing_or_burning_a_state_requires_an_empty_balance() {
    let call = "require_eq(self.balance.amount, 0u128)";
    assert_requirement(
        checked(|| {
            DataUtxo::new_mut(&state_input(7, 5), &7u64)?
                .close()
                .output()
        }),
        DATA,
        "OutputState::None =>",
        call,
    );
    let address = Field::from(99u64);
    assert_requirement(
        checked(|| {
            UniqueDataUtxo::new_mut(&unique_input(address, 7, 5), &address, &7u64)?
                .close()
                .data_utxo()
                .output()
        }),
        DATA,
        "OutputState::Closed(address) =>",
        call,
    );
    assert_requirement(
        checked(|| {
            UniqueDataUtxo::new_mut(&unique_input(address, 7, 5), &address, &7u64)?
                .burn()
                .data_utxo()
                .output()
        }),
        DATA,
        "OutputState::None =>",
        call,
    );
}

#[test]
fn a_closed_unique_state_leaves_a_tombstone_and_a_burned_one_nothing() {
    let address = Field::from(99u64);
    let spend = || UniqueDataUtxo::new_mut(&unique_input(address, 7, 0), &address, &7u64).unwrap();
    let closed = spend().close().data_utxo().output().unwrap().unwrap();
    assert_eq!(
        (to_bytes(&closed.data_hash), closed.amount),
        (
            to_bytes(&poseidon(&[domain(CLOSED_DATA_HASH_DOMAIN), address]).unwrap()),
            0
        )
    );
    assert!(spend().burn().data_utxo().output().unwrap().is_none());
    assert!(
        DataUtxo::new_mut(&state_input(7, 0), &7u64)
            .unwrap()
            .close()
            .output()
            .unwrap()
            .is_none()
    );
}
