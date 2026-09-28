use zk_program_sdk::circuit::Field;

use super::{
    fixtures::{
        broken, spend, Spend, ASSET, AS_GIVEN, AT_LEAST_ONE, BALANCE, BALANCE_FITS,
        DIFFERENT_ASSETS, DIFFERENT_OWNERS, FIRST_DUMMY, KEYED, KEYED_DUMMY, NOT_SPENDABLE, OWNER,
        PROGRAM_STATE, RING, UNSPENDABLE,
    },
    vectors::{
        a_dummy_first, in_a_ring, max_plus_max, ones, sender_then_stranger, sol, sol_then_usdc,
        threes, twos, with_state,
    },
};
use crate::{
    harness::fixture::{native, Refusal},
    protocol::transaction::wallets::dummy,
};

fn natively<P: zk_program_sdk::ZkCircuit>(
    named: Vec<(&'static str, P)>,
) -> Vec<(&'static str, Result<(), Refusal>)> {
    named
        .into_iter()
        .map(|(name, fixture)| (name, native(&fixture)))
        .collect()
}

fn holding<T>(
    named: &[(&'static str, T)],
    result: Result<(), Refusal>,
) -> Vec<(&'static str, Result<(), Refusal>)> {
    named.iter().map(|(name, _)| (*name, result)).collect()
}

#[test]
fn every_spend_holds_exactly_the_real_inputs_total_under_the_first_inputs_owner_and_asset() {
    assert_eq!(
        (natively(ones()), natively(twos()), natively(threes())),
        (
            holding(&ones(), Ok(())),
            holding(&twos(), Ok(())),
            holding(&threes(), Ok(()))
        )
    );
}

#[test]
fn a_wrong_total_owner_or_asset_breaks_exactly_its_rule() {
    let honest = || spend::<2, AS_GIVEN>([sol(300, 0), sol(200, 1)]);
    let one = Field::from(1u64);
    let other = |edit: fn(&mut Spend<2, AS_GIVEN>, Field)| {
        let mut fixture = honest();
        edit(&mut fixture, one);
        native(&fixture)
    };
    assert_eq!(
        [
            other(|fixture, one| fixture.balance = fixture.balance + one),
            other(|fixture, one| fixture.owner_hash = fixture.owner_hash + one),
            other(|fixture, one| fixture.asset_hash = fixture.asset_hash + one),
        ],
        [Err(broken(BALANCE)), Err(broken(OWNER)), Err(broken(ASSET))]
    );
}

#[test]
fn every_malformed_input_set_breaks_exactly_its_rule() {
    assert_eq!(
        [
            native(&spend::<0, AS_GIVEN>([])),
            native(&a_dummy_first()),
            native(&spend::<1, AS_GIVEN>([in_a_ring(0)])),
            native(&spend::<2, AS_GIVEN>([sol(5, 0), in_a_ring(1)])),
            native(&spend::<1, AS_GIVEN>([with_state(0)])),
            native(&spend::<2, AS_GIVEN>([sol(5, 0), with_state(1)])),
            native(&spend::<2, UNSPENDABLE>([sol(5, 0), sol(5, 1)])),
            native(&sol_then_usdc()),
            native(&sender_then_stranger()),
            native(&spend::<2, KEYED>([sol(5, 0), dummy()])),
        ],
        [
            Err(broken(AT_LEAST_ONE)),
            Err(broken(FIRST_DUMMY)),
            Err(broken(RING)),
            Err(broken(RING)),
            Err(broken(PROGRAM_STATE)),
            Err(broken(PROGRAM_STATE)),
            Err(broken(NOT_SPENDABLE)),
            Err(broken(DIFFERENT_ASSETS)),
            Err(broken(DIFFERENT_OWNERS)),
            Err(broken(KEYED_DUMMY)),
        ]
    );
}

#[test]
fn two_inputs_of_2_pow_64_minus_1_do_not_fit_the_balance() {
    assert_eq!(native(&max_plus_max()), Err(broken(BALANCE_FITS)));
}
