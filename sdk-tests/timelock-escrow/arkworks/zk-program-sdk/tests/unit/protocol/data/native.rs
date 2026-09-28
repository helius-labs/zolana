use zk_program_sdk::{
    circuit::{checked_utxo_data, Field, UtxoData},
    conversion::{Allocator, ProofInput},
    CircuitError, ZkCircuit,
};
use zolana_transaction::Mint;

use super::{
    fixtures::{
        broken, fresh, Encoded, Held, ASSET, BALANCE, BURN_LEAVES, COMMITS, COUNT, NOT_SPENDABLE,
        OWNER, RING,
    },
    state::{Counter, Skewed},
    vectors::{a_dummy_input, a_ring_input, a_token_input, another_state, burned, holds},
};
use crate::{
    harness::fixture::{native, rule_broken, Refusal},
    protocol::transaction::wallets::{address, RECIPIENT, SENDER, USDC},
};

const NONZERO: &str = "a public transfer moves a nonzero amount";

fn names<T>(
    named: &[(&'static str, T)],
    result: Result<(), Refusal>,
) -> Vec<(&'static str, Result<(), Refusal>)> {
    named.iter().map(|(name, _)| (*name, result)).collect()
}

#[test]
fn every_held_counter_keeps_its_native_count_balance_owner_and_asset() {
    let burned_holds: Vec<_> = holds()
        .into_iter()
        .map(|(name, fixture)| {
            let Held {
                input,
                state,
                count,
                balance,
                owner_hash,
                asset_hash,
            } = fixture;
            (
                name,
                Held::<true> {
                    input,
                    state,
                    count,
                    balance,
                    owner_hash,
                    asset_hash,
                },
            )
        })
        .collect();
    assert_eq!(
        (
            holds()
                .iter()
                .map(|(name, fixture)| (*name, native(fixture)))
                .collect::<Vec<_>>(),
            burned_holds
                .iter()
                .map(|(name, fixture)| (*name, native(fixture)))
                .collect::<Vec<_>>(),
        ),
        (names(&holds(), Ok(())), names(&holds(), Ok(())))
    );
}

#[test]
fn a_wrong_count_balance_owner_or_asset_breaks_exactly_its_rule() {
    let one = Field::from(1u64);
    let edited = |edit: fn(&mut Held<false>, Field)| {
        let (_, mut fixture) = holds().swap_remove(0);
        edit(&mut fixture, one);
        native(&fixture)
    };
    assert_eq!(
        [
            edited(|fixture, one| fixture.count = fixture.count + one),
            edited(|fixture, one| fixture.balance = fixture.balance + one),
            edited(|fixture, one| fixture.owner_hash = fixture.owner_hash + one),
            edited(|fixture, one| fixture.asset_hash = fixture.asset_hash + one),
        ],
        [
            Err(broken(COUNT)),
            Err(broken(BALANCE)),
            Err(broken(OWNER)),
            Err(broken(ASSET))
        ]
    );
}

#[test]
fn an_input_that_does_not_commit_to_the_state_breaks_exactly_its_rule() {
    assert_eq!(
        [
            native(&another_state()),
            native(&a_token_input()),
            native(&a_ring_input()),
            native(&a_dummy_input()),
        ],
        [
            Err(broken(COMMITS)),
            Err(broken(COMMITS)),
            Err(broken(RING)),
            Err(broken(NOT_SPENDABLE)),
        ]
    );
}

#[test]
fn a_new_counter_starts_at_zero_under_its_owner_and_asset() {
    let mut wrong = fresh(address(SENDER), Mint::SOL);
    wrong.owner = address(RECIPIENT);
    assert_eq!(
        [
            native(&fresh(address(SENDER), Mint::SOL)),
            native(&fresh(address(RECIPIENT), USDC)),
            native(&wrong),
        ],
        [Ok(()), Ok(()), Err(broken(OWNER))]
    );
}

#[test]
fn checked_utxo_data_is_the_borsh_encoding_when_both_hashes_agree() {
    let native_state = |count: u64| {
        Counter { count }
            .instantiate(&Allocator::native())
            .expect("state")
    };
    let skewed = Skewed { count: 5 }
        .instantiate(&Allocator::native())
        .expect("skewed state");
    let encoded = |state| checked_utxo_data(&state).map_err(|error: CircuitError| error.name());
    assert_eq!(
        (
            encoded(native_state(5)),
            encoded(native_state(u64::MAX)),
            native_state(5).utxo_data().map_err(|error| error.name()),
            skewed.utxo_data().map_err(|error| error.name()),
            checked_utxo_data(&skewed).map_err(|error| error.name()),
        ),
        (
            Ok(Counter { count: 5 }.bytes()),
            Ok(Counter { count: u64::MAX }.bytes()),
            Ok(Counter { count: 5 }.bytes()),
            Ok(borsh::to_vec(&Skewed { count: 5 }).expect("skewed bytes")),
            Err("CircuitError.DataHashMismatch"),
        )
    );
}

#[test]
fn checked_utxo_data_runs_natively_only() {
    let encoded = Encoded {
        state: Counter { count: 5 },
    };
    assert_eq!(
        (
            native(&encoded),
            Encoded::export_r1cs()
                .map(|_| ())
                .map_err(|error| error.name()),
        ),
        (Ok(()), Err("CircuitError.ReadsVariableValue"))
    );
}

#[test]
fn a_burned_counter_must_leave_nothing_and_withdraw_all_empties_it() {
    assert_eq!(
        [
            native(&burned::<false>(300)),
            native(&burned::<true>(300)),
            native(&burned::<false>(0)),
            native(&burned::<true>(0)),
        ],
        [
            Err(broken(BURN_LEAVES)),
            Ok(()),
            Ok(()),
            Err(rule_broken(NONZERO, super::fixtures::FILE)),
        ]
    );
}
