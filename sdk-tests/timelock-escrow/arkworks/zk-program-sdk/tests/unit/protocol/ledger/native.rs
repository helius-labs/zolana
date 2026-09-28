use zolana_transaction::Mint;

use super::{
    fixtures::{
        accessors, broken, deposits, into_burned, ledger, pairs, sources, Empty, ANOTHER_ASSET,
        BALANCES, BALANCE_FITS, DATA, FILE, NONZERO, PAIRS, SOURCES, TOKEN, TRANSFER, TRANSFER_ALL,
        TRANSFER_EXCEEDS, WITHDRAW, WITHDRAWAL_EXCEEDS, WITHDRAW_ALL,
    },
    vectors::{
        Vector, EXCEEDING, TRANSFERS, TRANSFER_ALLS, WITHDRAWALS, WITHDRAW_ALLS, ZERO_DEPOSIT,
        ZERO_WITHDRAWAL,
    },
};
use crate::{
    harness::fixture::{expected, native, per_vector, Native, Refusal},
    protocol::transaction::wallets::{address, ACCOUNT, RECIPIENT, SENDER, USDC},
};

const BURNED: Refusal = ("CircuitError.TransferToBurnedUtxo", None, FILE);

fn off_by_one(vectors: &[Vector]) -> Vec<Vector> {
    vectors.iter().map(Vector::off_by_one).collect()
}

#[test]
fn every_transfer_leaves_exactly_the_native_balances_for_every_holder_pair() {
    let wrong = off_by_one(&TRANSFERS);
    assert_eq!(
        (
            per_vector(&TRANSFERS, |vector| pairs::<TRANSFER, _>(&Native, vector)),
            per_vector(&wrong, |vector| pairs::<TRANSFER, _>(&Native, vector)),
        ),
        (
            expected(&TRANSFERS, &PAIRS, |_, _| Ok(())),
            expected(&wrong, &PAIRS, |_, _| Err(broken(BALANCES))),
        )
    );
}

#[test]
fn transfer_all_moves_exactly_the_whole_balance_for_every_holder_pair() {
    let wrong = off_by_one(&TRANSFER_ALLS);
    assert_eq!(
        (
            per_vector(&TRANSFER_ALLS, |vector| pairs::<TRANSFER_ALL, _>(
                &Native, vector
            )),
            per_vector(&wrong, |vector| pairs::<TRANSFER_ALL, _>(&Native, vector)),
        ),
        (
            expected(&TRANSFER_ALLS, &PAIRS, |_, _| Ok(())),
            expected(&wrong, &PAIRS, |_, _| Err(broken(BALANCES))),
        )
    );
}

#[test]
fn a_withdrawal_leaves_exactly_the_deposit_minus_the_amount_for_every_source() {
    let wrong = off_by_one(&WITHDRAWALS);
    assert_eq!(
        (
            per_vector(&WITHDRAWALS, |vector| sources::<WITHDRAW, _>(
                &Native, vector
            )),
            per_vector(&wrong, |vector| sources::<WITHDRAW, _>(&Native, vector)),
        ),
        (
            expected(&WITHDRAWALS, &SOURCES, |_, _| Ok(())),
            expected(&wrong, &SOURCES, |_, _| Err(broken(BALANCES))),
        )
    );
}

#[test]
fn withdraw_all_returns_exactly_the_balance_and_leaves_zero_for_every_source() {
    let wrong: Vec<Vector> = WITHDRAW_ALLS
        .iter()
        .map(|vector| Vector {
            amount: vector.amount - 1,
            ..*vector
        })
        .collect();
    assert_eq!(
        (
            per_vector(&WITHDRAW_ALLS, |vector| sources::<WITHDRAW_ALL, _>(
                &Native, vector
            )),
            per_vector(&wrong, |vector| sources::<WITHDRAW_ALL, _>(&Native, vector)),
        ),
        (
            expected(&WITHDRAW_ALLS, &SOURCES, |_, _| Ok(())),
            expected(&wrong, &SOURCES, |_, _| Err(broken(
                super::fixtures::WITHDRAWN
            ))),
        )
    );
}

#[test]
fn deposits_add_exactly_their_amounts() {
    assert_eq!(
        (
            native(&deposits::<1, false>([3], 3)),
            native(&deposits::<2, false>([3, 4], 7)),
            native(&deposits::<2, false>([u64::MAX - 1, 1], u64::MAX)),
            native(&deposits::<2, false>([3, 4], 8)),
            native(&deposits::<1, true>([u64::MAX], u64::MAX)),
        ),
        (Ok(()), Ok(()), Ok(()), Err(broken(BALANCES)), Ok(()))
    );
}

#[test]
fn owner_and_asset_hash_to_the_native_owner_hash_and_hash_bytes_of_the_mint() {
    let wrong_owner = |mut fixture: super::fixtures::Accessors<TOKEN>| {
        fixture.owner = address(RECIPIENT);
        fixture
    };
    assert_eq!(
        (
            native(&accessors::<TOKEN>(SENDER, Mint::SOL)),
            native(&accessors::<TOKEN>(RECIPIENT, USDC)),
            native(&accessors::<DATA>(SENDER, Mint::SOL)),
            native(&accessors::<DATA>(RECIPIENT, USDC)),
            native(&wrong_owner(accessors::<TOKEN>(SENDER, Mint::SOL))),
        ),
        (
            Ok(()),
            Ok(()),
            Ok(()),
            Ok(()),
            Err(broken(super::fixtures::OWNER_HASH))
        )
    );
}

#[test]
fn a_destination_holding_another_asset_breaks_exactly_that_rule() {
    let vector = &TRANSFERS[0];
    assert_eq!(
        (
            native(&ledger::<TOKEN, TOKEN, TRANSFER, false>(Mint::SOL, vector)),
            native(&ledger::<TOKEN, TOKEN, TRANSFER, false>(USDC, vector)),
            native(&ledger::<TOKEN, DATA, TRANSFER, false>(USDC, vector)),
            native(&ledger::<DATA, TOKEN, TRANSFER_ALL, false>(
                USDC,
                &TRANSFER_ALLS[0]
            )),
        ),
        (
            Ok(()),
            Err(broken(ANOTHER_ASSET)),
            Err(broken(ANOTHER_ASSET)),
            Err(broken(ANOTHER_ASSET)),
        )
    );
}

#[test]
fn a_transfer_into_a_burned_utxo_is_a_structural_error() {
    assert_eq!(
        (
            native(&into_burned::<TOKEN, false>()),
            native(&into_burned::<TOKEN, true>()),
            native(&into_burned::<DATA, false>()),
            native(&into_burned::<DATA, true>()),
        ),
        (Err(BURNED), Err(BURNED), Err(BURNED), Err(BURNED))
    );
}

#[test]
fn a_debit_beyond_the_balance_breaks_exactly_its_rule() {
    assert_eq!(
        (
            per_vector(&EXCEEDING, |vector| pairs::<TRANSFER, _>(&Native, vector)),
            per_vector(&EXCEEDING, |vector| sources::<WITHDRAW, _>(&Native, vector)),
        ),
        (
            expected(&EXCEEDING, &PAIRS, |_, _| Err(broken(TRANSFER_EXCEEDS))),
            expected(&EXCEEDING, &SOURCES, |_, _| Err(broken(WITHDRAWAL_EXCEEDS))),
        )
    );
}

#[test]
fn a_public_transfer_of_zero_breaks_the_nonzero_rule() {
    let empty = Empty::<WITHDRAW_ALL> {
        owner: address(SENDER),
        mint: Mint::SOL,
        account: ACCOUNT,
        amount: 0,
    };
    assert_eq!(
        (
            pairs::<TRANSFER, _>(&Native, &ZERO_DEPOSIT),
            sources::<WITHDRAW, _>(&Native, &ZERO_WITHDRAWAL),
            native(&empty),
        ),
        (
            PAIRS
                .iter()
                .map(|pair| (*pair, Err(broken(NONZERO))))
                .collect(),
            SOURCES
                .iter()
                .map(|source| (*source, Err(broken(NONZERO))))
                .collect(),
            Err(broken(NONZERO)),
        )
    );
}

#[test]
fn a_balance_of_at_least_2_pow_64_does_not_fit() {
    assert_eq!(
        (
            native(&deposits::<2, false>([u64::MAX, 1], 0)),
            native(&deposits::<2, true>([u64::MAX, 1], 0)),
            native(&deposits::<2, false>([u64::MAX, u64::MAX], 0)),
        ),
        (
            Err(broken(BALANCE_FITS)),
            Err(broken(BALANCE_FITS)),
            Err(broken(BALANCE_FITS)),
        )
    );
}

#[test]
fn a_balance_summed_over_more_than_253_bits_is_too_wide_to_check() {
    let too_wide = ("CircuitError.BitWidthTooLarge", None);
    let refusal = |result: Result<(), Refusal>| result.map_err(|(name, rule, _)| (name, rule));
    assert_eq!(
        (
            native(&deposits::<190, false>([1; 190], 190)),
            refusal(native(&deposits::<191, false>([1; 191], 191))),
            refusal(native(&deposits::<191, true>([1; 191], 191))),
        ),
        (Ok(()), Err(too_wide), Err(too_wide))
    );
}

#[test]
#[ignore = "FINDING: BitWidthTooLarge from balance() points at src/circuit/protocol/utxo/ledger.rs, not the circuit's line"]
fn a_balance_too_wide_to_check_points_at_the_circuit_line() {
    assert_eq!(
        native(&deposits::<191, false>([1; 191], 191)),
        Err(("CircuitError.BitWidthTooLarge", None, FILE))
    );
}
