use zk_program_sdk::{testing::PrivateVariableReport, ZkCircuit};
use zolana_transaction::Mint;

use super::{
    fixtures::{
        accessors, deposits, into_burned, ledger, pairs, sources, Ledger, ANOTHER_ASSET, BALANCES,
        BALANCE_FITS, DATA, NONZERO, PAIRS, SOURCES, TOKEN, TRANSFER, TRANSFER_ALL,
        TRANSFER_EXCEEDS, WITHDRAW, WITHDRAWAL_EXCEEDS, WITHDRAWN, WITHDRAW_ALL,
    },
    vectors::{TRANSFERS, TRANSFER_ALLS, WITHDRAWALS, WITHDRAW_ALLS},
};
use crate::{
    harness::{
        digest::r1cs_digest,
        fixture::{
            assignment, check_constraints, check_private_variables, each, expected, exported,
            per_vector, size, CheckConstraints, Export, Size,
        },
    },
    protocol::transaction::{
        labels::{allocated, breaks, checks, first_wire_of, tamper},
        wallets::USDC,
    },
};

type Transfer = Ledger<TOKEN, TOKEN, TRANSFER, true>;
type TransferIntoHeld = Ledger<TOKEN, TOKEN, TRANSFER, false>;

#[test]
fn every_ledger_fixture_has_exactly_the_pinned_size_and_digest() {
    assert_eq!(
        [
            (size::<Transfer>(), r1cs_digest::<Transfer>()),
            (
                size::<TransferIntoHeld>(),
                r1cs_digest::<TransferIntoHeld>()
            ),
            (
                size::<Ledger<TOKEN, TOKEN, TRANSFER_ALL, true>>(),
                r1cs_digest::<Ledger<TOKEN, TOKEN, TRANSFER_ALL, true>>()
            ),
            (
                size::<Ledger<TOKEN, TOKEN, WITHDRAW, true>>(),
                r1cs_digest::<Ledger<TOKEN, TOKEN, WITHDRAW, true>>()
            ),
            (
                size::<Ledger<TOKEN, TOKEN, WITHDRAW_ALL, true>>(),
                r1cs_digest::<Ledger<TOKEN, TOKEN, WITHDRAW_ALL, true>>()
            ),
        ],
        [
            (
                Size {
                    constraints: 1642,
                    variables: 1644
                },
                "f087ddc82bd4d4a476e5babaf3c9ea3d644189de79431f77a6eb7028eb3db4e2".to_string()
            ),
            (
                Size {
                    constraints: 1644,
                    variables: 1644
                },
                "b8fe0c32075ab9027fe2bd09307e4d92798345297503736d6915831def6d61ea".to_string()
            ),
            (
                Size {
                    constraints: 1577,
                    variables: 1580
                },
                "c5fe4a6bf521d03bde414defd9285fd2551d068b5a19ac4a8ac6db34260b4131".to_string()
            ),
            (
                Size {
                    constraints: 1643,
                    variables: 1645
                },
                "aeac1971cda635b26731fed26cf34261af913d2cb9c29386cfaeea06966bd7f3".to_string()
            ),
            (
                Size {
                    constraints: 1579,
                    variables: 1581
                },
                "f941bd315c35bd1ed356ad4e45f170e6fb69a452213a697133ee25d7e63ac895".to_string()
            ),
        ]
    );
}

#[test]
fn token_and_data_holders_export_byte_identical_r1cs_for_every_operation() {
    let vector = &TRANSFERS[0];
    assert_eq!(
        (
            pairs::<TRANSFER, _>(&Export, vector),
            pairs::<TRANSFER_ALL, _>(&Export, vector),
            sources::<WITHDRAW, _>(&Export, vector),
            sources::<WITHDRAW_ALL, _>(&Export, vector),
            super::fixtures::Accessors::<DATA>::export_r1cs().expect("r1cs"),
        ),
        (
            each(&PAIRS, Transfer::export_r1cs().expect("r1cs")),
            each(
                &PAIRS,
                Ledger::<TOKEN, TOKEN, TRANSFER_ALL, true>::export_r1cs().expect("r1cs")
            ),
            each(
                &SOURCES,
                Ledger::<TOKEN, TOKEN, WITHDRAW, true>::export_r1cs().expect("r1cs")
            ),
            each(
                &SOURCES,
                Ledger::<TOKEN, TOKEN, WITHDRAW_ALL, true>::export_r1cs().expect("r1cs")
            ),
            super::fixtures::Accessors::<TOKEN>::export_r1cs().expect("r1cs"),
        )
    );
}

#[test]
fn a_destination_built_from_the_source_asset_adds_no_asset_row_and_another_adds_exactly_two() {
    let vector = &TRANSFERS[0];
    let own = ledger::<TOKEN, TOKEN, TRANSFER, true>(Mint::SOL, vector);
    let held = ledger::<TOKEN, TOKEN, TRANSFER, false>(Mint::SOL, vector);
    assert_eq!(
        (
            checks(&own, ANOTHER_ASSET),
            checks(&held, ANOTHER_ASSET),
            size::<TransferIntoHeld>().constraints - size::<Transfer>().constraints,
        ),
        (vec![], vec![1575..1576, 1576..1577], 2)
    );
}

#[test]
fn each_rule_owns_exactly_its_pinned_rows() {
    let transfer = ledger::<TOKEN, TOKEN, TRANSFER, true>(Mint::SOL, &TRANSFERS[0]);
    let withdraw = ledger::<TOKEN, TOKEN, WITHDRAW, true>(Mint::SOL, &WITHDRAWALS[0]);
    let withdraw_all = ledger::<TOKEN, TOKEN, WITHDRAW_ALL, true>(Mint::SOL, &WITHDRAW_ALLS[0]);
    let transfer_all = ledger::<TOKEN, TOKEN, TRANSFER_ALL, true>(Mint::SOL, &TRANSFER_ALLS[0]);
    assert_eq!(
        (
            [NONZERO, TRANSFER_EXCEEDS, BALANCES].map(|rule| checks(&transfer, rule)),
            [NONZERO, TRANSFER_EXCEEDS, BALANCES].map(|rule| checks(&transfer_all, rule)),
            [NONZERO, WITHDRAWAL_EXCEEDS, BALANCES].map(|rule| checks(&withdraw, rule)),
            [NONZERO, WITHDRAWN, BALANCES].map(|rule| checks(&withdraw_all, rule)),
        ),
        (
            [
                vec![1574..1575],
                vec![1575..1640],
                vec![1640..1641, 1641..1642]
            ],
            [vec![1574..1575], vec![], vec![1575..1576, 1576..1577]],
            [
                vec![1574..1575, 1575..1576],
                vec![1576..1641],
                vec![1641..1642, 1642..1643]
            ],
            [
                vec![1574..1575, 1575..1576],
                vec![1576..1577],
                vec![1577..1578, 1578..1579]
            ],
        )
    );
}

#[test]
fn balance_is_free_within_64_bits_and_one_range_check_beyond() {
    let one = deposits::<1, false>([3], 3);
    let two = deposits::<2, false>([3, 4], 7);
    let two_all = deposits::<2, true>([3, 4], 7);
    assert_eq!(
        (
            [BALANCE_FITS, BALANCES].map(|rule| checks(&one, rule)),
            [BALANCE_FITS, BALANCES].map(|rule| checks(&two, rule)),
            checks(&two_all, BALANCE_FITS),
            size::<super::fixtures::Deposits<2, false>>().constraints
                - size::<super::fixtures::Deposits<1, false>>().constraints,
        ),
        (
            [vec![], vec![932..933]],
            [vec![998..1063], vec![1063..1064]],
            vec![998..1063],
            1 + 65 + 65
        )
    );
}

#[test]
fn every_valid_vector_checks_exactly_the_pinned_count_for_every_holder() {
    assert_eq!(
        (
            per_vector(&TRANSFERS, |vector| pairs::<TRANSFER, _>(
                &CheckConstraints,
                vector
            )),
            per_vector(&TRANSFER_ALLS, |vector| pairs::<TRANSFER_ALL, _>(
                &CheckConstraints,
                vector
            )),
            per_vector(&WITHDRAWALS, |vector| sources::<WITHDRAW, _>(
                &CheckConstraints,
                vector
            )),
            per_vector(&WITHDRAW_ALLS, |vector| sources::<WITHDRAW_ALL, _>(
                &CheckConstraints,
                vector
            )),
        ),
        (
            expected(&TRANSFERS, &PAIRS, |_, _| Ok(1642)),
            expected(&TRANSFER_ALLS, &PAIRS, |_, _| Ok(1577)),
            expected(&WITHDRAWALS, &SOURCES, |_, _| Ok(1643)),
            expected(&WITHDRAW_ALLS, &SOURCES, |_, _| Ok(1579)),
        )
    );
}

#[test]
fn a_tampered_witness_breaks_the_rule_that_owns_its_row() {
    let transfer = ledger::<TOKEN, TOKEN, TRANSFER, true>(Mint::SOL, &TRANSFERS[0]);
    let withdraw = ledger::<DATA, TOKEN, WITHDRAW, true>(Mint::SOL, &WITHDRAWALS[0]);
    let two = deposits::<2, false>([3, 4], 7);
    let balance_wires = allocated(&transfer, "a field proof input");
    assert_eq!(
        (
            tamper(&transfer, first_wire_of(&transfer, NONZERO)),
            tamper(&transfer, first_wire_of(&transfer, TRANSFER_EXCEEDS)),
            tamper(&withdraw, first_wire_of(&withdraw, WITHDRAWAL_EXCEEDS)),
            tamper(&two, first_wire_of(&two, BALANCE_FITS)),
            balance_wires
                .iter()
                .map(|wire| tamper(&transfer, *wire))
                .collect::<Vec<_>>(),
        ),
        (
            Err(breaks(NONZERO)),
            Err(breaks(TRANSFER_EXCEEDS)),
            Err(breaks(WITHDRAWAL_EXCEEDS)),
            Err(breaks(BALANCE_FITS)),
            vec![Err(breaks(BALANCES)), Err(breaks(BALANCES))],
        )
    );
}

#[test]
fn a_witness_whose_destination_holds_another_asset_breaks_the_asset_rows() {
    let vector = &TRANSFERS[0];
    let held = |mint| ledger::<TOKEN, TOKEN, TRANSFER, true>(mint, vector);
    let rows = exported::<TransferIntoHeld>();
    assert_eq!(
        (
            rows.first_unsatisfied(&assignment(&held(Mint::SOL))),
            rows.first_unsatisfied(&assignment(&held(USDC))),
        ),
        (None, Some(1575))
    );
}

#[test]
fn balance_reads_no_owner_so_only_the_nullifier_keys_are_free() {
    let free = |fixture_report: PrivateVariableReport| {
        (
            fixture_report
                .free
                .iter()
                .map(|free| free.variable)
                .collect::<Vec<_>>(),
            fixture_report
                .free
                .iter()
                .map(|free| free.allocation.as_ref().map(|label| label.text))
                .collect::<Vec<_>>(),
            fixture_report.tolerated,
        )
    };
    let nullifier_keys = |count: usize| {
        (
            [290, 581][..count].to_vec(),
            vec![Some("a 32-byte proof input"); count],
            vec![],
        )
    };
    assert_eq!(
        (
            free(check_private_variables(&ledger::<
                TOKEN,
                DATA,
                TRANSFER,
                true,
            >(
                Mint::SOL, &TRANSFERS[0]
            ))),
            free(check_private_variables(&ledger::<
                DATA,
                TOKEN,
                WITHDRAW_ALL,
                true,
            >(
                Mint::SOL, &WITHDRAW_ALLS[0]
            ))),
            free(check_private_variables(&deposits::<2, false>([3, 4], 7))),
            free(check_private_variables(&accessors::<DATA>(5, USDC))),
        ),
        (
            nullifier_keys(2),
            nullifier_keys(2),
            nullifier_keys(1),
            nullifier_keys(0)
        )
    );
}

#[test]
fn a_transfer_into_a_burned_utxo_is_refused_before_any_row() {
    let refusal = |result: Result<Vec<u8>, zk_program_sdk::ProverError>| {
        result.map(|_| ()).map_err(|error| error.name())
    };
    let burned = "CircuitError.TransferToBurnedUtxo";
    assert_eq!(
        (
            refusal(super::fixtures::IntoBurned::<TOKEN, false>::export_r1cs()),
            refusal(super::fixtures::IntoBurned::<DATA, true>::export_r1cs()),
            check_constraints(&into_burned::<TOKEN, true>()),
            check_constraints(&into_burned::<DATA, false>()),
        ),
        (
            Err(burned),
            Err(burned),
            Err((burned, None, None)),
            Err((burned, None, None)),
        )
    );
}

#[test]
fn a_balance_too_wide_to_check_is_refused_before_any_row() {
    let too_wide = "CircuitError.BitWidthTooLarge";
    assert_eq!(
        (
            super::fixtures::Deposits::<191, false>::export_r1cs()
                .map(|_| ())
                .map_err(|error| error.name()),
            check_constraints(&deposits::<190, false>([1; 190], 190)),
        ),
        (Err(too_wide), Ok(13472))
    );
}
