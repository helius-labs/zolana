use spr_program::{testing::PrivateVariableReport, ZkCircuit};
use spr_transaction::Mint;

use super::{
    fixtures::{
        accessors, balance, deposits, into_closed, pairs, sources, Balance, ANOTHER_ASSET,
        BALANCES, BALANCE_FITS, DATA, NONZERO, PAIRS, SOURCES, TOKEN, TRANSFER, TRANSFER_ALL,
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

type Transfer = Balance<TOKEN, TOKEN, TRANSFER, true>;
type TransferIntoHeld = Balance<TOKEN, TOKEN, TRANSFER, false>;

#[test]
fn every_balance_fixture_has_exactly_the_pinned_size_and_digest() {
    assert_eq!(
        [
            (size::<Transfer>(), r1cs_digest::<Transfer>()),
            (
                size::<TransferIntoHeld>(),
                r1cs_digest::<TransferIntoHeld>()
            ),
            (
                size::<Balance<TOKEN, TOKEN, TRANSFER_ALL, true>>(),
                r1cs_digest::<Balance<TOKEN, TOKEN, TRANSFER_ALL, true>>()
            ),
            (
                size::<Balance<TOKEN, TOKEN, WITHDRAW, true>>(),
                r1cs_digest::<Balance<TOKEN, TOKEN, WITHDRAW, true>>()
            ),
            (
                size::<Balance<TOKEN, TOKEN, WITHDRAW_ALL, true>>(),
                r1cs_digest::<Balance<TOKEN, TOKEN, WITHDRAW_ALL, true>>()
            ),
        ],
        [
            (
                Size {
                    constraints: 1640,
                    variables: 1642
                },
                "8ad859a97fd9c5e8176cb364182bf01fde5ebd41708e2f5a9b9acbd8d4fec0e7".to_string()
            ),
            (
                Size {
                    constraints: 1642,
                    variables: 1642
                },
                "f6fc82eef4783281d1a3f89ed7daad1b421c5440cd4c4e73d18f499132b1ef52".to_string()
            ),
            (
                Size {
                    constraints: 1575,
                    variables: 1578
                },
                "2b7f93daf3b901f1b8bf23d0fa9fc11b5d77355d0abbb9ce933444cce9175fdf".to_string()
            ),
            (
                Size {
                    constraints: 1641,
                    variables: 1643
                },
                "c581b8837a19f145b601241dd68a9d69b419d94f5fb7f6f61db829aa6db9fbd7".to_string()
            ),
            (
                Size {
                    constraints: 1577,
                    variables: 1579
                },
                "20c31b3f5b3fcb7f5e8f6f91704859121aa6e8bd3b9bfe05fc4dd36d6ba0e9a7".to_string()
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
                Balance::<TOKEN, TOKEN, TRANSFER_ALL, true>::export_r1cs().expect("r1cs")
            ),
            each(
                &SOURCES,
                Balance::<TOKEN, TOKEN, WITHDRAW, true>::export_r1cs().expect("r1cs")
            ),
            each(
                &SOURCES,
                Balance::<TOKEN, TOKEN, WITHDRAW_ALL, true>::export_r1cs().expect("r1cs")
            ),
            super::fixtures::Accessors::<TOKEN>::export_r1cs().expect("r1cs"),
        )
    );
}

#[test]
fn a_destination_built_from_the_source_asset_adds_no_asset_row_and_another_adds_exactly_two() {
    let vector = &TRANSFERS[0];
    let own = balance::<TOKEN, TOKEN, TRANSFER, true>(Mint::SOL, vector);
    let held = balance::<TOKEN, TOKEN, TRANSFER, false>(Mint::SOL, vector);
    assert_eq!(
        (
            checks(&own, ANOTHER_ASSET),
            checks(&held, ANOTHER_ASSET),
            size::<TransferIntoHeld>().constraints - size::<Transfer>().constraints,
        ),
        (vec![], vec![1573..1574, 1574..1575], 2)
    );
}

#[test]
fn each_rule_owns_exactly_its_pinned_rows() {
    let transfer = balance::<TOKEN, TOKEN, TRANSFER, true>(Mint::SOL, &TRANSFERS[0]);
    let withdraw = balance::<TOKEN, TOKEN, WITHDRAW, true>(Mint::SOL, &WITHDRAWALS[0]);
    let withdraw_all = balance::<TOKEN, TOKEN, WITHDRAW_ALL, true>(Mint::SOL, &WITHDRAW_ALLS[0]);
    let transfer_all = balance::<TOKEN, TOKEN, TRANSFER_ALL, true>(Mint::SOL, &TRANSFER_ALLS[0]);
    assert_eq!(
        (
            [NONZERO, TRANSFER_EXCEEDS, BALANCES].map(|rule| checks(&transfer, rule)),
            [NONZERO, TRANSFER_EXCEEDS, BALANCES].map(|rule| checks(&transfer_all, rule)),
            [NONZERO, WITHDRAWAL_EXCEEDS, BALANCES].map(|rule| checks(&withdraw, rule)),
            [NONZERO, WITHDRAWN, BALANCES].map(|rule| checks(&withdraw_all, rule)),
        ),
        (
            [
                vec![1572..1573],
                vec![1573..1638],
                vec![1638..1639, 1639..1640]
            ],
            [vec![1572..1573], vec![], vec![1573..1574, 1574..1575]],
            [
                vec![1572..1573, 1573..1574],
                vec![1574..1639],
                vec![1639..1640, 1640..1641]
            ],
            [
                vec![1572..1573, 1573..1574],
                vec![1574..1575],
                vec![1575..1576, 1576..1577]
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
            [vec![], vec![931..932]],
            [vec![997..1062], vec![1062..1063]],
            vec![997..1062],
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
            expected(&TRANSFERS, &PAIRS, |_, _| Ok(1640)),
            expected(&TRANSFER_ALLS, &PAIRS, |_, _| Ok(1575)),
            expected(&WITHDRAWALS, &SOURCES, |_, _| Ok(1641)),
            expected(&WITHDRAW_ALLS, &SOURCES, |_, _| Ok(1577)),
        )
    );
}

#[test]
fn a_tampered_witness_breaks_the_rule_that_owns_its_row() {
    let transfer = balance::<TOKEN, TOKEN, TRANSFER, true>(Mint::SOL, &TRANSFERS[0]);
    let withdraw = balance::<DATA, TOKEN, WITHDRAW, true>(Mint::SOL, &WITHDRAWALS[0]);
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
    let held = |mint| balance::<TOKEN, TOKEN, TRANSFER, true>(mint, vector);
    let rows = exported::<TransferIntoHeld>();
    assert_eq!(
        (
            rows.first_unsatisfied(&assignment(&held(Mint::SOL))),
            rows.first_unsatisfied(&assignment(&held(USDC))),
        ),
        (None, Some(1573))
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
            [289, 579][..count].to_vec(),
            vec![Some("a 32-byte proof input"); count],
            vec![],
        )
    };
    assert_eq!(
        (
            free(check_private_variables(&balance::<
                TOKEN,
                DATA,
                TRANSFER,
                true,
            >(
                Mint::SOL, &TRANSFERS[0]
            ))),
            free(check_private_variables(&balance::<
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
fn a_transfer_into_a_closed_utxo_is_refused_before_any_row() {
    let refusal = |result: Result<Vec<u8>, spr_program::ProverError>| {
        result.map(|_| ()).map_err(|error| error.name())
    };
    let closed = "CircuitError.TransferToClosedUtxo";
    assert_eq!(
        (
            refusal(super::fixtures::IntoClosed::<TOKEN, false>::export_r1cs()),
            refusal(super::fixtures::IntoClosed::<DATA, true>::export_r1cs()),
            check_constraints(&into_closed::<TOKEN, true>()),
            check_constraints(&into_closed::<DATA, false>()),
        ),
        (
            Err(closed),
            Err(closed),
            Err((closed, None, None)),
            Err((closed, None, None)),
        )
    );
}

#[test]
fn a_balance_too_wide_to_check_is_refused_before_any_row() {
    let too_wide = ("CircuitError.BitWidthTooLarge", super::fixtures::FILE);
    assert_eq!(
        (
            super::fixtures::Deposits::<191, false>::export_r1cs()
                .map(|_| ())
                .map_err(|error| (error.name(), error.location().file())),
            check_constraints(&deposits::<190, false>([1; 190], 190)),
        ),
        (Err(too_wide), Ok(13471))
    );
}

#[test]
fn oversized_amount_errors_keep_the_operation_location_through_the_prover() {
    use super::fixtures::{oversized_operation, Oversized, BALANCE_READ, FILE};
    fn check<const OP: usize>() {
        let (line, _) = oversized_operation(OP);
        let fixture = Oversized::<OP>;
        for error in [
            Oversized::<OP>::export_r1cs().expect_err("setup width limit"),
            fixture
                .export_assignment()
                .expect_err("assignment width limit"),
            fixture
                .check_constraints()
                .expect_err("proving width limit"),
        ] {
            assert!(matches!(
                error.circuit_error().expect("wrapped circuit error").kind(),
                spr_program::CircuitErrorKind::BitWidthTooLarge { bits: 254 }
            ));
            assert_eq!(
                (
                    error.name(),
                    error.location().file(),
                    error.location().line()
                ),
                ("CircuitError.BitWidthTooLarge", FILE, line),
            );
        }
    }
    check::<BALANCE_READ>();
    check::<WITHDRAW_ALL>();
    check::<WITHDRAW>();
    check::<TRANSFER>();
}
