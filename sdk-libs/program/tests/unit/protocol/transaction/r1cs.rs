use super::wallets::{address, PAYER, SENDER};
use super::{
    fixtures::{
        Asserted, Checked, Fund, Payment, Refresh, Settle, LEAVES, NO_TREE, PRIVATE_TX_HASH,
        PUBLIC_HASH, TRANSACTION_HASH,
    },
    labels::{allocated, breaks, checks, scoped, tamper, Broken},
    vectors::{forgotten, funds, payments, refreshes, settles, swept},
};
use crate::harness::{
    digest::{r1cs_digest, sha256},
    fixture::{check_constraints, check_private_variables, size, Size},
};
use zolana_program::{
    circuit::Field,
    testing::{check_tampered, Tamper},
    ZkProgramCircuit,
};

const PROOF_INPUTS_BREAK_RULE: &str = "ProverError.ProofInputsBreakRule";
const BOOL_RULE: &str = "a bool proof input is neither 0 nor 1";
const U16_RULE: &str = "a u16 proof input does not fit in 16 bits";
const EMPTINESS: &str = "whether a token output is empty";
const PUBLIC_HASH_BINDING: &str = "the circuit's public hash is not the proof's public input";

const fn inside_scope(scope: &'static str) -> Broken {
    (PROOF_INPUTS_BREAK_RULE, Some(scope), false)
}

fn pinned(constraints: usize, variables: usize, digest: &str) -> (Size, String) {
    (
        Size {
            constraints,
            variables,
        },
        digest.to_string(),
    )
}

#[test]
fn every_shape_has_exactly_the_pinned_size_and_digest() {
    assert_eq!(
        [
            (
                size::<Asserted<Refresh>>(),
                r1cs_digest::<Asserted<Refresh>>()
            ),
            (
                size::<Asserted<Payment>>(),
                r1cs_digest::<Asserted<Payment>>()
            ),
            (size::<Asserted<Fund>>(), r1cs_digest::<Asserted<Fund>>()),
            (
                size::<Asserted<Settle>>(),
                r1cs_digest::<Asserted<Settle>>()
            ),
        ],
        [
            pinned(
                4204,
                4204,
                "ef22b8cd30baefeebb1bbb3ee674effaf99fa40092dcff5b5128cee476b615da"
            ),
            pinned(
                10700,
                10700,
                "9c0b5d8fa40bc7d3e2ef25cb7161f16a8694e4e2c79c8ee3df1404dced88cfce"
            ),
            pinned(
                8997,
                8997,
                "606e4c0b9ad4ddb769af46cce40d5c64b218ee1a81093af785e77b00a7e1c3b2"
            ),
            // Settle shares one account hash between deposit and withdrawal, saving
            // one two-field Poseidon hash (240 rows) compared with uncached addresses.
            pinned(
                6234,
                6233,
                "fc28189198e0b6ea47f63efac912ea60bb848add7b00375018f37a16befc5711"
            ),
        ]
    );
}

#[test]
fn every_refresh_and_one_of_each_other_shape_checks_exactly_the_pinned_count() {
    assert_eq!(
        (
            refreshes()
                .into_iter()
                .map(|(name, program)| (name, check_constraints(&Asserted::honest(program))))
                .collect::<Vec<_>>(),
            [
                check_constraints(&Asserted::honest(payments().swap_remove(0).1)),
                check_constraints(&Asserted::honest(funds().swap_remove(0).1)),
                check_constraints(&Asserted::honest(settles().swap_remove(0).1)),
            ],
        ),
        (
            refreshes()
                .into_iter()
                .map(|(name, _)| (name, Ok(4204)))
                .collect::<Vec<_>>(),
            [Ok(10700), Ok(8997), Ok(6234)],
        )
    );
}

#[test]
fn each_tampered_hash_claim_breaks_exactly_its_rule() {
    let fixture = Asserted::honest(refreshes().swap_remove(0).1);
    assert_eq!(
        allocated(&fixture, "a field proof input")
            .into_iter()
            .map(|wire| tamper(&fixture, wire))
            .collect::<Vec<_>>(),
        vec![
            Err(breaks(PRIVATE_TX_HASH)),
            Err(breaks(TRANSACTION_HASH)),
            Err(breaks(PUBLIC_HASH)),
        ]
    );
}

#[test]
fn the_balance_and_tree_rules_own_rows_only_where_a_value_is_variable() {
    let refresh = Asserted::honest(refreshes().swap_remove(0).1);
    let payment = Asserted::honest(payments().swap_remove(0).1);
    let fund = Asserted::honest(funds().swap_remove(0).1);
    let settle = Asserted::honest(settles().swap_remove(0).1);
    assert_eq!(
        (
            [checks(&refresh, LEAVES), checks(&refresh, NO_TREE)],
            [checks(&payment, LEAVES), checks(&payment, NO_TREE)],
            [checks(&fund, LEAVES), checks(&fund, NO_TREE)],
            [checks(&settle, LEAVES), checks(&settle, NO_TREE)],
        ),
        (
            [vec![], vec![2259..2260]],
            [vec![5819..5820], vec![5821..5822]],
            [vec![5660..5661], vec![5662..5663]],
            [vec![], vec![2744..2745]],
        )
    );
}

#[test]
fn only_the_first_nullifier_enters_the_program_circuit_and_the_rest_are_carried() {
    let payment = Asserted::honest(payments().swap_remove(0).1);
    let nullifiers = allocated(&payment, "utxo nullifier");
    let latest_trees = allocated(&payment, "utxo latest tree id");
    assert_eq!(
        (
            nullifiers
                .iter()
                .map(|wire| tamper(&payment, *wire))
                .collect::<Vec<_>>(),
            latest_trees
                .iter()
                .map(|wire| tamper(&payment, *wire))
                .collect::<Vec<_>>(),
        ),
        (
            vec![Err(inside_scope("a poseidon hash")), Ok(()), Ok(())],
            vec![
                Err(inside_scope("the transaction's outputs and hashes")),
                Ok(()),
                Ok(())
            ],
        )
    );
}

#[test]
fn a_tampered_context_breaks_its_range_or_booleanity_row() {
    let payment = Asserted::honest(payments().swap_remove(0).1);
    let from_latest = Asserted::honest(refreshes().swap_remove(2).1);
    let [uses_tree, ..] = allocated(&payment, "a bool proof input")[..] else {
        unreachable!("the context's bool comes first")
    };
    let tree_id = allocated(&payment, "a u16 proof input")[0];
    assert_eq!(
        [
            tamper(&payment, tree_id),
            tamper(&payment, uses_tree),
            tamper(&from_latest, uses_tree),
        ],
        [
            Err(breaks(U16_RULE)),
            Err(breaks(BOOL_RULE)),
            Err(inside_scope("the transaction's outputs and hashes")),
        ]
    );
}

#[test]
fn a_prover_cannot_flip_whether_a_token_output_is_empty_and_only_a_zero_amounts_hint_is_free() {
    let [(_, kept), (_, emptied), _] = <[_; 3]>::try_from(payments()).expect("three payments");
    let tampered = |program| {
        let fixture = Asserted::honest(program);
        scoped(&fixture, EMPTINESS)
            .into_iter()
            .map(|wire| tamper(&fixture, wire))
            .collect::<Vec<_>>()
    };
    let refused = Err(inside_scope("an equality test"));
    assert_eq!(
        (tampered(kept), tampered(emptied)),
        (
            vec![refused, refused, refused, refused],
            vec![refused, refused, refused, Ok(())],
        )
    );
}

#[test]
fn no_variable_is_free_and_only_carried_spend_values_are_tolerated() {
    let report = |free_and_tolerated: zolana_program::testing::PrivateVariableReport| {
        (
            free_and_tolerated.free.len(),
            free_and_tolerated.tolerated.len(),
        )
    };
    assert_eq!(
        [
            report(check_private_variables(&Asserted::honest(
                refreshes().swap_remove(0).1
            ))),
            report(check_private_variables(&Asserted::honest(
                payments().swap_remove(0).1
            ))),
            report(check_private_variables(&Asserted::honest(
                funds().swap_remove(0).1
            ))),
            report(check_private_variables(&Asserted::honest(
                settles().swap_remove(0).1
            ))),
        ],
        [(0, 0), (0, 9), (0, 2), (0, 0)]
    );
}

#[test]
fn the_prover_refuses_value_that_leaves_the_transaction() {
    assert_eq!(
        check_constraints(&Checked {
            program: forgotten()
        }),
        Err(("CircuitError.RuleBroken", None, None))
    );
}

/// One fixture of each program shape, the way a client holds it.
fn programs() -> (Refresh, Payment, Fund, Settle) {
    (
        refreshes().first().expect("refreshes fixture").1.clone(),
        payments().first().expect("payments fixture").1.clone(),
        funds().first().expect("funds fixture").1.clone(),
        settles().first().expect("settles fixture").1.clone(),
    )
}

#[test]
fn a_program_transaction_carries_the_programs_own_proof_inputs() {
    fn agree<P: ZkProgramCircuit>(program: &P) {
        let transaction = program
            .create_program_transaction(&address(SENDER), PAYER)
            .unwrap();
        let inputs = program.proof_inputs().unwrap();
        assert_eq!(
            transaction.proof_inputs.to_bytes().unwrap(),
            inputs.to_bytes().unwrap()
        );
        assert_eq!(
            vec![transaction.public_hash],
            inputs.public_inputs().unwrap()
        );
    }
    let (refresh, payment, fund, settle) = programs();
    agree(&refresh);
    agree(&payment);
    agree(&fund);
    agree(&settle);
}

#[test]
fn a_forged_public_hash_breaks_the_public_hash_binding() {
    fn forged<P: ZkProgramCircuit>(program: &P) -> Option<&'static str> {
        check_tampered(program, Tamper::PublicHash(Field::from(0u64)))
            .expect_err("a forged public hash must be refused")
            .broken_rule()
    }
    let (refresh, payment, fund, settle) = programs();
    assert_eq!(
        [
            forged(&refresh),
            forged(&payment),
            forged(&fund),
            forged(&settle)
        ],
        [Some(PUBLIC_HASH_BINDING); 4]
    );
}

/// Pins each program shape's exported constraints, its assignment and its
/// public hash. A change here changes the program's proving key: the R1CS and
/// Picus digests move with any added, removed or reordered row or variable
/// (including the public hash allocation order), the `.wtns` digest with any
/// change to the assignment, and the public hash with the transaction hashing.
#[test]
fn program_r1cs_assignment_and_public_hash_digests_are_pinned() {
    fn digests<P: ZkProgramCircuit>(program: &P) -> [String; 4] {
        let [public_hash] = program.proof_inputs().unwrap().public_inputs().unwrap()[..] else {
            panic!("a program has exactly one public input");
        };
        [
            sha256(&P::export_r1cs().unwrap()),
            sha256(&P::export_picus_r1cs().unwrap()),
            sha256(&program.export_assignment().unwrap()),
            hex::encode(public_hash),
        ]
    }
    let (refresh, payment, fund, settle) = programs();
    assert_eq!(
        [
            digests(&refresh),
            digests(&payment),
            digests(&fund),
            digests(&settle)
        ],
        PROGRAM_DIGESTS
    );
}

// Rows: refresh, payment, fund, settle. Columns: R1CS, Picus R1CS, WTNS, public hash.
const PROGRAM_DIGESTS: [[&str; 4]; 4] = [
    [
        "81db26551d2d90ffab46c87183b65b0b88a8ceba3ff4e2c52f3315f0ea54e51f",
        "49dbb526cc8776943a301a9746f11ee8dd248c3fe05ff0b79d0a182f17cf0654",
        "58be4572c790e62c1c3dc23bb8123a50c5931ab94496558c92ac2272093f9031",
        "1262ad8b978066f99ab7fe58ff7f40c6a83b7b5c7142e2c9a7bb5b3ae7835ff3",
    ],
    [
        "9cea6f7c74326343563826489647963297c72902bc83ee8c5928473f95e2ce36",
        "4a7148af03ad96a5d9bc0a15a96e21f69c6ef00c8b9bea685a73019fb793d946",
        "97b7bcbe81a6fc4b8ecf50984460c194cf0ca3ea744ec769874a857ac23f9755",
        "00ab9a4969c8eda551d93955a0d8c831a869e1a3c635a10aee5358b8b23616e2",
    ],
    [
        "398dc661f890cadbc3de360ba2dffa6c9d515568b0c2a96cd18540c65639d9be",
        "4f764322e38ba8ae831dadc5750a46a2cc37d8325bd2e3153ab63d8f53a7d358",
        "91f3b27bdf29ad8f6bbe141e5cafd240858833a69197b2da6101c708918b8214",
        "22466475981df2cc061b43b0c2f1f60cfef7edc937fb4f37360bb02ebed4cfe4",
    ],
    [
        "27a591fae137b594301495ce9da44a5943bfdd1fe5b8cbfe9b0fe6eaefe4f4f8",
        "6422be7de1bfce3e9eb7fbc3f686ad809919062cbc58f1b3e670216834d7a29b",
        "f7cbdbc90484b2da6bb722ee70d6e5ece22462f0568b76ff531b4f5f660d6769",
        "1bae2c3566190acf2905515514e3bad74cbb22831cb214773188fc28c2eacb81",
    ],
];

#[test]
fn closing_requires_zero_balance_regardless_of_the_zero_output_option() {
    let checked = |program| check_constraints(&Checked { program }).map(|_| ());
    assert_eq!(
        (
            check_constraints(&Asserted::honest(swept::<true>(300))).map(|_| ()),
            checked(swept::<false>(0)),
            checked(swept::<false>(300)),
        ),
        (Ok(()), Ok(()), Err(("CircuitError.RuleBroken", None, None)),),
        "closing after balance operations must constrain the final balance and suppress outputs"
    );
}
