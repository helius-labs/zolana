use super::wallets::{address, PAYER, SENDER};
use super::{
    fixtures::{
        Asserted, Checked, Fund, Payment, Refresh, Settle, LEAVES, NO_TREE, PRIVATE_TX_HASH,
        PUBLIC_HASH, TRANSACTION_HASH,
    },
    labels::{allocated, breaks, checks, scoped, tamper, Broken},
    vectors::{forgotten, funds, payments, refreshes, settles},
};
use crate::harness::{
    digest::{r1cs_digest, sha256},
    fixture::{check_constraints, check_private_variables, size, Size},
};
use zolana_program::{
    circuit::Field,
    testing::{check_tampered, Tamper},
    ZkProgram,
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
                4195,
                4201,
                "648563b9ea6ff893057604eb693f92e67faef87dbaf98ceb4617788e5c1e597b"
            ),
            pinned(
                9748,
                9754,
                "748c43075a8b53c0bda1387f529663204a2ec6a2e10bee583eec3ffcdab7d630"
            ),
            pinned(
                8979,
                8985,
                "78c842acec0ad140a948d14264173eeea4eb807be27262f17c30c1fda52a00e7"
            ),
            pinned(
                6465,
                6470,
                "6adc78dadbc3529eacdc148d55f239e38bc8c6f96a3672c4e7b3ce82eb8a5288"
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
                .map(|(name, _)| (name, Ok(4195)))
                .collect::<Vec<_>>(),
            [Ok(9748), Ok(8979), Ok(6465)],
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
            [vec![], vec![2250..2251]],
            [vec![5644..5645], vec![5646..5647]],
            [vec![5642..5643], vec![5644..5645]],
            [vec![], vec![2735..2736]],
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
        [(0, 0), (0, 8), (0, 2), (0, 0)]
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
    fn agree<P: ZkProgram>(program: &P) {
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
    fn forged<P: ZkProgram>(program: &P) -> Option<&'static str> {
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
    fn digests<P: ZkProgram>(program: &P) -> [String; 4] {
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
        "d538ef908b826dafc5800ccd0f3ad215650b4659ebeb4b960132b3e3c9f2821b",
        "9f7640b3da532a1714a31466a4c5a148ffb54d07f0040fed2bd098de8929d75a",
        "1d9b93233947838fb89bd92d7ca0de1e7549db5e686151461375fe5dff9afe6b",
        "1262ad8b978066f99ab7fe58ff7f40c6a83b7b5c7142e2c9a7bb5b3ae7835ff3",
    ],
    [
        "0bd71bdcc617a4fa0abe5418cdabc3ebb26cfb31ebd78361bae65eff72eb38e3",
        "a5f5c09e97eb16b9ea0c3a06957c2a43ba6add5c0ae22a03ad82b3ce1cda6adb",
        "caf6eaa52c5fc9c853ed30247a88e1b78cd2e6b719b4b9d69347f8aaa2f30f10",
        "2ca032801a065bc6479559e42ee3b54534df841c40405e42c642a7f9bc279546",
    ],
    [
        "e38b7fda3443414d47aa8c0ebc8a1d549c9849c09655ad2dbb8bee34629a624a",
        "da13fdd3f4ba5e0cdb789330274e5828cf1202caf9b1a903e3f087b1a6d30b79",
        "fa7b09ace494b37044eab917242c7dff63af01c0d9f5303f74b2f8dea264d76f",
        "22466475981df2cc061b43b0c2f1f60cfef7edc937fb4f37360bb02ebed4cfe4",
    ],
    [
        "fe1e15d2514d2e7f66d25ddac6d31a9272fbd8a5208630ca7a8d9a685d7e786c",
        "31a0d33d4a8ff1f369900abcd2e453c944ec540755a5e37e31b357ea4ba988a5",
        "6a2f9d04c18abe190408a221fb89e42deed92243402ba4d9ff3a1000bea82dd7",
        "1bae2c3566190acf2905515514e3bad74cbb22831cb214773188fc28c2eacb81",
    ],
];
