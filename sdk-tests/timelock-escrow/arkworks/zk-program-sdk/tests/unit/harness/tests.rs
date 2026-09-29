use zk_program_sdk::{
    circuit::{zero, Assert, CircuitVar, Constraints, Field},
    conversion::ProofInput,
    CircuitError,
};

use super::{
    digest::{picus_r1cs_digest, r1cs_digest, sha256},
    field::field,
    fixture::{assignment, first_unsatisfied, size, with_wires, Size},
};

const RULE: &str = "the claim is whether x is zero";
const CLAIMED_WIRE: usize = 2;

#[derive(Clone, Copy, Debug, ProofInput)]
struct IsZeroClaim {
    x: Field,
    claimed: Field,
}

impl Constraints for IsZeroClaimCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        CircuitVar::from(self.x.is_equal(&zero())?).assert_equal(&self.claimed, RULE)
    }
}

#[test]
fn sha256_digests_are_lowercase_hex() {
    assert_eq!(
        (sha256(b""), sha256(b"abc")),
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string()
        )
    );
}

#[test]
fn a_fixture_with_an_intermediate_witness_has_a_pinned_size_and_digest() {
    let honest = assignment(&IsZeroClaim {
        x: field("0"),
        claimed: field("1"),
    });
    let wrong = with_wires(honest.clone(), &[(CLAIMED_WIRE, field("0").into())]);
    assert_eq!(
        (
            size::<IsZeroClaim>(),
            r1cs_digest::<IsZeroClaim>(),
            picus_r1cs_digest::<IsZeroClaim>(),
            first_unsatisfied::<IsZeroClaim>(&honest),
            first_unsatisfied::<IsZeroClaim>(&wrong),
        ),
        (
            Size {
                constraints: 3,
                variables: 5,
            },
            "ad1d6a0004cba9b2a332920f28270cc5a54d4f0babae59c2897c1f9ac81db82d".to_string(),
            "5d26255e40920a637bacbf19b526e5b875b3deffd21db15f6b3e0d4122e9f418".to_string(),
            None,
            Some(2),
        )
    );
}

#[cfg(feature = "external-tools")]
mod external {
    use std::time::Duration;

    use ark_bn254::Fr;
    use zk_program_sdk::circuit::Field;

    use super::{IsZeroClaim, CLAIMED_WIRE};
    use crate::harness::{
        circomlib,
        equivalence::{assert_relation_equivalent, picus_verdicts, sizes, Case, SdkWitness},
        field::{decimal, field, MODULUS_MINUS_1},
        fixture::{assignment, picus_export, with_wires, Size},
        iden3::R1csHeader,
        picus::{verdict_within, Verdict},
        snarkjs::ptau_power,
        WorkDir,
    };

    fn case(name: &'static str, x: Field, claimed: Field, is_zero: bool) -> Case<IsZeroClaim> {
        let honest = IsZeroClaim {
            x,
            claimed: Field::from(u64::from(is_zero)),
        };
        let holds = claimed == honest.claimed;
        Case {
            name,
            holds,
            fixture: IsZeroClaim { x, claimed },
            sdk_witness: if holds {
                SdkWitness::Assignment
            } else {
                SdkWitness::Tampered {
                    honest,
                    wires: vec![(CLAIMED_WIRE, Fr::from(claimed))],
                }
            },
            circom: vec![("x", vec![decimal(x)]), ("claimed", vec![decimal(claimed)])],
        }
    }

    fn cases() -> Vec<Case<IsZeroClaim>> {
        let (zero, one, p_minus_1) = (field("0"), field("1"), field(MODULUS_MINUS_1));
        let two = field("2");
        let honest = IsZeroClaim {
            x: p_minus_1,
            claimed: zero,
        };
        vec![
            case("0 is zero", zero, one, true),
            case("0 is not zero", zero, zero, true),
            case("1 is not zero", one, zero, false),
            case("1 is zero", one, one, false),
            case("p - 1 is not zero", p_minus_1, zero, false),
            case("p - 1 is zero", p_minus_1, one, false),
            Case {
                name: "p - 1 claims 2",
                holds: false,
                fixture: IsZeroClaim {
                    x: p_minus_1,
                    claimed: two,
                },
                sdk_witness: SdkWitness::Explicit(with_wires(
                    assignment(&honest),
                    &[(CLAIMED_WIRE, two.into())],
                )),
                circom: vec![
                    ("x", vec![decimal(p_minus_1)]),
                    ("claimed", vec![decimal(two)]),
                ],
            },
        ]
    }

    #[test]
    fn a_circomlib_reference_is_relation_equivalent_and_deterministic() {
        let compiled = circomlib::compile("harness/is_zero.circom");
        let work = WorkDir::new("harness-is-zero");
        assert_relation_equivalent(&compiled, &cases());
        let claimed = compiled.wire("main.claimed");
        assert_eq!(
            (
                claimed,
                sizes::<IsZeroClaim>(&compiled),
                picus_verdicts::<IsZeroClaim>(
                    &work,
                    "is-zero",
                    &[CLAIMED_WIRE],
                    &compiled,
                    &[claimed],
                    Duration::from_secs(60),
                ),
            ),
            (
                2,
                (
                    Size {
                        constraints: 3,
                        variables: 5,
                    },
                    Size {
                        constraints: 4,
                        variables: 6,
                    }
                ),
                (Verdict::Safe, Verdict::Safe)
            )
        );
    }

    #[test]
    fn a_picus_run_past_its_limit_is_unknown() {
        let work = WorkDir::new("harness-picus-limit");
        assert_eq!(
            verdict_within(
                &work,
                "is-zero",
                &picus_export::<IsZeroClaim>(),
                Duration::ZERO
            ),
            Verdict::Unknown
        );
    }

    #[test]
    fn the_ptau_power_is_the_smallest_snarkjs_accepts_and_at_least_4() {
        let power = |constraints, public_inputs| {
            ptau_power(&R1csHeader::bn254(0, public_inputs, 0, constraints))
        };
        assert_eq!(
            [
                power(0, 0),
                power(1, 0),
                power(15, 0),
                power(16, 0),
                power(15, 1),
                power(1023, 0),
                power(1024, 0),
                power(40_000, 1),
            ],
            [4, 4, 4, 5, 5, 10, 11, 16]
        );
    }
}
