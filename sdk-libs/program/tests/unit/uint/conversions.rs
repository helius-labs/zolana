//! All ten widening/narrowing alias pairs are instantiated, so a missing conversion
//! is a compile error and every narrowing boundary is checked natively and in R1CS.
use crate::{
    harness::fixture::{
        assignment, check_constraints, check_tampered, export, exported, native, size,
    },
    uint::{
        construction::fixtures::IntoVar,
        rows::{field, max, power_of_two},
    },
};
use zolana_program::{
    circuit::{Assert, CircuitVar, Constraints, Field, Uint},
    conversion::ProofInput,
    CircuitError,
};

macro_rules! conversion {
    ($module:ident, $narrow:literal, $wide:literal) => {
        mod $module {
            use super::*;
            #[derive(Clone, Debug, ProofInput)]
            pub struct Widen { pub x: Field, pub claimed: Field }
            impl Constraints for WidenCircuit {
                fn constraints(&self) -> Result<(), CircuitError> {
                    let wide = Uint::<$wide>::from(Uint::<$narrow>::try_from(&self.x)?);
                    CircuitVar::from(wide).assert_equal(&self.claimed, "converted uint")
                }
            }
            #[derive(Clone, Debug, ProofInput)]
            pub struct Narrow { pub x: Field, pub claimed: Field }
            impl Constraints for NarrowCircuit {
                fn constraints(&self) -> Result<(), CircuitError> {
                    let narrow = Uint::<$narrow>::try_from(Uint::<$wide>::try_from(&self.x)?)?;
                    CircuitVar::from(narrow).assert_equal(&self.claimed, "converted uint")
                }
            }
            proptest::proptest! {
                #![proptest_config(proptest::test_runner::Config::with_cases(24))]
                #[test]
                fn random_conversion_roundtrips_hold_and_false_claims_are_rejected(raw in proptest::prelude::any::<u128>()) {
                    let x = raw & ((1u128 << $narrow)-1);
                    let fixture = Narrow { x: x.into(), claimed: x.into() };
                    proptest::prop_assert_eq!(native(&fixture), Ok(()));
                    proptest::prop_assert_eq!(check_constraints(&fixture), Ok($wide + $narrow + 3));
                    proptest::prop_assert_eq!(check_tampered(&fixture, 2, (x+1).into()), Err(crate::harness::fixture::breaks_rule($wide + $narrow + 2, "converted uint")));
                    let widened = Widen { x: x.into(), claimed: x.into() };
                    proptest::prop_assert_eq!(native(&widened), Ok(()));
                    proptest::prop_assert_eq!(check_constraints(&widened), Ok($narrow + 2));
                    proptest::prop_assert_eq!(exported::<Widen>().first_unsatisfied(&assignment(&widened)), None);
                    proptest::prop_assert_eq!(check_tampered(&widened, 2, (x+1).into()), Err(crate::harness::fixture::breaks_rule($narrow + 1, "converted uint")));
                    let wrong = Widen { x: x.into(), claimed: (x+1).into() };
                    proptest::prop_assert_eq!(native(&wrong).map_err(|(name,rule,_)| (name,rule)), Err(("CircuitError.RuleBroken", Some("converted uint"))));
                }
            }
            #[cfg(feature = "external-tools")]
            #[test]
            fn narrowing_relation_matches_circomlib_num2bits() {
                use crate::harness::{circomlib, equivalence::{Case, SdkWitness, assert_relation_equivalent, sizes}, field::decimal};
                let compiled = circomlib::compile(concat!("uint/conversion_", stringify!($wide), "_", stringify!($narrow), ".circom"));
                let cases: Vec<_> = [ark_bn254::Fr::from(0u64), max($narrow), power_of_two($narrow), max($wide)].into_iter().map(|x| {
                    let holds = x < power_of_two($narrow);
                    let witness = [vec![ark_bn254::Fr::from(1u64), x, x], crate::uint::rows::low_bits(x, $wide), crate::uint::rows::low_bits(x, $narrow)].concat();
                    Case { name: "alias boundary", holds, fixture: Narrow { x: field(x), claimed: field(x) }, sdk_witness: SdkWitness::Explicit(witness),
                        circom: vec![("x", vec![decimal(field(x))]), ("claimed", vec![decimal(field(x))])] }
                }).collect();
                assert_relation_equivalent(&compiled, &cases);
                let (sdk, reference) = sizes::<Narrow>(&compiled);
                assert_eq!((sdk.constraints, reference.constraints), ($wide+$narrow+3, $wide+$narrow+5));
            }
            #[test]
            fn widening_preserves_the_value_and_adds_no_rows_or_variables() {
                assert_eq!(export::<Widen>(), export::<IntoVar<$narrow>>());
                for x in [ark_bn254::Fr::from(0u64), ark_bn254::Fr::from(1u64), max($narrow)] {
                    let fixture = Widen { x: field(x), claimed: field(x) };
                    assert_eq!(native(&fixture), Ok(()));
                    assert_eq!(check_constraints(&fixture), Ok($narrow + 2));
                    assert_eq!(exported::<Widen>().first_unsatisfied(&assignment(&fixture)), None);
                    assert!(check_tampered(&fixture, 2, field(x + ark_bn254::Fr::from(1u64))).is_err());
                }
            }
            #[test]
            fn narrowing_preserves_fitting_values_and_enforces_its_bound() {
                assert_eq!(size::<Narrow>().constraints, $wide + $narrow + 3);
                for x in [ark_bn254::Fr::from(0u64), ark_bn254::Fr::from(1u64), max($narrow)] {
                    let fixture = Narrow { x: field(x), claimed: field(x) };
                    assert_eq!(native(&fixture), Ok(()));
                    assert_eq!(check_constraints(&fixture), Ok($wide + $narrow + 3));
                    assert_eq!(exported::<Narrow>().first_unsatisfied(&assignment(&fixture)), None);
                    assert!(check_tampered(&fixture, 2, field(x + ark_bn254::Fr::from(1u64))).is_err());
                }
                for x in [power_of_two($narrow), max($wide)] {
                    let fixture = Narrow { x: field(x), claimed: field(x) };
                    let error = native(&fixture).expect_err("narrowing overflow");
                    assert_eq!((error.0, error.1), ("CircuitError.RuleBroken", Some(concat!("a value does not fit in ", stringify!($narrow), " bits"))));
                    let one = ark_bn254::Fr::from(1u64);
                    let witness = [vec![one, x, x], crate::uint::rows::low_bits(x, $wide), crate::uint::rows::low_bits(x, $narrow)].concat();
                    assert_eq!(exported::<Narrow>().first_unsatisfied(&witness), Some($wide + $narrow + 1));
                }
            }
        }
    }
}
conversion!(u8_u16, 8, 16);
conversion!(u8_u32, 8, 32);
conversion!(u8_u64, 8, 64);
conversion!(u8_u128, 8, 128);
conversion!(u16_u32, 16, 32);
conversion!(u16_u64, 16, 64);
conversion!(u16_u128, 16, 128);
conversion!(u32_u64, 32, 64);
conversion!(u32_u128, 32, 128);
conversion!(u64_u128, 64, 128);

#[cfg(feature = "external-tools")]
mod external {
    use super::*;
    use crate::harness::{
        circomlib,
        equivalence::{assert_relation_equivalent, Case, SdkWitness},
        fixture::export,
        snarkjs, WorkDir,
    };
    use zolana_program::ZkCircuit;
    #[test]
    fn narrowing_matches_num2bits_and_roundtrips_through_snarkjs() {
        let compiled = circomlib::compile("uint/conversion_64_8.circom");
        let fixture = u8_u64::Narrow {
            x: 255u64.into(),
            claimed: 255u64.into(),
        };
        let cases = [
            Case {
                name: "255 fits",
                holds: true,
                fixture: fixture.clone(),
                sdk_witness: SdkWitness::Assignment,
                circom: vec![("x", vec!["255".into()]), ("claimed", vec!["255".into()])],
            },
            Case {
                name: "wrong claim",
                holds: false,
                fixture: u8_u64::Narrow {
                    x: 255u64.into(),
                    claimed: 254u64.into(),
                },
                sdk_witness: SdkWitness::Tampered {
                    honest: fixture.clone(),
                    wires: vec![(2, ark_bn254::Fr::from(254u64))],
                },
                circom: vec![("x", vec!["255".into()]), ("claimed", vec!["254".into()])],
            },
        ];
        assert_relation_equivalent(&compiled, &cases);
        let work = WorkDir::new("uint-conversions-snarkjs");
        let r1cs = work.write("narrow.r1cs", &export::<u8_u64::Narrow>());
        let wtns = work.write(
            "narrow.wtns",
            &fixture.export_assignment().expect("assignment"),
        );
        assert_eq!(
            snarkjs::groth16(&work, &r1cs, &wtns),
            (true, serde_json::json!([]))
        );
    }
}

#[cfg(feature = "external-tools")]
#[test]
fn picus_checks_narrowing_determinism() {
    use crate::{
        harness::{circomlib, picus::Verdict, WorkDir},
        uint::picus_form::claim_verdicts,
    };
    let work = WorkDir::new("uint-conversion-picus");
    let reference = circomlib::compile("uint/conversion_64_8.circom");
    let (sdk, reference) = claim_verdicts::<u8_u64::Narrow>(
        &work,
        "narrow",
        &[2],
        &reference,
        &["main.claimed"],
        std::time::Duration::from_secs(20),
    );
    eprintln!("Uint narrowing Picus: SDK={sdk:?}, circom={reference:?}");
    assert_ne!(sdk, Verdict::Unsafe);
    assert_ne!(reference, Verdict::Unsafe);
}
