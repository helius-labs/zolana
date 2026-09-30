mod external;

use ark_bn254::Fr;
use ark_ff::{One, Zero};
use proptest::prelude::*;
use zolana_program::{
    circuit::{constant, Constraints, Field},
    conversion::ProofInput,
    CircuitError,
};

use crate::harness::{
    field::{decimal, field, integer, modulus, random, MODULUS_MINUS_1},
    fixture::{
        assignment, breaks_rule, check_constraints, check_private_variables, check_tampered,
        exported, native, no_free_variable, outcome, rule_broken,
    },
    iden3::R1csHeader,
};

const RULE: &str = "the claimed product equals left times right";

#[derive(Clone, Copy, Debug, ProofInput)]
struct Product {
    left: Field,
    right: Field,
    product: Field,
}

impl Constraints for ProductCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left.assert_product(&self.right, &self.product, RULE)
    }
}

const VECTORS: [(&str, &str, &str); 6] = [
    ("0", "0", "0"),
    ("0", MODULUS_MINUS_1, "0"),
    ("1", MODULUS_MINUS_1, MODULUS_MINUS_1),
    ("2", "3", "6"),
    (MODULUS_MINUS_1, MODULUS_MINUS_1, "1"),
    (
        "18446744073709551616",
        "18446744073709551616",
        "340282366920938463463374607431768211456",
    ),
];

fn fixture((left, right, product): (&str, &str, &str)) -> Product {
    Product {
        left: field(left),
        right: field(right),
        product: field(product),
    }
}

#[test]
fn constant_and_variable_products_accept_exactly_the_independent_vectors() {
    for (left, right, product) in VECTORS {
        assert_eq!(integer(left) * integer(right) % modulus(), integer(product));
        let input = fixture((left, right, product));
        assert_eq!(native(&input), Ok(()));
        assert_eq!(check_constraints(&input), Ok(1));
        assert_eq!(
            exported::<Product>().first_unsatisfied(&assignment(&input)),
            None
        );
        let wrong = Product {
            product: Field::from(Fr::from(input.product) + Fr::one()),
            ..input
        };
        assert_eq!(native(&wrong), Err(rule_broken(RULE, file!())));
        assert_eq!(
            check_tampered(&input, 3, wrong.product),
            Err(breaks_rule(0, RULE))
        );
    }
}

#[test]
fn a_product_assertion_is_exactly_one_multiplication_row_without_an_intermediate() {
    assert_eq!(
        exported::<Product>(),
        super::rows::r1cs(
            R1csHeader::bn254(4, 0, 3, 1),
            vec![(
                vec![(Fr::one(), 1)],
                vec![(Fr::one(), 2)],
                vec![(Fr::one(), 3)]
            )],
        )
    );
    assert_eq!(
        check_private_variables(&fixture(("2", "3", "6"))),
        no_free_variable(1, 3)
    );
}

#[derive(Clone, Copy, Debug, ProofInput)]
struct Constants;

impl Constraints for ConstantsCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        constant(2u64).assert_product(&constant(3u64), &constant(6u64), RULE)
    }
}

#[test]
fn all_constant_products_add_nothing_and_wrong_constants_return_the_callers_rule() {
    assert_eq!(
        exported::<Constants>(),
        super::rows::r1cs(R1csHeader::bn254(1, 0, 0, 0), vec![])
    );
    assert_eq!(assignment(&Constants), vec![Fr::one()]);
    assert_eq!(
        outcome(constant(2u64).assert_product(&constant(3u64), &constant(7u64), RULE)),
        Err(rule_broken(RULE, file!()))
    );
}

proptest! {
    #[test]
    fn random_products_match_big_integer_arithmetic_and_bind_every_claim(
        left in any::<[u8; 32]>(), right in any::<[u8; 32]>()
    ) {
        let (left, right) = (random(left), random(right));
        let product = field(&(integer(&decimal(left)) * integer(&decimal(right)) % modulus()).to_string());
        let input = Product { left, right, product };
        prop_assert_eq!(native(&input), Ok(()));
        prop_assert_eq!(check_constraints(&input), Ok(1));
        let mut witness = assignment(&input);
        prop_assert_eq!(exported::<Product>().first_unsatisfied(&witness), None);
        let wrong = Fr::from(product) + Fr::one();
        *witness.get_mut(3).expect("product wire") = wrong;
        prop_assert_eq!(exported::<Product>().first_unsatisfied(&witness), Some(0));
        prop_assert_eq!(native(&Product { product: Field::from(wrong), ..input }), Err(rule_broken(RULE, file!())));
    }
}

#[test]
fn a_zero_factor_still_binds_the_product_while_leaving_the_other_factor_free() {
    let input = fixture(("0", "9", "0"));
    assert_eq!(check_tampered(&input, 2, Field::from(Fr::zero())), Ok(()));
    assert_eq!(
        check_tampered(&input, 3, Field::from(1u64)),
        Err(breaks_rule(0, RULE))
    );
}
