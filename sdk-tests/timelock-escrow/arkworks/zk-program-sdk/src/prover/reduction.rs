use ark_ff::PrimeField;
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_poly::EvaluationDomain;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystemRef, SynthesisError};

pub(crate) struct CircomReduction;

type QapInstance<F> = (Vec<F>, Vec<F>, Vec<F>, F, usize, usize);

impl R1CSToQAP for CircomReduction {
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<QapInstance<F>, SynthesisError> {
        LibsnarkReduction::instance_map_with_evaluation::<F, D>(cs, t)
    }

    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &ConstraintMatrices<F>,
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> Result<Vec<F>, SynthesisError> {
        let domain =
            D::new(num_constraints + num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();
        let inputs = full_assignment
            .get(..num_inputs)
            .ok_or(SynthesisError::AssignmentMissing)?;
        if matrices.a.len() < num_constraints || matrices.b.len() < num_constraints {
            return Err(SynthesisError::AssignmentMissing);
        }

        let mut a = Vec::with_capacity(domain_size);
        let mut b = Vec::with_capacity(domain_size);
        let mut c = Vec::with_capacity(domain_size);
        for (a_row, b_row) in matrices.a.iter().zip(&matrices.b).take(num_constraints) {
            let a_value = evaluate(a_row, full_assignment)?;
            let b_value = evaluate(b_row, full_assignment)?;
            a.push(a_value);
            b.push(b_value);
            c.push(a_value * b_value);
        }
        a.extend_from_slice(inputs);
        a.resize(domain_size, F::zero());
        b.resize(domain_size, F::zero());
        c.resize(domain_size, F::zero());

        let odd_coset_shift = D::new(2 * domain_size)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?
            .element(1);
        for evaluations in [&mut a, &mut b, &mut c] {
            domain.ifft_in_place(evaluations);
            D::distribute_powers_and_mul_by_const(evaluations, odd_coset_shift, F::one());
            domain.fft_in_place(evaluations);
        }

        let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
        for (ab_i, c_i) in ab.iter_mut().zip(c) {
            *ab_i -= c_i;
        }
        Ok(ab)
    }

    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        _: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        let powers = max_power
            .checked_mul(2)
            .and_then(|powers| powers.checked_add(1))
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let mut scalars: Vec<F> =
            core::iter::successors(Some(delta_inverse), |power| Some(*power * t))
                .take(powers)
                .collect();
        D::new(powers)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?
            .ifft_in_place(&mut scalars);
        Ok(scalars.into_iter().skip(1).step_by(2).collect())
    }
}

fn evaluate<F: PrimeField>(row: &[(F, usize)], assignment: &[F]) -> Result<F, SynthesisError> {
    row.iter()
        .try_fold(F::zero(), |sum, (coefficient, variable)| {
            assignment
                .get(*variable)
                .map(|value| sum + *coefficient * value)
        })
        .ok_or(SynthesisError::AssignmentMissing)
}
