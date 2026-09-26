use ark_bn254::{G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger256, PrimeField, Zero};
use ark_groth16::r1cs_to_qap::R1CSToQAP;
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::{ConstraintMatrices, SynthesisError};
use ark_std::cfg_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{
    groth16::{Proof, ProvingKey},
    reduction::CircomReduction,
};
use crate::{circuit::Field, RelationError};

pub(crate) fn create_proof(
    proving_key: &ProvingKey,
    r: Field,
    s: Field,
    matrices: &ConstraintMatrices<Field>,
    full_assignment: &[Field],
) -> Result<Proof, RelationError> {
    let num_inputs = matrices.num_instance_variables;
    let h = CircomReduction::witness_map_from_matrices::<Field, GeneralEvaluationDomain<Field>>(
        matrices,
        num_inputs,
        matrices.num_constraints,
        full_assignment,
    )?;
    let (h_scalars, scalars) = join(|| bigints(&h), || bigints(full_assignment));
    let assignment = scalars.get(1..).ok_or(SynthesisError::AssignmentMissing)?;
    let aux_assignment = scalars
        .get(num_inputs..)
        .ok_or(SynthesisError::AssignmentMissing)?;

    let ((h_acc, l_aux_acc), ((a_acc, b_g1_acc), b_g2_acc)) = join(
        || {
            join(
                || G1Projective::msm_bigint(&proving_key.h_query, &h_scalars),
                || G1Projective::msm_bigint(&proving_key.l_query, aux_assignment),
            )
        },
        || {
            join(
                || {
                    join(
                        || query_msm_g1(&proving_key.a_query, assignment),
                        || query_msm_g1(&proving_key.b_g1_query, assignment),
                    )
                },
                || query_msm_g2(&proving_key.b_g2_query, assignment),
            )
        },
    );

    let vk = &proving_key.vk;
    let g_a = proving_key.delta_g1 * r + first(&proving_key.a_query)? + a_acc? + vk.alpha_g1;
    let g1_b = if r.is_zero() {
        G1Projective::zero()
    } else {
        proving_key.delta_g1 * s + first(&proving_key.b_g1_query)? + b_g1_acc? + proving_key.beta_g1
    };
    let g2_b = vk.delta_g2 * s + first(&proving_key.b_g2_query)? + b_g2_acc? + vk.beta_g2;
    let g_c = g_a * s + g1_b * r - proving_key.delta_g1 * (r * s) + l_aux_acc + h_acc;
    Ok(Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    })
}

fn bigints(values: &[Field]) -> Vec<BigInteger256> {
    cfg_iter!(values).map(|value| value.into_bigint()).collect()
}

fn first<G: AffineRepr>(query: &[G]) -> Result<G, RelationError> {
    query
        .first()
        .copied()
        .ok_or(RelationError::Synthesis(SynthesisError::AssignmentMissing))
}

fn query_msm_g1(
    query: &[G1Affine],
    assignment: &[BigInteger256],
) -> Result<G1Projective, RelationError> {
    let bases = query.get(1..).ok_or(SynthesisError::AssignmentMissing)?;
    Ok(G1Projective::msm_bigint(bases, assignment))
}

fn query_msm_g2(
    query: &[G2Affine],
    assignment: &[BigInteger256],
) -> Result<G2Projective, RelationError> {
    let bases = query.get(1..).ok_or(SynthesisError::AssignmentMissing)?;
    Ok(G2Projective::msm_bigint(bases, assignment))
}

#[cfg(feature = "parallel")]
pub(crate) fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
where
    A: FnOnce() -> RA + Send,
    B: FnOnce() -> RB + Send,
    RA: Send,
    RB: Send,
{
    rayon::join(a, b)
}

#[cfg(not(feature = "parallel"))]
pub(crate) fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
where
    A: FnOnce() -> RA,
    B: FnOnce() -> RB,
{
    (a(), b())
}
