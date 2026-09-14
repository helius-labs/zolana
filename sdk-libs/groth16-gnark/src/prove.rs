use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::EvaluationDomain;
use ark_std::rand::RngCore;

use crate::{Error, ProvingKey};

#[derive(Debug, Clone)]
pub struct Assignment {
    pub nb_public: usize,
    pub wires: Vec<Fr>,
    pub a: Vec<Fr>,
    pub b: Vec<Fr>,
    pub c: Vec<Fr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub ar: G1Affine,
    pub bs: G2Affine,
    pub krs: G1Affine,
}

impl Assignment {
    /// Parses the solved-assignment blob emitted by Zolana's gnark solver.
    pub fn from_blob(blob: &[u8]) -> Result<Self, Error> {
        let mut position = 0usize;
        let u32_at = |position: &mut usize| -> Result<usize, Error> {
            let bytes = blob
                .get(*position..*position + 4)
                .ok_or(Error::MalformedAssignment(*position))?;
            *position += 4;
            Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
        };
        let nb_public = u32_at(&mut position)?;
        let nb_wires = u32_at(&mut position)?;
        let wires = scalars(blob, &mut position, nb_wires)?;
        let nb_constraints = u32_at(&mut position)?;
        let a = scalars(blob, &mut position, nb_constraints)?;
        let b = scalars(blob, &mut position, nb_constraints)?;
        let c = scalars(blob, &mut position, nb_constraints)?;
        if position != blob.len() {
            return Err(Error::MalformedAssignment(position));
        }
        Ok(Self {
            nb_public,
            wires,
            a,
            b,
            c,
        })
    }
}

fn scalars(blob: &[u8], position: &mut usize, count: usize) -> Result<Vec<Fr>, Error> {
    let end = count
        .checked_mul(32)
        .and_then(|length| position.checked_add(length))
        .ok_or(Error::MalformedAssignment(*position))?;
    let bytes = blob
        .get(*position..end)
        .ok_or(Error::MalformedAssignment(*position))?;
    let values = bytes
        .chunks_exact(32)
        .enumerate()
        .map(|(index, chunk)| {
            let value = Fr::from_be_bytes_mod_order(chunk);
            (value.into_bigint().to_bytes_be() == chunk)
                .then_some(value)
                .ok_or(Error::MalformedAssignment(*position + index * 32))
        })
        .collect::<Result<Vec<_>, _>>()?;
    *position = end;
    Ok(values)
}

pub fn prove(
    proving_key: &ProvingKey,
    assignment: &Assignment,
    rng: &mut impl RngCore,
) -> Result<Proof, Error> {
    prove_with_randomness(proving_key, assignment, Fr::rand(&mut *rng), Fr::rand(rng))
}

pub fn prove_with_randomness(
    proving_key: &ProvingKey,
    assignment: &Assignment,
    r: Fr,
    s: Fr,
) -> Result<Proof, Error> {
    check(proving_key, assignment)?;
    let domain_size = proving_key.domain.cardinality as usize;
    let h = compute_h(proving_key, assignment)?;

    let wires_a: Vec<Fr> = assignment
        .wires
        .iter()
        .zip(&proving_key.infinity_a)
        .filter(|(_, infinity)| !**infinity)
        .map(|(wire, _)| *wire)
        .collect();
    let wires_b: Vec<Fr> = assignment
        .wires
        .iter()
        .zip(&proving_key.infinity_b)
        .filter(|(_, infinity)| !**infinity)
        .map(|(wire, _)| *wire)
        .collect();
    let private = &assignment.wires[assignment.nb_public..];

    let delta = G1Projective::from(proving_key.delta_g1);
    let ar = msm_g1(&proving_key.a, &wires_a) + proving_key.alpha_g1 + delta * r;
    let bs1 = msm_g1(&proving_key.b_g1, &wires_b) + proving_key.beta_g1 + delta * s;
    let bs = msm_g2(&proving_key.b_g2, &wires_b)
        + proving_key.beta_g2
        + G2Projective::from(proving_key.delta_g2) * s;
    let krs = msm_g1(&proving_key.k, private) + msm_g1(&proving_key.z, &h[..domain_size - 1])
        - delta * (r * s)
        + ar * s
        + bs1 * r;

    Ok(Proof {
        ar: ar.into_affine(),
        bs: bs.into_affine(),
        krs: krs.into_affine(),
    })
}

fn check(proving_key: &ProvingKey, assignment: &Assignment) -> Result<(), Error> {
    if assignment.wires.len() != proving_key.nb_wires {
        return Err(Error::WireCount {
            wires: assignment.wires.len(),
            expected: proving_key.nb_wires,
        });
    }
    if assignment.a.len() != assignment.b.len() || assignment.a.len() != assignment.c.len() {
        return Err(Error::UnevenAssignment);
    }
    if assignment.a.len() > proving_key.domain.cardinality as usize {
        return Err(Error::TooManyConstraints(assignment.a.len()));
    }
    if assignment.nb_public != proving_key.nb_public() {
        return Err(Error::PublicCount(assignment.nb_public));
    }
    Ok(())
}

fn compute_h(proving_key: &ProvingKey, assignment: &Assignment) -> Result<Vec<Fr>, Error> {
    let domain = proving_key.evaluation_domain();
    let size = domain.size as usize;
    let coset = domain
        .get_coset(proving_key.domain.multiplicative_gen)
        .ok_or(Error::DomainInconsistent)?;
    let denominator = (proving_key
        .domain
        .multiplicative_gen
        .pow([proving_key.domain.cardinality])
        - Fr::one())
    .inverse()
    .ok_or(Error::DomainInconsistent)?;
    let pad = |values: &[Fr]| {
        let mut output = values.to_vec();
        output.resize(size, Fr::zero());
        output
    };
    let mut a = pad(&assignment.a);
    let mut b = pad(&assignment.b);
    let mut c = pad(&assignment.c);
    domain.ifft_in_place(&mut a);
    domain.ifft_in_place(&mut b);
    domain.ifft_in_place(&mut c);
    coset.fft_in_place(&mut a);
    coset.fft_in_place(&mut b);
    coset.fft_in_place(&mut c);
    for ((a_value, b_value), c_value) in a.iter_mut().zip(&b).zip(&c) {
        *a_value = (*a_value * b_value - c_value) * denominator;
    }
    coset.ifft_in_place(&mut a);
    Ok(a)
}

fn msm_g1(bases: &[G1Affine], scalars: &[Fr]) -> G1Projective {
    G1Projective::msm(bases, scalars).unwrap_or_else(|_| G1Projective::zero())
}

fn msm_g2(bases: &[G2Affine], scalars: &[Fr]) -> G2Projective {
    G2Projective::msm(bases, scalars).unwrap_or_else(|_| G2Projective::zero())
}

impl Proof {
    pub fn is_well_formed(&self) -> bool {
        !self.ar.is_zero() && !self.bs.is_zero() && !self.krs.is_zero()
    }
}
