//! `TransferProofSystem.WriteTo` from `prover/server/prover/common/marshal.go`
//! over gnark v0.15.0's `ProvingKey.WriteTo` and `VerifyingKey.WriteTo`.

use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ff::{Field, One, Zero};
use ark_poly::Radix2EvaluationDomain;

use crate::{reader::Reader, Error};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferHeader {
    pub n_inputs: u32,
    pub n_outputs: u32,
    pub requires_p256: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    pub cardinality: u64,
    pub cardinality_inv: Fr,
    pub generator: Fr,
    pub generator_inv: Fr,
    pub multiplicative_gen: Fr,
    pub multiplicative_gen_inv: Fr,
}

#[derive(Debug, Clone)]
pub struct ProvingKey {
    pub domain: Domain,
    pub alpha_g1: G1Affine,
    pub beta_g1: G1Affine,
    pub delta_g1: G1Affine,
    pub a: Vec<G1Affine>,
    pub b_g1: Vec<G1Affine>,
    pub z: Vec<G1Affine>,
    pub k: Vec<G1Affine>,
    pub beta_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub b_g2: Vec<G2Affine>,
    pub nb_wires: usize,
    pub infinity_a: Vec<bool>,
    pub infinity_b: Vec<bool>,
}

#[derive(Debug, Clone)]
pub struct VerifyingKey {
    pub alpha_g1: G1Affine,
    pub beta_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g1: G1Affine,
    pub delta_g2: G2Affine,
    pub k: Vec<G1Affine>,
}

#[derive(Debug, Clone)]
pub struct TransferKey {
    pub header: TransferHeader,
    pub pk: ProvingKey,
    pub vk: VerifyingKey,
    pub constraint_system_offset: usize,
}

impl ProvingKey {
    pub fn nb_public(&self) -> usize {
        self.nb_wires - self.k.len()
    }

    pub fn evaluation_domain(&self) -> Radix2EvaluationDomain<Fr> {
        let domain = &self.domain;
        Radix2EvaluationDomain {
            size: domain.cardinality,
            log_size_of_group: domain.cardinality.trailing_zeros(),
            size_as_field_element: Fr::from(domain.cardinality),
            size_inv: domain.cardinality_inv,
            group_gen: domain.generator,
            group_gen_inv: domain.generator_inv,
            offset: Fr::one(),
            offset_inv: Fr::one(),
            offset_pow_size: Fr::one(),
        }
    }
}

/// Parses a combined Zolana transfer key and rejects BSB22 commitment keys.
pub fn parse_transfer_key(bytes: &[u8]) -> Result<TransferKey, Error> {
    let mut reader = Reader::new(bytes);
    let header = TransferHeader {
        n_inputs: reader.u32()?,
        n_outputs: reader.u32()?,
        requires_p256: reader.u32()? != 0,
    };
    let pk = proving_key(&mut reader)?;
    let vk = verifying_key(&mut reader)?;
    Ok(TransferKey {
        header,
        pk,
        vk,
        constraint_system_offset: reader.position(),
    })
}

fn domain(reader: &mut Reader<'_>) -> Result<Domain, Error> {
    let cardinality = reader.u64()?;
    if cardinality < 2 || !cardinality.is_power_of_two() {
        return Err(Error::DomainSize(cardinality));
    }
    let domain = Domain {
        cardinality,
        cardinality_inv: reader.fr()?,
        generator: reader.fr()?,
        generator_inv: reader.fr()?,
        multiplicative_gen: reader.fr()?,
        multiplicative_gen_inv: reader.fr()?,
    };
    reader.u8()?;
    let size = Fr::from(cardinality);
    let consistent = size * domain.cardinality_inv == Fr::one()
        && domain.generator * domain.generator_inv == Fr::one()
        && domain.multiplicative_gen * domain.multiplicative_gen_inv == Fr::one()
        && domain.generator.pow([cardinality]) == Fr::one()
        && domain.generator.pow([cardinality / 2]) != Fr::one()
        && !domain.multiplicative_gen.is_zero();
    consistent
        .then_some(domain)
        .ok_or(Error::DomainInconsistent)
}

fn proving_key(reader: &mut Reader<'_>) -> Result<ProvingKey, Error> {
    let domain = domain(reader)?;
    let alpha_g1 = reader.g1()?;
    let beta_g1 = reader.g1()?;
    let delta_g1 = reader.g1()?;
    let a = reader.g1_vec()?;
    let b_g1 = reader.g1_vec()?;
    let z_bit_reversed = reader.g1_vec()?;
    let k = reader.g1_vec()?;
    let beta_g2 = reader.g2()?;
    let delta_g2 = reader.g2()?;
    let b_g2 = reader.g2_vec()?;
    let nb_wires = reader.u64()? as usize;
    let nb_infinity_a = reader.u64()? as usize;
    let nb_infinity_b = reader.u64()? as usize;
    let infinity_a = reader.bools(nb_wires)?;
    let infinity_b = reader.bools(nb_wires)?;
    let commitment_keys = reader.u32()?;
    if commitment_keys != 0 {
        return Err(Error::CommitmentKeysUnsupported(commitment_keys));
    }
    let counts_match = infinity_a.iter().filter(|&&value| value).count() == nb_infinity_a
        && infinity_b.iter().filter(|&&value| value).count() == nb_infinity_b
        && a.len() == nb_wires - nb_infinity_a
        && b_g1.len() == nb_wires - nb_infinity_b
        && b_g2.len() == b_g1.len()
        && k.len() <= nb_wires;
    if !counts_match {
        return Err(Error::InfinityCounts);
    }
    let size = domain.cardinality as usize;
    if z_bit_reversed.len() != size - 1 {
        return Err(Error::DomainInconsistent);
    }
    Ok(ProvingKey {
        domain,
        alpha_g1,
        beta_g1,
        delta_g1,
        a,
        b_g1,
        z: monomial_order(&z_bit_reversed, size),
        k,
        beta_g2,
        delta_g2,
        b_g2,
        nb_wires,
        infinity_a,
        infinity_b,
    })
}

fn monomial_order(points: &[G1Affine], size: usize) -> Vec<G1Affine> {
    let bits = size.trailing_zeros();
    (0..size - 1)
        .map(|index| points[index.reverse_bits() >> (usize::BITS - bits)])
        .collect()
}

fn verifying_key(reader: &mut Reader<'_>) -> Result<VerifyingKey, Error> {
    let vk = VerifyingKey {
        alpha_g1: reader.g1()?,
        beta_g1: reader.g1()?,
        beta_g2: reader.g2()?,
        gamma_g2: reader.g2()?,
        delta_g1: reader.g1()?,
        delta_g2: reader.g2()?,
        k: reader.g1_vec()?,
    };
    reader.u64_vec_vec()?;
    let commitment_keys = reader.u32()?;
    if commitment_keys != 0 {
        return Err(Error::CommitmentKeysUnsupported(commitment_keys));
    }
    Ok(vk)
}
