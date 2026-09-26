use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInt, One, PrimeField, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::ConstraintMatrices;

use super::groth16::{ProvingKey, VerifyingKey};
use crate::{circuit::Field, RelationError};

const G1_BYTES: usize = 64;
const G2_BYTES: usize = 128;
const FIELD_BYTES: usize = 32;
const COEFFICIENT_BYTES: usize = 12 + FIELD_BYTES;
const GROTH16: u32 = 1;
const MATRIX_A: u32 = 0;
const MATRIX_B: u32 = 1;

pub(crate) struct Zkey {
    pub(crate) proving_key: ProvingKey,
    variables: usize,
    public_inputs: usize,
    domain_size: usize,
    coefficients: Vec<Coefficient>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Coefficient {
    matrix: u32,
    constraint: u32,
    variable: u32,
    value: Field,
}

impl Zkey {
    pub(crate) fn read(bytes: &[u8]) -> Result<Self, RelationError> {
        let sections = Sections::read(bytes)?;

        let mut header = Reader::new(sections.get(1)?);
        if header.u32()? != GROTH16 {
            return Err(RelationError::InvalidZkey("the zkey is not a Groth16 key"));
        }
        header.finish()?;

        let mut groth = Reader::new(sections.get(2)?);
        groth.modulus(&Fq::MODULUS, "the zkey is not over the BN254 base field")?;
        groth.modulus(
            &Field::MODULUS,
            "the zkey is not over the BN254 scalar field",
        )?;
        let variables = groth.usize()?;
        let public_inputs = groth.usize()?;
        let domain_size = groth.usize()?;
        let alpha_g1 = non_identity(groth.g1("alpha")?, "alpha")?;
        let beta_g1 = non_identity(groth.g1("beta")?, "beta")?;
        let beta_g2 = non_identity(groth.g2("beta")?, "beta")?;
        let gamma_g2 = non_identity(groth.g2("gamma")?, "gamma")?;
        let delta_g1 = non_identity(groth.g1("delta")?, "delta")?;
        let delta_g2 = non_identity(groth.g2("delta")?, "delta")?;
        groth.finish()?;
        if delta_g2 == gamma_g2 {
            return Err(RelationError::UncontributedZkey);
        }

        let witness_variables = variables
            .checked_sub(public_inputs)
            .and_then(|count| count.checked_sub(1))
            .ok_or(RelationError::InvalidZkey(
                "the zkey has more public inputs than variables",
            ))?;

        let proving_key = ProvingKey {
            vk: VerifyingKey {
                alpha_g1,
                beta_g2,
                gamma_g2,
                delta_g2,
                gamma_abc_g1: sections.g1s(3, public_inputs + 1, "IC")?,
            },
            beta_g1,
            delta_g1,
            a_query: sections.g1s(5, variables, "A")?,
            b_g1_query: sections.g1s(6, variables, "B1")?,
            b_g2_query: sections.g2s(7, variables)?,
            l_query: sections.g1s(8, witness_variables, "C")?,
            h_query: sections.g1s(9, domain_size, "H")?,
        };

        Ok(Self {
            proving_key,
            variables,
            public_inputs,
            domain_size,
            coefficients: coefficients(sections.get(4)?)?,
        })
    }

    pub(crate) fn check_circuit(
        &self,
        matrices: &ConstraintMatrices<Field>,
    ) -> Result<(), RelationError> {
        let domain_size = GeneralEvaluationDomain::<Field>::new(
            matrices.num_constraints + matrices.num_instance_variables,
        )
        .ok_or(RelationError::KeysForAnotherCircuit)?
        .size();
        let same_shape = self.variables
            == matrices.num_instance_variables + matrices.num_witness_variables
            && self.public_inputs + 1 == matrices.num_instance_variables
            && self.domain_size == domain_size;
        if !same_shape {
            return Err(RelationError::KeysForAnotherCircuit);
        }

        let mut expected = circuit_coefficients(matrices)?;
        expected.sort_unstable();
        let mut actual = self.coefficients.clone();
        actual.sort_unstable();
        if actual != expected {
            return Err(RelationError::KeysForAnotherCircuit);
        }
        Ok(())
    }
}

fn non_identity<P: AffineRepr>(point: P, name: &'static str) -> Result<P, RelationError> {
    if point.is_zero() {
        return Err(RelationError::InvalidKeyPoint(name));
    }
    Ok(point)
}

fn circuit_coefficients(
    matrices: &ConstraintMatrices<Field>,
) -> Result<Vec<Coefficient>, RelationError> {
    let index =
        |value: usize| u32::try_from(value).map_err(|_| RelationError::KeysForAnotherCircuit);
    let mut coefficients = Vec::with_capacity(
        matrices.a_num_non_zero + matrices.b_num_non_zero + matrices.num_instance_variables,
    );
    for (matrix, rows) in [(MATRIX_A, &matrices.a), (MATRIX_B, &matrices.b)] {
        for (constraint, row) in rows.iter().enumerate() {
            for (value, variable) in row {
                coefficients.push(Coefficient {
                    matrix,
                    constraint: index(constraint)?,
                    variable: index(*variable)?,
                    value: *value,
                });
            }
        }
    }
    for variable in 0..matrices.num_instance_variables {
        coefficients.push(Coefficient {
            matrix: MATRIX_A,
            constraint: index(matrices.num_constraints + variable)?,
            variable: index(variable)?,
            value: Field::one(),
        });
    }
    Ok(coefficients)
}

fn coefficients(section: &[u8]) -> Result<Vec<Coefficient>, RelationError> {
    let mut reader = Reader::new(section);
    let count = reader.usize()?;
    let expected = count
        .checked_mul(COEFFICIENT_BYTES)
        .and_then(|size| size.checked_add(4));
    if expected != Some(section.len()) {
        return Err(RelationError::InvalidZkey(
            "the zkey coefficient section has the wrong size",
        ));
    }
    let mut coefficients = Vec::with_capacity(count);
    for _ in 0..count {
        coefficients.push(Coefficient {
            matrix: reader.u32()?,
            constraint: reader.u32()?,
            variable: reader.u32()?,
            value: reader.coefficient()?,
        });
    }
    reader.finish()?;
    Ok(coefficients)
}

struct Sections<'a> {
    sections: Vec<(u32, &'a [u8])>,
}

impl<'a> Sections<'a> {
    fn read(bytes: &'a [u8]) -> Result<Self, RelationError> {
        let mut reader = Reader::new(bytes);
        if reader.take(4)? != b"zkey" {
            return Err(RelationError::InvalidZkey("the file is not a zkey"));
        }
        if reader.u32()? != 1 {
            return Err(RelationError::InvalidZkey("the zkey version is not 1"));
        }
        let count = reader.u32()?;
        let mut sections = Vec::new();
        for _ in 0..count {
            let kind = reader.u32()?;
            let size = usize::try_from(reader.u64()?)
                .map_err(|_| RelationError::InvalidZkey("a zkey section is too large"))?;
            sections.push((kind, reader.take(size)?));
        }
        reader.finish()?;
        Ok(Self { sections })
    }

    fn get(&self, kind: u32) -> Result<&'a [u8], RelationError> {
        let mut matching = self.sections.iter().filter(|(id, _)| *id == kind);
        match (matching.next(), matching.next()) {
            (Some((_, payload)), None) => Ok(payload),
            (None, _) => Err(RelationError::InvalidZkey("a zkey section is missing")),
            (Some(_), Some(_)) => Err(RelationError::InvalidZkey("a zkey section is repeated")),
        }
    }

    fn g1s(
        &self,
        kind: u32,
        count: usize,
        name: &'static str,
    ) -> Result<Vec<G1Affine>, RelationError> {
        let mut reader = self.sized(kind, count, G1_BYTES)?;
        let points = (0..count)
            .map(|_| reader.g1(name))
            .collect::<Result<_, _>>()?;
        reader.finish()?;
        Ok(points)
    }

    fn g2s(&self, kind: u32, count: usize) -> Result<Vec<G2Affine>, RelationError> {
        let mut reader = self.sized(kind, count, G2_BYTES)?;
        let points = (0..count)
            .map(|_| reader.g2("B2"))
            .collect::<Result<_, _>>()?;
        reader.finish()?;
        Ok(points)
    }

    fn sized(
        &self,
        kind: u32,
        count: usize,
        point_bytes: usize,
    ) -> Result<Reader<'a>, RelationError> {
        let section = self.get(kind)?;
        if count.checked_mul(point_bytes) != Some(section.len()) {
            return Err(RelationError::InvalidZkey(
                "a zkey point section has the wrong size",
            ));
        }
        Ok(Reader::new(section))
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], RelationError> {
        if count > self.bytes.len() {
            return Err(RelationError::InvalidZkey("the zkey ends early"));
        }
        let (taken, rest) = self.bytes.split_at(count);
        self.bytes = rest;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RelationError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RelationError::InvalidZkey("the zkey ends early"))
    }

    fn finish(&self) -> Result<(), RelationError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(RelationError::InvalidZkey(
                "a zkey section has trailing bytes",
            ))
        }
    }

    fn u32(&mut self) -> Result<u32, RelationError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, RelationError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn usize(&mut self) -> Result<usize, RelationError> {
        usize::try_from(self.u32()?)
            .map_err(|_| RelationError::InvalidZkey("a zkey count is too large"))
    }

    fn bigint(&mut self) -> Result<BigInt<4>, RelationError> {
        let bytes: [u8; FIELD_BYTES] = self.array()?;
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *limb = u64::from_le_bytes(*chunk);
        }
        Ok(BigInt::new(limbs))
    }

    fn modulus(&mut self, modulus: &BigInt<4>, wrong: &'static str) -> Result<(), RelationError> {
        let size = self.usize()?;
        if size != FIELD_BYTES || self.bigint()? != *modulus {
            return Err(RelationError::InvalidZkey(wrong));
        }
        Ok(())
    }

    fn coefficient(&mut self) -> Result<Field, RelationError> {
        let montgomery = self.bigint()?;
        if montgomery >= Field::MODULUS {
            return Err(RelationError::InvalidZkey(
                "a zkey coefficient is not canonical",
            ));
        }
        Ok(Field::new_unchecked(
            Field::new_unchecked(montgomery).into_bigint(),
        ))
    }

    fn fq(&mut self, name: &'static str) -> Result<Fq, RelationError> {
        let montgomery = self.bigint()?;
        if montgomery >= Fq::MODULUS {
            return Err(RelationError::InvalidKeyPoint(name));
        }
        Ok(Fq::new_unchecked(montgomery))
    }

    fn g1(&mut self, name: &'static str) -> Result<G1Affine, RelationError> {
        let x = self.fq(name)?;
        let y = self.fq(name)?;
        if x.is_zero() && y.is_zero() {
            return Ok(G1Affine::identity());
        }
        let point = G1Affine::new_unchecked(x, y);
        if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(RelationError::InvalidKeyPoint(name));
        }
        Ok(point)
    }

    fn g2(&mut self, name: &'static str) -> Result<G2Affine, RelationError> {
        let x = Fq2::new(self.fq(name)?, self.fq(name)?);
        let y = Fq2::new(self.fq(name)?, self.fq(name)?);
        if x.is_zero() && y.is_zero() {
            return Ok(G2Affine::identity());
        }
        let point = G2Affine::new_unchecked(x, y);
        if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(RelationError::InvalidKeyPoint(name));
        }
        Ok(point)
    }
}
