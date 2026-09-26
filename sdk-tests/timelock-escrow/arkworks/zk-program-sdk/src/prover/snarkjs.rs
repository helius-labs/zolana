use ark_ff::{BigInt, BigInteger, PrimeField};
#[cfg(feature = "setup")]
use ark_relations::r1cs::ConstraintMatrices;

use crate::{circuit::Field, RelationError};

const FIELD_BYTES: u32 = 32;

#[cfg(feature = "setup")]
pub(crate) fn r1cs(matrices: &ConstraintMatrices<Field>) -> Result<Vec<u8>, RelationError> {
    let variables = matrices.num_instance_variables + matrices.num_witness_variables;

    let mut header = Vec::new();
    header.extend_from_slice(&FIELD_BYTES.to_le_bytes());
    header.extend_from_slice(&Field::MODULUS.to_bytes_le());
    put_u32(&mut header, variables)?;
    put_u32(&mut header, 0)?;
    put_u32(
        &mut header,
        matrices.num_instance_variables.saturating_sub(1),
    )?;
    put_u32(&mut header, matrices.num_witness_variables)?;
    header.extend_from_slice(&u64_of(variables)?.to_le_bytes());
    put_u32(&mut header, matrices.num_constraints)?;

    let complete = [&matrices.a, &matrices.b, &matrices.c]
        .iter()
        .all(|rows| rows.len() == matrices.num_constraints);
    if !complete {
        return Err(RelationError::Conversion(
            "the constraint matrices do not hold every constraint",
        ));
    }

    let mut constraints = Vec::new();
    let rows = matrices.a.iter().zip(&matrices.b).zip(&matrices.c);
    for ((a, b), c) in rows {
        for row in [a, b, c] {
            put_u32(&mut constraints, row.len())?;
            for (coefficient, variable) in row {
                put_u32(&mut constraints, *variable)?;
                constraints.extend_from_slice(&coefficient.into_bigint().to_bytes_le());
            }
        }
    }

    let mut labels = Vec::new();
    for variable in 0..variables {
        labels.extend_from_slice(&u64_of(variable)?.to_le_bytes());
    }

    binary_file(b"r1cs", 1, &[(1, &header), (2, &constraints), (3, &labels)])
}

pub(crate) fn wtns(assignment: &[Field]) -> Result<Vec<u8>, RelationError> {
    let mut header = Vec::new();
    header.extend_from_slice(&FIELD_BYTES.to_le_bytes());
    header.extend_from_slice(&Field::MODULUS.to_bytes_le());
    put_u32(&mut header, assignment.len())?;

    let mut values = Vec::new();
    for value in assignment {
        values.extend_from_slice(&value.into_bigint().to_bytes_le());
    }

    binary_file(b"wtns", 2, &[(1, &header), (2, &values)])
}

pub(crate) fn read_wtns(bytes: &[u8]) -> Result<Vec<Field>, RelationError> {
    let mut file = Cursor::new(bytes);
    if file.take(4)? != b"wtns" {
        return Err(invalid("the bytes are not a wtns file"));
    }
    if file.u32()? != 2 {
        return Err(invalid("the wtns version is not 2"));
    }
    let mut header = None;
    let mut values = None;
    for _ in 0..file.u32()? {
        let kind = file.u32()?;
        let size = usize::try_from(file.u64()?).map_err(|_| invalid("a section is too large"))?;
        let payload = file.take(size)?;
        let section = match kind {
            1 => &mut header,
            2 => &mut values,
            _ => return Err(invalid("the file has an unknown section")),
        };
        if section.replace(payload).is_some() {
            return Err(invalid("a section is repeated"));
        }
    }
    file.finish()?;

    let mut header = Cursor::new(header.ok_or(invalid("the header section is missing"))?);
    let over_scalar_field = header.u32()? == FIELD_BYTES
        && header.take(FIELD_BYTES as usize)? == Field::MODULUS.to_bytes_le().as_slice();
    if !over_scalar_field {
        return Err(invalid("the values are not over the BN254 scalar field"));
    }
    let count = usize::try_from(header.u32()?).map_err(|_| invalid("the count is too large"))?;
    header.finish()?;

    let values = values.ok_or(invalid("the values section is missing"))?;
    if count.checked_mul(FIELD_BYTES as usize) != Some(values.len()) {
        return Err(invalid("the count does not match the values section"));
    }
    values
        .as_chunks::<32>()
        .0
        .iter()
        .map(|chunk| {
            let mut limbs = [0u64; 4];
            for (limb, bytes) in limbs.iter_mut().zip(chunk.as_chunks::<8>().0) {
                *limb = u64::from_le_bytes(*bytes);
            }
            Field::from_bigint(BigInt::new(limbs))
                .ok_or(RelationError::NonCanonical("a proof input"))
        })
        .collect()
}

fn invalid(problem: &'static str) -> RelationError {
    RelationError::InvalidProofInputs(problem)
}

struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], RelationError> {
        if count > self.bytes.len() {
            return Err(invalid("the file ends early"));
        }
        let (taken, rest) = self.bytes.split_at(count);
        self.bytes = rest;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RelationError> {
        self.take(N)?
            .try_into()
            .map_err(|_| invalid("the file ends early"))
    }

    fn u32(&mut self) -> Result<u32, RelationError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, RelationError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn finish(&self) -> Result<(), RelationError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(invalid("a section has trailing bytes"))
        }
    }
}

fn binary_file(
    magic: &[u8; 4],
    version: u32,
    sections: &[(u32, &[u8])],
) -> Result<Vec<u8>, RelationError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&version.to_le_bytes());
    put_u32(&mut bytes, sections.len())?;
    for (kind, payload) in sections {
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&u64_of(payload.len())?.to_le_bytes());
        bytes.extend_from_slice(payload);
    }
    Ok(bytes)
}

fn put_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), RelationError> {
    let value = u32::try_from(value)
        .map_err(|_| RelationError::Conversion("an r1cs count does not fit in 32 bits"))?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn u64_of(value: usize) -> Result<u64, RelationError> {
    u64::try_from(value)
        .map_err(|_| RelationError::Conversion("an r1cs size does not fit in 64 bits"))
}
