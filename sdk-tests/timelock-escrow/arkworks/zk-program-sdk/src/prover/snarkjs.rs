use ark_ff::{BigInteger, PrimeField};
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
