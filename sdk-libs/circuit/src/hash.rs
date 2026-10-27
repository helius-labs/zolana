use crate::{CircuitError, Field};

struct Parameters {
    width: usize,
    full: usize,
    partial: usize,
    ark: &'static [Field],
    mds: &'static [Field],
}

include!(concat!(env!("OUT_DIR"), "/poseidon.rs"));

/// The SPP Poseidon construction: a zero capacity lane and arity-specific
/// light-poseidon parameters, with no sponge or length prefix.
pub fn poseidon(inputs: &[Field]) -> Result<Field, CircuitError> {
    let p = parameters(inputs.len());
    let mut state = [Field::zero(); 13];
    for (target, value) in state[1..].iter_mut().zip(inputs) { *target = *value; }
    for round in 0..p.full + p.partial {
        for i in 0..p.width {
            state[i] += p.ark[round * p.width + i];
        }
        if round < p.full / 2 || round >= p.full / 2 + p.partial {
            for value in &mut state[..p.width] { *value = value.pow(5); }
        } else {
            state[0] = state[0].pow(5);
        }
        let previous = state;
        for (row, target) in state[..p.width].iter_mut().enumerate() {
            *target = Field::zero();
            for (column, value) in previous[..p.width].iter().enumerate() {
                *target += p.mds[row * p.width + column] * *value;
            }
        }
    }
    Ok(state[0])
}

/// The protocol packs fixed-length byte strings into 31-byte big-endian
/// chunks and folds them from the left. The length belongs to the hash domain.
pub fn hash_bytes(bytes: &[u8]) -> Result<Field, CircuitError> {
    let mut accumulator = None;
    for chunk in bytes.chunks(31) {
        let mut packed = Field::zero();
        for byte in chunk { packed = packed * Field::from(256u64) + Field::from(*byte); }
        accumulator = Some(match accumulator {
            None => packed,
            Some(previous) => poseidon(&[previous, packed])?,
        });
    }
    Ok(accumulator.unwrap_or_else(Field::zero))
}

pub fn nonzero_hash_chain(values: &[Field]) -> Result<Field, CircuitError> {
    let mut chain = Field::zero();
    for value in values {
        if *value != Field::zero() {
            chain = if chain == Field::zero() { *value } else { poseidon(&[chain, *value])? };
        }
    }
    Ok(chain)
}
