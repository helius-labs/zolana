use crate::{CircuitError, Field};

struct Parameters {
    width: usize,
    full: usize,
    partial: usize,
    ark: &'static [Field],
    mds: &'static [Field],
    pre_sparse: &'static [Field],
    sparse: &'static [Field],
}

include!(concat!(env!("OUT_DIR"), "/poseidon.rs"));

/// The SPP Poseidon construction: a zero capacity lane and arity-specific
/// light-poseidon parameters, with no sponge or length prefix.
pub fn poseidon(inputs: &[Field]) -> Result<Field, CircuitError> {
    let p = parameters(inputs.len());
    let mut state = [Field::zero(); 13];
    for (target, value) in state[1..].iter_mut().zip(inputs) { *target = *value; }
    for i in 0..p.width { state[i] += p.ark[i]; }
    let half = p.full / 2;
    for round in 0..half {
        for i in 0..p.width {
            state[i] = state[i].pow(5) + p.ark[(round + 1) * p.width + i];
        }
        state = mix(state, if round + 1 == half { p.pre_sparse } else { p.mds }, p.width);
    }
    for round in 0..p.partial {
        state[0] = state[0].pow(5) + p.ark[(half + 1) * p.width + round];
        let offset = (2 * p.width - 1) * round;
        let mut first = Field::zero();
        for i in 0..p.width { first += p.sparse[offset + i] * state[i]; }
        for i in 1..p.width {
            state[i] += state[0] * p.sparse[offset + p.width + i - 1];
        }
        state[0] = first;
    }
    for round in 0..half - 1 {
        for i in 0..p.width {
            state[i] = state[i].pow(5) + p.ark[(half + 1 + round) * p.width + p.partial + i];
        }
        state = mix(state, p.mds, p.width);
    }
    // Only lane zero is exposed; the other final MDS outputs are unused.
    let mut output = Field::zero();
    for i in 0..p.width { output += state[i].pow(5) * p.mds[i * p.width]; }
    Ok(output)
}

fn mix(state: [Field; 13], matrix: &[Field], width: usize) -> [Field; 13] {
    let mut out = [Field::zero(); 13];
    for i in 0..width {
        for j in 0..width { out[i] += matrix[j * width + i] * state[j]; }
    }
    out
}

/// The protocol packs fixed-length byte strings into 31-byte big-endian
/// chunks and folds them from the left. The length belongs to the hash domain.
/// Up to 31 bytes are packed directly without a Poseidon permutation; empty
/// input returns zero. Callers must distinguish lengths in their hash domain.
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
    let Some((first, rest)) = values.split_first() else { return Ok(Field::zero()); };
    let mut chain = *first;
    for value in rest {
        if *value != Field::zero() {
            chain = if chain == Field::zero() { *value } else { poseidon(&[chain, *value])? };
        }
    }
    Ok(chain)
}
