use ark_r1cs_std::fields::FieldVar;
use light_poseidon::{parameters::bn254_x5::get_poseidon_parameters, PoseidonParameters};

use crate::{
    circuit::{CircuitVar, Field},
    RelationError,
};

pub fn poseidon(inputs: &[CircuitVar]) -> Result<CircuitVar, RelationError> {
    let params = parameters(inputs.len())?;
    let width = params.width;
    let half_full_rounds = params.full_rounds / 2;
    let partial_rounds_end = half_full_rounds + params.partial_rounds;
    let mut state: Vec<CircuitVar> = core::iter::once(CircuitVar::zero())
        .chain(inputs.iter().cloned())
        .collect();
    for round in 0..params.full_rounds + params.partial_rounds {
        let round_constants = params
            .ark
            .get(round * width..(round + 1) * width)
            .ok_or(RelationError::PoseidonArity(inputs.len()))?;
        for (element, round_constant) in state.iter_mut().zip(round_constants) {
            *element += *round_constant;
        }
        if round < half_full_rounds || round >= partial_rounds_end {
            for element in state.iter_mut() {
                *element = sbox(element)?;
            }
        } else if let Some(first) = state.first_mut() {
            *first = sbox(first)?;
        }
        state = params
            .mds
            .iter()
            .map(|row| {
                row.iter()
                    .zip(&state)
                    .fold(CircuitVar::zero(), |sum, (factor, element)| {
                        sum + element * *factor
                    })
            })
            .collect();
    }
    state
        .into_iter()
        .next()
        .ok_or(RelationError::PoseidonArity(inputs.len()))
}

fn parameters(inputs: usize) -> Result<PoseidonParameters<Field>, RelationError> {
    let width = u8::try_from(inputs + 1).map_err(|_| RelationError::PoseidonArity(inputs))?;
    let params = get_poseidon_parameters::<Field>(width)
        .map_err(|_| RelationError::PoseidonArity(inputs))?;
    if params.alpha != 5 {
        return Err(RelationError::PoseidonArity(inputs));
    }
    Ok(params)
}

fn sbox(element: &CircuitVar) -> Result<CircuitVar, RelationError> {
    let square = element.square()?;
    Ok(square.square()? * element)
}
