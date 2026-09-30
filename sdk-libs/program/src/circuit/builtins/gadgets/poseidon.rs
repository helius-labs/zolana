use ark_bn254::Fr;
use light_poseidon::{parameters::bn254_x5::get_poseidon_parameters, PoseidonParameters};

use crate::{
    circuit::{builtins::field::var::system_of, labels::Scope, zero, CircuitVar},
    CircuitError, CircuitErrorKind,
};

#[track_caller]
pub fn poseidon(inputs: &[CircuitVar]) -> Result<CircuitVar, CircuitError> {
    let _scope = Scope::open(&system_of(inputs), "a poseidon hash");
    let params = parameters(inputs.len())?;
    let width = params.width;
    let half_full_rounds = params.full_rounds / 2;
    let partial_rounds_end = half_full_rounds + params.partial_rounds;
    let mut state: Vec<CircuitVar> = core::iter::once(zero())
        .chain(inputs.iter().cloned())
        .collect();
    for round in 0..params.full_rounds + params.partial_rounds {
        let round_constants = params.ark.get(round * width..(round + 1) * width).ok_or(
            CircuitErrorKind::UnsupportedHashInputCount {
                inputs: inputs.len(),
            },
        )?;
        for (element, round_constant) in state.iter_mut().zip(round_constants) {
            *element = element.offset(*round_constant);
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
                    .fold(zero(), |sum, (factor, element)| {
                        sum.plus(&element.scaled(*factor))
                    })
            })
            .collect();
    }
    Ok(state
        .into_iter()
        .next()
        .ok_or(CircuitErrorKind::UnsupportedHashInputCount {
            inputs: inputs.len(),
        })?)
}

fn parameters(inputs: usize) -> Result<PoseidonParameters<Fr>, CircuitError> {
    let width = u8::try_from(inputs + 1)
        .map_err(|_| CircuitErrorKind::UnsupportedHashInputCount { inputs })?;
    let params = get_poseidon_parameters::<Fr>(width)
        .map_err(|_| CircuitErrorKind::UnsupportedHashInputCount { inputs })?;
    if params.alpha != 5 {
        return Err(CircuitErrorKind::UnsupportedHashInputCount { inputs }.into());
    }
    Ok(params)
}

fn sbox(element: &CircuitVar) -> Result<CircuitVar, CircuitError> {
    let square = element.squared()?;
    Ok(square.squared()?.times(element))
}
