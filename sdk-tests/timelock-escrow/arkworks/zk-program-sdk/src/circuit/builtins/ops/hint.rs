#[cfg(feature = "client")]
use std::{any::TypeId, cell::Cell, rc::Rc};

use ark_bn254::Fr;
use ark_relations::gr1cs::SynthesisError;

use crate::{
    circuit::{
        builtins::field::var::{collect_array, system_of},
        constant, labels, value, CircuitSystem, CircuitVar, Field, VariableRole,
    },
    CircuitError,
};

/// Witnesses a hint computed off the circuit. They are free until `constrain`
/// pins them, and synthesis refuses a hint that no constraint reads.
#[must_use = "a hint is free until `constrain` pins it"]
pub struct Unconstrained<T> {
    values: T,
    cs: CircuitSystem,
}

impl<T> Unconstrained<T> {
    #[track_caller]
    pub fn constrain<R>(
        self,
        rule: &'static str,
        body: impl FnOnce(&T) -> Result<R, CircuitError>,
    ) -> Result<R, CircuitError> {
        labels::check(&self.cs, rule, || body(&self.values))
    }
}

/// `compute` runs natively and while proving, never while the circuit's shape
/// is built, so a hint's `O` witnesses exist for every input.
#[track_caller]
pub fn hint<const I: usize, const O: usize>(
    text: &'static str,
    inputs: [&CircuitVar; I],
    compute: impl FnOnce([Field; I]) -> Result<[Field; O], CircuitError>,
) -> Result<Unconstrained<[CircuitVar; O]>, CircuitError> {
    const { assert!(I > 0, "a hint computes from at least one input") };
    let cs = system_of(inputs);
    if cs.is_none() {
        let mut values = [Field::default(); I];
        for (slot, input) in values.iter_mut().zip(inputs) {
            *slot = value(input)?;
        }
        return Ok(Unconstrained {
            values: compute(values)?.map(constant),
            cs,
        });
    }
    let outputs = match assigned(inputs) {
        Some(values) => Some(match forged(&cs, text) {
            Some(forged) => collect_array(forged)?,
            None => compute(values)?,
        }),
        None => None,
    };
    let witnesses = labels::allocate(&cs, text, VariableRole::Hint, || {
        (0..O)
            .map(|index| {
                CircuitVar::witness(&cs, || {
                    outputs
                        .as_ref()
                        .and_then(|outputs| outputs.get(index))
                        .map(|output| Fr::from(*output))
                        .ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<Vec<_>, _>>()
    })?;
    Ok(Unconstrained {
        values: collect_array(witnesses)?,
        cs,
    })
}

fn assigned<const I: usize>(inputs: [&CircuitVar; I]) -> Option<[Field; I]> {
    let values = inputs
        .iter()
        .map(|input| input.assigned().ok().map(Field::from))
        .collect::<Option<Vec<_>>>()?;
    collect_array(values).ok()
}

#[cfg(feature = "client")]
struct ForgedHint {
    text: &'static str,
    values: Vec<Field>,
    hit: Rc<Cell<bool>>,
}

#[cfg(feature = "client")]
fn forged(cs: &CircuitSystem, text: &'static str) -> Option<Vec<Field>> {
    let system = cs.borrow()?;
    let cache = system.cache_map.borrow();
    let forged = cache
        .get(&TypeId::of::<ForgedHint>())?
        .downcast_ref::<ForgedHint>()
        .filter(|forged| forged.text == text)?;
    forged.hit.set(true);
    Some(forged.values.clone())
}

#[cfg(not(feature = "client"))]
fn forged(_cs: &CircuitSystem, _text: &'static str) -> Option<Vec<Field>> {
    None
}

/// Makes every hint labelled `text` witness `values` instead of computing
/// them. The returned flag is set once such a hint is synthesized.
#[cfg(feature = "client")]
pub(crate) fn forge(cs: &CircuitSystem, text: &'static str, values: &[Field]) -> Rc<Cell<bool>> {
    let hit = Rc::new(Cell::new(false));
    if let Some(system) = cs.borrow() {
        system.cache_map.borrow_mut().insert(
            TypeId::of::<ForgedHint>(),
            Box::new(ForgedHint {
                text,
                values: values.to_vec(),
                hit: hit.clone(),
            }),
        );
    }
    hit
}
