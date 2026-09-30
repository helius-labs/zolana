use crate::{
    circuit::{
        builtins::field::{primitive, var::collect_array},
        constant, Assert, Bool, CircuitVar, Field, Select,
    },
    CircuitError, CircuitErrorKind,
};

#[track_caller]
pub fn one_hot<const N: usize>(index: &CircuitVar) -> Result<[Bool; N], CircuitError> {
    let mut flags = Vec::with_capacity(N);
    for position in 0..N {
        flags.push(index.is_equal(&constant(Field::from(position as u64)))?);
    }
    let flags: [Bool; N] = collect_array(flags)?;
    let vars: Vec<CircuitVar> = flags.iter().map(Bool::var).collect();
    primitive::sum(&vars)
        .assert_equal(&constant(1u64), "the index is inside the array")
        .map_err(|error| match error.kind() {
            CircuitErrorKind::RuleBroken(_) => {
                error.replace_kind(CircuitErrorKind::IndexOutOfBounds { len: N })
            }
            _ => error,
        })?;
    Ok(flags)
}

#[track_caller]
pub fn select_index<T: Select, const N: usize>(
    items: &[T; N],
    index: &CircuitVar,
) -> Result<T, CircuitError> {
    let flags = one_hot::<N>(index)?;
    let mut candidates = items.iter().zip(&flags);
    let (first, _) = candidates
        .next()
        .ok_or(CircuitErrorKind::IndexOutOfBounds { len: N })?;
    Ok(candidates.fold(first.clone(), |selected, (item, flag)| {
        T::select(flag, item, &selected)
    }))
}
