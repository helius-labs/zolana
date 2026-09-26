use super::{constant, var::collect_array, zero, Assert, Bool, CircuitVar, Field};
use crate::RelationError;

pub trait Select: Clone {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self;
}

impl Select for CircuitVar {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self {
        if_false.clone() + condition.var() * (if_true.clone() - if_false)
    }
}

impl<T: Select, const N: usize> Select for [T; N] {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self {
        let mut selected = if_true.clone();
        for (slot, alternative) in selected.iter_mut().zip(if_false) {
            *slot = T::select(condition, slot, alternative);
        }
        selected
    }
}

pub fn one_hot<const N: usize>(index: &CircuitVar) -> Result<[Bool; N], RelationError> {
    let flags: [Bool; N] = collect_array(
        (0..N)
            .map(|position| index.is_equal(&constant(Field::from(position as u64))))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    flags
        .iter()
        .fold(zero(), |count, flag| count + flag.var())
        .assert_equal(&constant(1u64), "the index is inside the array")
        .map_err(|error| match error {
            RelationError::Violated(_) => RelationError::IndexOutOfBounds(N),
            error => error,
        })?;
    Ok(flags)
}

pub fn select_index<T: Select, const N: usize>(
    items: &[T; N],
    index: &CircuitVar,
) -> Result<T, RelationError> {
    let flags = one_hot::<N>(index)?;
    let mut candidates = items.iter().zip(&flags);
    let (first, _) = candidates
        .next()
        .ok_or(RelationError::IndexOutOfBounds(N))?;
    Ok(candidates.fold(first.clone(), |selected, (item, flag)| {
        T::select(flag, item, &selected)
    }))
}
