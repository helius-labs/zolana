use crate::circuit::{Bool, CircuitVar};

pub trait Select: Clone {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self;
}

impl Select for CircuitVar {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self {
        if_false.plus(&condition.var().times(&if_true.minus(if_false)))
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
