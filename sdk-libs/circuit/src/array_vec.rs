use core::ops::Deref;
use xark::Input;
use xark::input::{Reader, Type, Writer};

use crate::{CircuitError, CircuitErrorKind};

pub trait PaddedInput: Input + Clone {
    fn padding() -> Self;
}

/// A capacity-bounded input that always holds exactly N slots: the given items
/// followed by `T::padding()`.
///
/// Native code and the circuit see the same N slots, so iteration, `len()` and
/// the transaction shape built from them agree. The circuit reads every slot
/// from its inputs; padding is a value the circuit logic must treat as a dummy,
/// not something this type constrains.
#[derive(Clone, Copy, Debug)]
pub struct ArrayVec<T, const N: usize>([T; N]);

impl<T: PaddedInput, const N: usize> ArrayVec<T, N> {
    pub fn new(items: impl IntoIterator<Item = T>) -> Result<Self, CircuitError> {
        let mut items = items.into_iter();
        let slots = core::array::from_fn(|_| items.next().unwrap_or_else(T::padding));
        let excess = items.count();
        if excess != 0 {
            return Err(CircuitErrorKind::TooManyItems {
                capacity: N,
                found: N.saturating_add(excess),
            }
            .into());
        }
        Ok(Self(slots))
    }
}

impl<T, const N: usize> Deref for ArrayVec<T, N> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T: PaddedInput, const N: usize> Input for ArrayVec<T, N> {
    const TYPE: Type = Type::Array(&T::TYPE, N);

    fn read(r: &mut Reader<'_>) -> Self {
        Self(core::array::from_fn(|_| T::read(r)))
    }

    fn write(&self, w: &mut Writer<'_>) {
        for item in &self.0 {
            item.write(w);
        }
    }
}

impl PaddedInput for u64 {
    fn padding() -> Self {
        0
    }
}
