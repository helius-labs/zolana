use arrayvec::ArrayVec as ArrayStorage;
use core::ops::Deref;
use xark::Input;
use xark::input::{Reader, Type, Writer};

use crate::{CircuitError, CircuitErrorKind};

pub trait PaddedInput: Input + Clone {
    fn padding() -> Self;
}

/// A capacity-bounded input encoded as exactly N slots, including dummy padding.
#[derive(Clone, Debug)]
pub struct ArrayVec<T, const N: usize>(ArrayStorage<T, N>);

impl<T: PaddedInput, const N: usize> ArrayVec<T, N> {
    pub fn new(items: impl IntoIterator<Item = T>) -> Result<Self, CircuitError> {
        let mut out = ArrayStorage::new();
        for item in items {
            out.try_push(item)
                .map_err(|_| CircuitErrorKind::TooManyItems {
                    capacity: N,
                    found: N + 1,
                })?;
        }
        Ok(Self(out))
    }

    pub fn padded(&self) -> [T; N] {
        core::array::from_fn(|i| self.0.get(i).cloned().unwrap_or_else(T::padding))
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
        let mut out = ArrayStorage::new();
        for _ in 0..N {
            out.push(T::read(r));
        }
        Self(out)
    }

    fn write(&self, w: &mut Writer<'_>) {
        for item in &self.padded() {
            item.write(w);
        }
    }
}

impl PaddedInput for u64 {
    fn padding() -> Self {
        0
    }
}
