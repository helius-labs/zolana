use core::ops::Deref;
use tinyvec::ArrayVec as ArrayStorage;
use xark::Input;
use xark::input::{Reader, Type, Writer};

use crate::{CircuitError, CircuitErrorKind};

pub trait PaddedInput: Input + Clone {
    fn padding() -> Self;
}

/// A capacity-bounded input encoded as exactly N slots, including dummy padding.
/// Capacity must fit in tinyvec's u16 length.
#[derive(Clone, Copy, Debug)]
pub struct ArrayVec<T: Default, const N: usize>(ArrayStorage<[T; N]>);

impl<T: PaddedInput + Default, const N: usize> ArrayVec<T, N> {
    const CHECK_CAPACITY: () = assert!(N <= u16::MAX as usize, "ArrayVec capacity must fit u16");

    pub fn new(items: impl IntoIterator<Item = T>) -> Result<Self, CircuitError> {
        let () = Self::CHECK_CAPACITY;
        let mut out = ArrayStorage::new();
        for item in items {
            if out.try_push(item).is_some() {
                return Err(CircuitErrorKind::TooManyItems {
                    capacity: N,
                    found: N + 1,
                }
                .into());
            }
        }
        Ok(Self(out))
    }

    pub fn padded(&self) -> [T; N] {
        core::array::from_fn(|i| self.0.get(i).cloned().unwrap_or_else(T::padding))
    }
}

impl<T: Default, const N: usize> Deref for ArrayVec<T, N> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T: PaddedInput + Default, const N: usize> Input for ArrayVec<T, N> {
    const TYPE: Type = Type::Array(&T::TYPE, N);

    fn read(r: &mut Reader<'_>) -> Self {
        let () = Self::CHECK_CAPACITY;
        Self(ArrayStorage::from(core::array::from_fn(|_| T::read(r))))
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
