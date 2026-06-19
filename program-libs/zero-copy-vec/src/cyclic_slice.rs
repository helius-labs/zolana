use core::{
    fmt::{self, Debug},
    marker::PhantomData,
    mem::{size_of, MaybeUninit},
    ops::{Index, IndexMut},
};
#[cfg(feature = "std")]
use std::vec::Vec;

use wincode::{config::ConfigCore, io::Reader, ReadError, ReadResult, SchemaRead, TypeMeta};
use zerocopy::Ref;

use crate::{add_padding, errors::ZeroCopyError, ZeroCopyTraits};

/// Cyclic ring buffer backed by mutable bytes.
///
/// Wire format: `[current_index: u64 LE][length: u64 LE][capacity: u64 LE][padding for align(T)][T; capacity]`.
///
/// Layout-compatible with `light_zero_copy::cyclic_vec::ZeroCopyCyclicVecU64<T>` from crates.io 0.6.0.
pub struct CyclicSliceMut<'a, T>
where
    T: ZeroCopyTraits,
{
    /// `[current_index, length, capacity]` header.
    metadata: Ref<&'a mut [u8], [u64; 3]>,
    slice: Ref<&'a mut [u8], [T]>,
}

const CURRENT_INDEX_INDEX: usize = 0;
const LENGTH_INDEX: usize = 1;
const CAPACITY_INDEX: usize = 2;

impl<'a, T> CyclicSliceMut<'a, T>
where
    T: ZeroCopyTraits,
{
    pub fn new(capacity: u64, bytes: &'a mut [u8]) -> Result<Self, ZeroCopyError> {
        Ok(Self::new_at(capacity, bytes)?.0)
    }

    pub fn new_at(
        capacity: u64,
        bytes: &'a mut [u8],
    ) -> Result<(Self, &'a mut [u8]), ZeroCopyError> {
        if capacity == 0 {
            return Err(ZeroCopyError::InvalidCapacity);
        }
        let metadata_size = Self::metadata_size();
        if bytes.len() < metadata_size {
            return Err(ZeroCopyError::InsufficientMemoryAllocated(
                bytes.len(),
                metadata_size,
            ));
        }
        let (meta_data, bytes) = bytes.split_at_mut(metadata_size);

        let (mut metadata, _padding) = Ref::<&mut [u8], [u64; 3]>::from_prefix(meta_data)?;

        if metadata[LENGTH_INDEX] != 0
            || metadata[CURRENT_INDEX_INDEX] != 0
            || metadata[CAPACITY_INDEX] != 0
        {
            return Err(ZeroCopyError::MemoryNotZeroed);
        }
        metadata[CAPACITY_INDEX] = capacity;

        let (slice, remaining_bytes) =
            Ref::<&mut [u8], [T]>::from_prefix_with_elems(bytes, capacity as usize)?;
        Ok((Self { metadata, slice }, remaining_bytes))
    }

    pub fn from_bytes(bytes: &'a mut [u8]) -> Result<Self, ZeroCopyError> {
        Ok(Self::from_bytes_at(bytes)?.0)
    }

    #[inline]
    pub fn from_bytes_at(bytes: &'a mut [u8]) -> Result<(Self, &'a mut [u8]), ZeroCopyError> {
        let metadata_size = Self::metadata_size();
        if bytes.len() < metadata_size {
            return Err(ZeroCopyError::InsufficientMemoryAllocated(
                bytes.len(),
                metadata_size,
            ));
        }

        let (meta_data, bytes) = bytes.split_at_mut(metadata_size);
        let (metadata, _padding) = Ref::<&mut [u8], [u64; 3]>::from_prefix(meta_data)?;
        let capacity = metadata[CAPACITY_INDEX];
        let length = metadata[LENGTH_INDEX];
        let current = metadata[CURRENT_INDEX_INDEX];

        if length > capacity {
            return Err(ZeroCopyError::LengthGreaterThanCapacity);
        }
        if current > length {
            return Err(ZeroCopyError::CurrentIndexGreaterThanLength);
        }

        let full_vector_size = Self::data_size(capacity);
        if bytes.len() < full_vector_size {
            return Err(ZeroCopyError::InsufficientMemoryAllocated(
                bytes.len() + metadata_size,
                full_vector_size + metadata_size,
            ));
        }
        let (slice, remaining_bytes) =
            Ref::<&mut [u8], [T]>::from_prefix_with_elems(bytes, capacity as usize)?;
        Ok((Self { metadata, slice }, remaining_bytes))
    }

    #[inline]
    pub fn push(&mut self, value: T) {
        if self.len() < self.capacity() {
            let len = self.len();
            self.slice[len] = value;
            self.metadata[LENGTH_INDEX] = (len as u64) + 1;
        } else {
            let current_index = self.current_index();
            self.slice[current_index] = value;
        }
        let new_index = ((self.current_index() + 1) % self.capacity()) as u64;
        self.metadata[CURRENT_INDEX_INDEX] = new_index;
    }

    #[inline]
    pub fn clear(&mut self) {
        self.metadata[CURRENT_INDEX_INDEX] = 0;
        self.metadata[LENGTH_INDEX] = 0;
    }

    #[inline]
    pub fn first(&self) -> Option<&T> {
        self.get(self.first_index())
    }

    #[inline]
    pub fn first_mut(&mut self) -> Option<&mut T> {
        self.get_mut(self.first_index())
    }

    #[inline]
    pub fn last(&self) -> Option<&T> {
        self.get(self.last_index())
    }

    #[inline]
    pub fn last_mut(&mut self) -> Option<&mut T> {
        self.get_mut(self.last_index())
    }

    #[inline]
    fn current_index(&self) -> usize {
        self.metadata[CURRENT_INDEX_INDEX] as usize
    }

    /// First index is the next index after the last index mod capacity.
    #[inline]
    pub fn first_index(&self) -> usize {
        if self.len() < self.capacity() {
            0
        } else {
            self.last_index().saturating_add(1) % self.capacity()
        }
    }

    #[inline]
    pub fn last_index(&self) -> usize {
        if self.current_index() == 0 && self.len() == self.capacity() {
            self.capacity().saturating_sub(1)
        } else {
            self.current_index().saturating_sub(1) % self.capacity()
        }
    }

    #[inline]
    pub fn iter(&self) -> CyclicSliceMutIterator<'_, T> {
        CyclicSliceMutIterator {
            vec: self,
            current: self.first_index(),
            is_finished: false,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn metadata_size() -> usize {
        let mut size = size_of::<[u64; 3]>();
        add_padding::<[u64; 3], T>(&mut size);
        size
    }

    #[inline]
    pub fn data_size(capacity: u64) -> usize {
        (capacity as usize).saturating_mul(size_of::<T>())
    }

    pub fn required_size_for_capacity(capacity: u64) -> usize {
        Self::metadata_size().saturating_add(Self::data_size(capacity))
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.metadata[LENGTH_INDEX] as usize
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.metadata[CAPACITY_INDEX] as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len() {
            return None;
        }
        Some(&self.slice[index])
    }

    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index >= self.len() {
            return None;
        }
        Some(&mut self.slice[index])
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.slice[..self.len()]
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        let len = self.len();
        &mut self.slice[..len]
    }

    #[cfg(feature = "std")]
    #[inline]
    pub fn to_vec(&self) -> Vec<T> {
        self.as_slice().to_vec()
    }
}

pub struct CyclicSliceMutIterator<'a, T>
where
    T: ZeroCopyTraits,
{
    vec: &'a CyclicSliceMut<'a, T>,
    current: usize,
    is_finished: bool,
    _marker: PhantomData<T>,
}

impl<'a, T> Iterator for CyclicSliceMutIterator<'a, T>
where
    T: ZeroCopyTraits,
{
    type Item = &'a T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.vec.capacity() == 0 || self.is_finished {
            None
        } else {
            if self.current == self.vec.last_index() {
                self.is_finished = true;
            }
            let new_current = (self.current + 1) % self.vec.capacity();
            let element = self.vec.get(self.current);
            self.current = new_current;
            element
        }
    }
}

impl<T> IndexMut<usize> for CyclicSliceMut<'_, T>
where
    T: ZeroCopyTraits,
{
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.as_mut_slice()[index]
    }
}

impl<T> Index<usize> for CyclicSliceMut<'_, T>
where
    T: ZeroCopyTraits,
{
    type Output = T;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl<T> PartialEq for CyclicSliceMut<'_, T>
where
    T: ZeroCopyTraits + PartialEq,
{
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
            && self.metadata[CURRENT_INDEX_INDEX] == other.metadata[CURRENT_INDEX_INDEX]
    }
}

impl<T> fmt::Debug for CyclicSliceMut<'_, T>
where
    T: ZeroCopyTraits + Debug,
{
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_slice())
    }
}

// === wincode codec ===

unsafe impl<'de, C: ConfigCore, T> SchemaRead<'de, C> for CyclicSliceMut<'de, T>
where
    T: ZeroCopyTraits,
{
    type Dst = Self;
    const TYPE_META: TypeMeta = TypeMeta::Dynamic;

    fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self>) -> ReadResult<()> {
        let metadata_size = Self::metadata_size();
        let header_bytes = reader.take_borrowed_mut(metadata_size)?;
        let (metadata, _) = Ref::<&mut [u8], [u64; 3]>::from_prefix(header_bytes)
            .map_err(|_| ReadError::InvalidValue("CyclicSliceMut: metadata alignment"))?;

        let capacity = metadata[CAPACITY_INDEX];
        let length = metadata[LENGTH_INDEX];
        let current = metadata[CURRENT_INDEX_INDEX];
        if length > capacity {
            return Err(ReadError::InvalidValue("CyclicSliceMut: length > capacity"));
        }
        if current > length {
            return Err(ReadError::InvalidValue(
                "CyclicSliceMut: current_index > length",
            ));
        }

        let data_len = (capacity as usize).saturating_mul(size_of::<T>());
        let data_bytes = reader.take_borrowed_mut(data_len)?;
        let (slice, _) =
            Ref::<&mut [u8], [T]>::from_prefix_with_elems(data_bytes, capacity as usize)
                .map_err(|_| ReadError::InvalidValue("CyclicSliceMut: data alignment"))?;

        dst.write(CyclicSliceMut { metadata, slice });
        Ok(())
    }
}
