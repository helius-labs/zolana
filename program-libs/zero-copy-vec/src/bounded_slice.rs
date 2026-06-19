use core::{
    fmt,
    mem::{size_of, MaybeUninit},
    ops::{Index, IndexMut},
    slice,
};

use wincode::{config::ConfigCore, io::Reader, ReadError, ReadResult, SchemaRead, TypeMeta};
use zerocopy::Ref;

use crate::{add_padding, errors::ZeroCopyError, ZeroCopyTraits};

/// Length-prefixed slice with persisted capacity backed by mutable bytes.
///
/// Wire format: `[length: u64 LE][capacity: u64 LE][padding for align(T)][T; capacity]`.
///
/// Layout-compatible with `light_zero_copy::vec::ZeroCopyVecU64<T>` from crates.io 0.6.0.
pub struct BoundedSliceMut<'a, T>
where
    T: ZeroCopyTraits,
{
    /// `[length, capacity]` header.
    metadata: Ref<&'a mut [u8], [u64; 2]>,
    slice: Ref<&'a mut [u8], [T]>,
}

const LENGTH_INDEX: usize = 0;
const CAPACITY_INDEX: usize = 1;

impl<'a, T> BoundedSliceMut<'a, T>
where
    T: ZeroCopyTraits,
{
    #[inline]
    pub fn new(capacity: u64, bytes: &'a mut [u8]) -> Result<Self, ZeroCopyError> {
        Ok(Self::new_at(capacity, bytes)?.0)
    }

    pub fn new_at(
        capacity: u64,
        bytes: &'a mut [u8],
    ) -> Result<(Self, &'a mut [u8]), ZeroCopyError> {
        let metadata_size = Self::metadata_size();
        if bytes.len() < metadata_size {
            return Err(ZeroCopyError::InsufficientMemoryAllocated(
                bytes.len(),
                metadata_size,
            ));
        }
        let (meta_data, bytes) = bytes.split_at_mut(metadata_size);

        let (mut metadata, _padding) = Ref::<&mut [u8], [u64; 2]>::from_prefix(meta_data)?;
        if metadata[LENGTH_INDEX] != 0 || metadata[CAPACITY_INDEX] != 0 {
            return Err(ZeroCopyError::MemoryNotZeroed);
        }
        metadata[CAPACITY_INDEX] = capacity;
        let capacity_usize = capacity as usize;

        let (slice, remaining_bytes) =
            Ref::<&mut [u8], [T]>::from_prefix_with_elems(bytes, capacity_usize)?;
        Ok((Self { metadata, slice }, remaining_bytes))
    }

    #[inline]
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
        let (metadata, _padding) = Ref::<&mut [u8], [u64; 2]>::from_prefix(meta_data)?;
        let capacity = metadata[CAPACITY_INDEX];
        let length = metadata[LENGTH_INDEX];

        if length > capacity {
            return Err(ZeroCopyError::LengthGreaterThanCapacity);
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
    pub fn metadata_size() -> usize {
        let mut size = size_of::<[u64; 2]>();
        add_padding::<[u64; 2], T>(&mut size);
        size
    }

    #[inline]
    pub fn data_size(capacity: u64) -> usize {
        (capacity as usize).saturating_mul(size_of::<T>())
    }

    #[inline]
    pub fn required_size_for_capacity(capacity: u64) -> usize {
        Self::metadata_size().saturating_add(Self::data_size(capacity))
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.metadata[CAPACITY_INDEX] as usize
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.metadata[LENGTH_INDEX] as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn push(&mut self, value: T) -> Result<(), ZeroCopyError> {
        let len = self.len();
        if len == self.capacity() {
            return Err(ZeroCopyError::Full);
        }
        self.slice[len] = value;
        self.metadata[LENGTH_INDEX] = (len as u64) + 1;
        Ok(())
    }

    #[inline]
    pub fn clear(&mut self) {
        self.metadata[LENGTH_INDEX] = 0;
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
    pub fn first(&self) -> Option<&T> {
        self.get(0)
    }

    #[inline]
    pub fn first_mut(&mut self) -> Option<&mut T> {
        self.get_mut(0)
    }

    #[inline]
    pub fn last(&self) -> Option<&T> {
        self.get(self.len().saturating_sub(1))
    }

    #[inline]
    pub fn last_mut(&mut self) -> Option<&mut T> {
        self.get_mut(self.len().saturating_sub(1))
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

    #[inline]
    pub fn iter(&self) -> slice::Iter<'_, T> {
        self.as_slice().iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> slice::IterMut<'_, T> {
        self.as_mut_slice().iter_mut()
    }
}

impl<T> Index<usize> for BoundedSliceMut<'_, T>
where
    T: ZeroCopyTraits,
{
    type Output = T;
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl<T> IndexMut<usize> for BoundedSliceMut<'_, T>
where
    T: ZeroCopyTraits,
{
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.as_mut_slice()[index]
    }
}

impl<'b, T> IntoIterator for &'b BoundedSliceMut<'_, T>
where
    T: ZeroCopyTraits,
{
    type Item = &'b T;
    type IntoIter = slice::Iter<'b, T>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'b, T> IntoIterator for &'b mut BoundedSliceMut<'_, T>
where
    T: ZeroCopyTraits,
{
    type Item = &'b mut T;
    type IntoIter = slice::IterMut<'b, T>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<T> PartialEq for BoundedSliceMut<'_, T>
where
    T: ZeroCopyTraits + PartialEq,
{
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T> fmt::Debug for BoundedSliceMut<'_, T>
where
    T: ZeroCopyTraits + fmt::Debug,
{
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_slice())
    }
}

// === wincode codec ===
//
// Config-independent: length/capacity prefixes are always u64 little-endian,
// regardless of `C::IntEncoding` / `C::SeqLen`, because the wire format is
// pinned by deployed Solana account compatibility.

unsafe impl<'de, C: ConfigCore, T> SchemaRead<'de, C> for BoundedSliceMut<'de, T>
where
    T: ZeroCopyTraits,
{
    type Dst = Self;
    const TYPE_META: TypeMeta = TypeMeta::Dynamic;

    fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self>) -> ReadResult<()> {
        let metadata_size = Self::metadata_size();
        let header_bytes = reader.take_borrowed_mut(metadata_size)?;
        let (metadata, _) = Ref::<&mut [u8], [u64; 2]>::from_prefix(header_bytes)
            .map_err(|_| ReadError::InvalidValue("BoundedSliceMut: metadata alignment"))?;

        let capacity = metadata[CAPACITY_INDEX];
        let length = metadata[LENGTH_INDEX];
        if length > capacity {
            return Err(ReadError::InvalidValue(
                "BoundedSliceMut: length > capacity",
            ));
        }

        let data_len = (capacity as usize).saturating_mul(size_of::<T>());
        let data_bytes = reader.take_borrowed_mut(data_len)?;
        let (slice, _) =
            Ref::<&mut [u8], [T]>::from_prefix_with_elems(data_bytes, capacity as usize)
                .map_err(|_| ReadError::InvalidValue("BoundedSliceMut: data alignment"))?;

        dst.write(BoundedSliceMut { metadata, slice });
        Ok(())
    }
}
