use core::{fmt, marker::PhantomData};

use solana_program_error::ProgramError;
use wincode::{
    config::{Configuration, DEFAULT_PREALLOCATION_SIZE_LIMIT},
    io::Reader,
    len::FixIntLen,
    ReadError, SchemaRead,
};

use crate::error::ShieldedPoolError;

/// Configuration shared by the borrowed instruction-data readers. Record
/// lists carry explicit `u8` lengths; byte slices inside records carry `u16`.
pub(crate) type RefConfig = Configuration<true, DEFAULT_PREALLOCATION_SIZE_LIMIT, FixIntLen<u16>>;

/// Why a borrowed instruction view could not be built: the bytes do not decode,
/// or a well-formed list is longer than the protocol allows.
#[derive(Debug)]
pub enum DecodeError {
    Encoding(ReadError),
    Limit(ShieldedPoolError),
}

impl From<ReadError> for DecodeError {
    fn from(error: ReadError) -> Self {
        Self::Encoding(error)
    }
}

impl DecodeError {
    /// The program error to return: the named limit variant for an overlong
    /// list, `encoding` for bytes that do not decode.
    pub fn or_encoding(self, encoding: impl Into<ProgramError>) -> ProgramError {
        match self {
            Self::Encoding(_) => encoding.into(),
            Self::Limit(error) => error.into(),
        }
    }
}

type Decoder<'a, T> = fn(&mut &'a [u8]) -> Result<T, ReadError>;

/// Allocation-free view of an encoded instruction-data list.
///
/// Construction validates every item once and stores only the item bytes and
/// count. Iteration decodes one small item at a time; borrowed fields continue
/// to point into the original instruction buffer.
pub struct BorrowedList<'a, T> {
    bytes: &'a [u8],
    count: u8,
    decoder: Decoder<'a, T>,
    marker: PhantomData<T>,
}

impl<T> Clone for BorrowedList<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for BorrowedList<'_, T> {}

impl<T> fmt::Debug for BorrowedList<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BorrowedList")
            .field("count", &self.count)
            .field("encoded_len", &self.bytes.len())
            .finish()
    }
}

impl<T> PartialEq for BorrowedList<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        self.count == other.count && self.bytes == other.bytes
    }
}

impl<T> Eq for BorrowedList<'_, T> {}

impl<'a, T> BorrowedList<'a, T> {
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn try_iter(&self) -> BorrowedListIter<'a, T> {
        BorrowedListIter {
            bytes: self.bytes,
            remaining: self.count,
            decoder: self.decoder,
        }
    }

    pub fn get(&self, index: usize) -> Result<Option<T>, ReadError> {
        let Some(item) = self.try_iter().nth(index) else {
            return Ok(None);
        };
        item.map(Some)
    }

    pub fn first(&self) -> Result<Option<T>, ReadError> {
        let Some(item) = self.try_iter().next() else {
            return Ok(None);
        };
        item.map(Some)
    }

    pub(crate) fn read<S>(
        cursor: &mut &'a [u8],
        maximum_len: usize,
        overflow: ShieldedPoolError,
    ) -> Result<Self, DecodeError>
    where
        S: SchemaRead<'a, RefConfig, Dst = T>,
    {
        let (&count, after_count) = cursor
            .split_first()
            .ok_or(ReadError::Custom("instruction list is missing its count"))?;
        if usize::from(count) > maximum_len {
            return Err(DecodeError::Limit(overflow));
        }
        *cursor = after_count;

        let start = *cursor;
        for _ in 0..count {
            decode::<S>(cursor)?;
        }
        let encoded_len = start
            .len()
            .checked_sub(cursor.len())
            .ok_or(ReadError::Custom("instruction cursor moved backwards"))?;
        let bytes = start
            .get(..encoded_len)
            .ok_or(ReadError::Custom("instruction list is outside its input"))?;

        Ok(Self {
            bytes,
            count,
            decoder: decode::<S>,
            marker: PhantomData,
        })
    }
}

/// Fallible iterator for [`BorrowedList`].
pub struct BorrowedListIter<'a, T> {
    bytes: &'a [u8],
    remaining: u8,
    decoder: Decoder<'a, T>,
}

impl<T> Iterator for BorrowedListIter<'_, T> {
    type Item = Result<T, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some((self.decoder)(&mut self.bytes))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::from(self.remaining);
        (remaining, Some(remaining))
    }
}

impl<T> ExactSizeIterator for BorrowedListIter<'_, T> {}

pub(crate) fn read<'a, S>(cursor: &mut &'a [u8]) -> Result<S::Dst, ReadError>
where
    S: SchemaRead<'a, RefConfig>,
{
    <S as SchemaRead<'a, RefConfig>>::get(cursor.by_ref())
}

fn decode<'a, S>(cursor: &mut &'a [u8]) -> Result<S::Dst, ReadError>
where
    S: SchemaRead<'a, RefConfig>,
{
    read::<S>(cursor)
}

pub(crate) fn finish(cursor: &[u8]) -> Result<(), ReadError> {
    if cursor.is_empty() {
        Ok(())
    } else {
        Err(ReadError::TrailingBytes)
    }
}
