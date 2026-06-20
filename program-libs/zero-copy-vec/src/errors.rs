use core::fmt;
#[cfg(feature = "std")]
use std::error::Error;

use solana_program_error::ProgramError;

#[derive(Debug, PartialEq)]
pub enum ZeroCopyError {
    Full,
    InsufficientMemoryAllocated(usize, usize),
    UnalignedPointer,
    MemoryNotZeroed,
    InvalidConversion,
    Size,
    InvalidCapacity,
    LengthGreaterThanCapacity,
    CurrentIndexGreaterThanLength,
    InsufficientCapacity,
}

impl fmt::Display for ZeroCopyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZeroCopyError::Full => write!(f, "The vector is full, cannot push any new elements"),
            ZeroCopyError::InsufficientMemoryAllocated(allocated, required) => write!(
                f,
                "Memory allocated {}, Memory required {}",
                allocated, required
            ),
            ZeroCopyError::UnalignedPointer => write!(f, "Unaligned pointer"),
            ZeroCopyError::MemoryNotZeroed => write!(f, "Memory not zeroed"),
            ZeroCopyError::InvalidConversion => write!(f, "Invalid conversion"),
            ZeroCopyError::Size => write!(f, "Invalid size"),
            ZeroCopyError::InvalidCapacity => {
                write!(f, "Invalid capacity. Capacity must be greater than 0")
            }
            ZeroCopyError::LengthGreaterThanCapacity => {
                write!(f, "Length is greater than capacity")
            }
            ZeroCopyError::CurrentIndexGreaterThanLength => {
                write!(f, "Current index is greater than length")
            }
            ZeroCopyError::InsufficientCapacity => write!(f, "Insufficient capacity for operation"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for ZeroCopyError {}

impl From<ZeroCopyError> for u32 {
    fn from(e: ZeroCopyError) -> u32 {
        match e {
            ZeroCopyError::Full => 15001,
            ZeroCopyError::InsufficientMemoryAllocated(_, _) => 15004,
            ZeroCopyError::UnalignedPointer => 15006,
            ZeroCopyError::MemoryNotZeroed => 15007,
            ZeroCopyError::InvalidConversion => 15008,
            ZeroCopyError::Size => 15010,
            ZeroCopyError::InvalidCapacity => 15012,
            ZeroCopyError::LengthGreaterThanCapacity => 15013,
            ZeroCopyError::CurrentIndexGreaterThanLength => 15014,
            ZeroCopyError::InsufficientCapacity => 15016,
        }
    }
}

impl From<ZeroCopyError> for ProgramError {
    fn from(e: ZeroCopyError) -> Self {
        ProgramError::Custom(e.into())
    }
}

impl<Src, Dst: ?Sized>
    From<
        zerocopy::ConvertError<
            zerocopy::AlignmentError<Src, Dst>,
            zerocopy::SizeError<Src, Dst>,
            core::convert::Infallible,
        >,
    > for ZeroCopyError
{
    fn from(
        err: zerocopy::ConvertError<
            zerocopy::AlignmentError<Src, Dst>,
            zerocopy::SizeError<Src, Dst>,
            core::convert::Infallible,
        >,
    ) -> Self {
        match err {
            zerocopy::ConvertError::Alignment(_) => ZeroCopyError::UnalignedPointer,
            zerocopy::ConvertError::Size(_) => ZeroCopyError::Size,
            zerocopy::ConvertError::Validity(infallible) => match infallible {},
        }
    }
}
