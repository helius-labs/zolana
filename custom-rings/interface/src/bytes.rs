use wincode::{config::DefaultConfig, containers, len::FixIntLen, SchemaRead};
use zolana_interface::instruction::{InterfaceTransfer, TreeContext};

use crate::error::CustomRingError;

/// A cursor whose short reads fail with `short`.
pub(crate) struct Bytes<'a> {
    data: &'a [u8],
    short: CustomRingError,
}

impl<'a> Bytes<'a> {
    pub(crate) const fn new(data: &'a [u8], short: CustomRingError) -> Self {
        Self { data, short }
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], CustomRingError> {
        let (head, rest) = self.data.split_at_checked(len).ok_or(self.short)?;
        self.data = rest;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], CustomRingError> {
        let (head, rest) = self.data.split_first_chunk::<N>().ok_or(self.short)?;
        self.data = rest;
        Ok(head)
    }

    pub(crate) fn byte(&mut self) -> Result<u8, CustomRingError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, CustomRingError> {
        Ok(u16::from_le_bytes(*self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, CustomRingError> {
        Ok(u32::from_le_bytes(*self.array()?))
    }

    pub(crate) fn pod<T: bytemuck::Pod>(&mut self) -> Result<&'a T, CustomRingError> {
        bytemuck::try_from_bytes(self.take(core::mem::size_of::<T>())?)
            .map_err(|_| CustomRingError::InvalidInstructionData)
    }

    pub(crate) fn fields(&mut self, count: usize) -> Result<&'a [[u8; 32]], CustomRingError> {
        Ok(self.take(count * 32)?.as_chunks::<32>().0)
    }

    /// `len u16 || bytes`.
    pub(crate) fn sized(&mut self) -> Result<&'a [u8], CustomRingError> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }

    /// `ceil(len / 8)` bytes, bit `i` at byte `i / 8` bit `i % 8`, no bit set past `len`.
    pub(crate) fn bitmap(&mut self, len: usize) -> Result<u64, CustomRingError> {
        if len > u64::BITS as usize {
            return Err(self.short);
        }
        let bits = self
            .take(len.div_ceil(8))?
            .iter()
            .enumerate()
            .fold(0u64, |bits, (index, byte)| {
                bits | u64::from(*byte) << (8 * index)
            });
        if len < 64 && bits >> len != 0 {
            return Err(CustomRingError::InvalidInstructionData);
        }
        Ok(bits)
    }

    pub(crate) fn interface_transfers(
        &mut self,
    ) -> Result<Vec<InterfaceTransfer>, CustomRingError> {
        <containers::Vec<InterfaceTransfer, FixIntLen<u8>> as SchemaRead<'a, DefaultConfig>>::get(
            &mut self.data,
        )
        .map_err(|_| CustomRingError::InvalidInstructionData)
    }

    pub(crate) fn tree_context(&mut self) -> Result<TreeContext, CustomRingError> {
        <TreeContext as SchemaRead<'a, DefaultConfig>>::get(&mut self.data).map_err(|_| self.short)
    }

    pub(crate) const fn rest(self) -> &'a [u8] {
        self.data
    }

    pub(crate) fn finish(self) -> Result<(), CustomRingError> {
        match self.data {
            [] => Ok(()),
            _ => Err(self.short),
        }
    }
}
