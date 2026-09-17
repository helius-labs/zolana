use bytemuck::{Pod, Zeroable};

pub const RECEIPT_SEED: &[u8] = b"receipt";

/// Receipt shapes with a committed verifying key. A receipt pads to its
/// capacity with zero slots; `count` is the number of live nullifiers.
pub const RECEIPT_CAPACITIES: [u16; 2] = [8, 512];

/// Largest receipt shape.
pub const RECEIPT_MAX_CAPACITY: u16 = 512;

/// Header of a nullifier receipt account; `capacity` 32-byte nullifier slots
/// follow it. A receipt records that its live nullifiers were absent from
/// `tree`'s nullifier tree at `nullifier_root`, once `verified` is set by a
/// receipt proof. Receipt-backed merges spend contiguous slices of it and
/// must see the same root in the tree's history. The account holds no
/// reservation: it blocks nothing and expires with root history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct ReceiptHeader {
    pub discriminator: u8,
    pub bump: u8,
    /// 1 once the receipt proof verified; uploads are rejected afterwards.
    pub verified: u8,
    pub _padding: u8,
    pub capacity: [u8; 2],
    /// Live nullifiers, set by `verify_receipt`.
    pub count: [u8; 2],
    /// Slots written so far; uploads must be contiguous.
    pub filled: [u8; 2],
    pub _padding2: [u8; 6],
    pub tree: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub rent_sponsor: [u8; 32],
    pub nonce: [u8; 8],
}

impl ReceiptHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn has_discriminator(&self) -> bool {
        self.discriminator == super::discriminator::RECEIPT
    }

    pub fn capacity(&self) -> u16 {
        u16::from_le_bytes(self.capacity)
    }

    pub fn count(&self) -> u16 {
        u16::from_le_bytes(self.count)
    }

    pub fn filled(&self) -> u16 {
        u16::from_le_bytes(self.filled)
    }

    pub fn nonce(&self) -> u64 {
        u64::from_le_bytes(self.nonce)
    }
}

const _: () = assert!(ReceiptHeader::SIZE == 120);
const _: () = assert!(core::mem::align_of::<ReceiptHeader>() == 1);

pub fn is_supported_capacity(capacity: u16) -> bool {
    RECEIPT_CAPACITIES.contains(&capacity)
}

/// Account size for a receipt of `capacity` slots.
pub fn receipt_account_size(capacity: u16) -> usize {
    ReceiptHeader::SIZE + usize::from(capacity) * 32
}

/// The nullifier slots after the header, in slot order. `data` must be a
/// whole receipt account (the loader checks its length).
pub fn receipt_nullifiers(data: &[u8]) -> &[[u8; 32]] {
    bytemuck::cast_slice(&data[ReceiptHeader::SIZE..])
}

pub fn receipt_nullifiers_mut(data: &mut [u8]) -> &mut [[u8; 32]] {
    bytemuck::cast_slice_mut(&mut data[ReceiptHeader::SIZE..])
}
