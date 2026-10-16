use solana_address::Address;
use zolana_hasher::primitives::pack_be_chunks;

use super::Bytes;
use crate::circuit::Field;

/// How a public field reaches the verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicFieldKind {
    /// An unsigned integer of `bits` bits, one public input.
    Integer { bits: u32 },
    /// 0 or 1, one public input.
    Bool,
    /// A 32-byte big-endian value below the BN254 modulus, one public input.
    Hash,
    /// `len` arbitrary bytes, packed into 31-byte big-endian chunks, one public
    /// input per chunk.
    Bytes { len: usize },
    /// `len` items of one kind, in order.
    Array {
        len: usize,
        item: Box<PublicFieldKind>,
    },
}

impl PublicFieldKind {
    /// The number of public inputs a field of this kind takes when it is bound
    /// directly, without hashing.
    pub fn public_inputs(&self) -> usize {
        match self {
            Self::Integer { .. } | Self::Bool | Self::Hash => 1,
            Self::Bytes { len } => pack_be_chunks(*len),
            Self::Array { len, item } => len * item.public_inputs(),
        }
    }
}

#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a public input field type",
    label = "a public input field implements `PublicField`",
    note = "`PublicField` gives the on-chain type of a public input: u16, u32, u64 and u128 are integers, bool is a bool, [u8; 32] and Field are 32-byte field values, Bytes<N> and Address are packed bytes, and [T; N] is an array of a `PublicField` type"
)]
pub trait PublicField {
    fn kind() -> PublicFieldKind;
}

/// A public field that one public hash can take: an integer, a bool, a 32-byte
/// field value or an array of those. Packed bytes are not one, so a ZK program,
/// whose public inputs hash into one value on-chain, cannot declare them.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a public input field type",
    label = "a public input field implements `PublicHashField`",
    note = "`PublicHashField` gives the on-chain type of a hashed public input: u16, u32, u64 and u128 are integers, bool is a bool, [u8; 32], Field, ShieldedAddress, Owner and Mint are 32-byte hashes, and [T; N] is an array of a `PublicHashField` type"
)]
pub trait PublicHashField: PublicField {}

pub trait PublicInputLayout {
    fn layout() -> Vec<(&'static str, PublicFieldKind)>;
}

macro_rules! integer {
    ($($integer:ty),*) => {
        $(
            impl PublicField for $integer {
                fn kind() -> PublicFieldKind {
                    PublicFieldKind::Integer { bits: <$integer>::BITS }
                }
            }

            impl PublicHashField for $integer {}
        )*
    };
}

integer!(u16, u32, u64, u128);

impl PublicField for bool {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Bool
    }
}

impl PublicHashField for bool {}

impl PublicField for [u8; 32] {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Hash
    }
}

impl PublicHashField for [u8; 32] {}

impl PublicField for Field {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Hash
    }
}

impl PublicHashField for Field {}

impl<const N: usize> PublicField for Bytes<N> {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Bytes { len: N }
    }
}

impl PublicField for Address {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Bytes { len: 32 }
    }
}

impl<T: PublicField, const N: usize> PublicField for [T; N] {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Array {
            len: N,
            item: Box::new(T::kind()),
        }
    }
}

impl<T: PublicHashField, const N: usize> PublicHashField for [T; N] {}
