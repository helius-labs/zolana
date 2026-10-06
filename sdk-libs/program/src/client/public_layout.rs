use zolana_keypair::ShieldedAddress;
use zolana_transaction::Mint;

use super::Owner;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicFieldKind {
    Integer {
        bits: u32,
    },
    Bool,
    Hash,
    Array {
        len: usize,
        item: Box<PublicFieldKind>,
    },
}

#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a public input field type",
    label = "a public input field implements `PublicField`",
    note = "`PublicField` gives the on-chain type of a public input: u16, u32, u64 and u128 are integers, bool is a bool, [u8; 32], ShieldedAddress, Owner and Mint are 32-byte hashes, and [T; N] is an array of a `PublicField` type"
)]
pub trait PublicField {
    fn kind() -> PublicFieldKind;
}

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
        )*
    };
}

integer!(u16, u32, u64, u128);

macro_rules! hash {
    ($($hash:ty),*) => {
        $(
            impl PublicField for $hash {
                fn kind() -> PublicFieldKind {
                    PublicFieldKind::Hash
                }
            }
        )*
    };
}

hash!([u8; 32], ShieldedAddress, Owner, Mint);

impl PublicField for bool {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Bool
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
