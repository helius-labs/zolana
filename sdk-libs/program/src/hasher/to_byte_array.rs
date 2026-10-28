use spr_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, HasherError, Poseidon,
};

use crate::client::{Bytes, UtxoOwner};

/// Encodes a native state field for its Poseidon commitment.
///
/// Byte strings use `Bytes<32>`. Custom types can implement this trait with an
/// encoding that matches their circuit type's `DataHash` implementation.
pub trait ToByteArray {
    fn to_byte_array(&self) -> Result<[u8; 32], HasherError>;
}

macro_rules! impl_to_byte_array_for_integer {
    ($($integer:ty),*) => {
        $(
            impl ToByteArray for $integer {
                fn to_byte_array(&self) -> Result<[u8; 32], HasherError> {
                    Ok(right_align(&self.to_be_bytes()))
                }
            }
        )*
    };
}

impl_to_byte_array_for_integer!(u16, u32, u64, u128);

impl ToByteArray for bool {
    fn to_byte_array(&self) -> Result<[u8; 32], HasherError> {
        Ok(right_align(&[u8::from(*self)]))
    }
}

impl ToByteArray for [u8; 32] {
    fn to_byte_array(&self) -> Result<[u8; 32], HasherError> {
        Ok(*self)
    }
}

impl<T: ToByteArray, const N: usize> ToByteArray for [T; N] {
    fn to_byte_array(&self) -> Result<[u8; 32], HasherError> {
        let mut elements = [[0u8; 32]; N];
        for (target, element) in elements.iter_mut().zip(self.iter()) {
            *target = element.to_byte_array()?;
        }
        Poseidon::hashv(&elements.each_ref().map(<[u8; 32]>::as_slice))
    }
}

// State byte fields have one fixed width because hash_bytes does not commit to length.
impl ToByteArray for Bytes<32> {
    fn to_byte_array(&self) -> Result<[u8; 32], HasherError> {
        hash_bytes(&self.0)
    }
}

impl ToByteArray for solana_address::Address {
    fn to_byte_array(&self) -> Result<[u8; 32], HasherError> {
        hash_bytes(self.as_array())
    }
}

impl ToByteArray for UtxoOwner {
    fn to_byte_array(&self) -> Result<[u8; 32], HasherError> {
        let mut tagged = [0u8; 33];
        let (tag, key) = tagged.split_at_mut(1);
        tag.fill(self.tag);
        key.copy_from_slice(&self.key);
        Poseidon::hashv(&[&hash_bytes(&tagged)?, &self.nullifier_pk])
    }
}
