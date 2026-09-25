use borsh::{BorshDeserialize, BorshSerialize};
use zolana_hasher::{primitives::hash_bytes, HasherError};

use crate::hasher::ToByteArray;

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Bytes<const N: usize>(pub [u8; N]);

impl<const N: usize> ToByteArray for Bytes<N> {
    fn to_byte_array(&self) -> Result<[u8; 32], HasherError> {
        hash_bytes(&self.0)
    }
}
