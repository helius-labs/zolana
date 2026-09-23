use borsh::{BorshDeserialize, BorshSerialize};
use pinocchio::error::ProgramError;
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use zolana_program::compression::CompressedAccountData;

use crate::error::CompressionError;

pub const ACCOUNT_DATA_DOMAIN: &[u8; 42] = b"zolana:compression-example:account-data:v1";

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountState {
    pub address: [u8; 32],
    pub authority: [u8; 32],
    pub value: u64,
    pub version: u64,
    /// The UTXO blinding, which `SppTransactCpi` derives from the creating
    /// transaction's first nullifier. Published with the plaintext state so a
    /// reader can spend the UTXO without replaying the transaction chain that
    /// produced that first nullifier.
    pub blinding: [u8; 32],
}

impl CompressedAccountData for AccountState {
    fn data_hash(&self) -> Result<[u8; 32], ProgramError> {
        let authority_hash = hash_bytes(&self.authority).map_err(CompressionError::from)?;
        let data_domain = hash_bytes(ACCOUNT_DATA_DOMAIN).map_err(CompressionError::from)?;
        Ok(Poseidon::hashv(&[
            &self.address,
            &data_domain,
            &authority_hash,
            &right_align(&self.value.to_be_bytes()),
            &right_align(&self.version.to_be_bytes()),
            &self.blinding,
        ])
        .map_err(CompressionError::from)?)
    }

    fn address_mut(&mut self) -> &mut [u8; 32] {
        &mut self.address
    }

    fn blinding_mut(&mut self) -> &mut [u8; 32] {
        &mut self.blinding
    }
}
