use spr_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use spr_program::hasher::{DataHasher, HasherError};
use wincode::{SchemaRead, SchemaWrite};

pub const ACCOUNT_DATA_DOMAIN: &[u8; 42] = b"zolana:compression-example:account-data:v1";

#[derive(
    SchemaRead,
    SchemaWrite,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
pub struct AccountState {
    pub authority: [u8; 32],
    pub value: u64,
    pub version: u64,
}

impl DataHasher for AccountState {
    fn hash(&self) -> Result<[u8; 32], HasherError> {
        let authority_hash = hash_bytes(&self.authority)?;
        let data_domain = hash_bytes(ACCOUNT_DATA_DOMAIN)?;
        Poseidon::hashv(&[
            &data_domain,
            &authority_hash,
            &right_align(&self.value.to_be_bytes()),
            &right_align(&self.version.to_be_bytes()),
        ])
    }
}
