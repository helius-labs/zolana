use borsh::{BorshDeserialize, BorshSerialize};

use super::state::{NULLIFIER_PUBKEY_LEN, P256_PUBKEY_LEN};

pub mod discriminator {
    pub const REGISTER: u8 = 0;
    pub const SET_SYNC_DELEGATE: u8 = 1;
    pub const ROTATE_SYNC_DELEGATE_KEY: u8 = 2;
    pub const REVOKE_SYNC_DELEGATE: u8 = 3;
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct RegisterData {
    pub owner_p256: Option<[u8; P256_PUBKEY_LEN]>,
    pub nullifier_pubkey: [u8; NULLIFIER_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct SetSyncDelegateData {
    pub sync_delegate: [u8; 32],
    pub sync_pubkey: [u8; P256_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct RotateSyncDelegateKeyData {
    pub sync_pubkey: [u8; P256_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
}

#[cfg(feature = "solana")]
pub use builders::*;

#[cfg(feature = "solana")]
mod builders {
    use solana_instruction::{AccountMeta, Instruction};
    use solana_pubkey::Pubkey;

    use super::{discriminator, RegisterData, RotateSyncDelegateKeyData, SetSyncDelegateData};
    use crate::instruction::encode_instruction;

    const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

    fn program_id() -> Pubkey {
        crate::user_registry::user_registry_program_id()
    }

    /// Accounts: `[user_record (writable), owner (writable signer), system_program]`.
    pub fn register(user_record: Pubkey, owner: Pubkey, data: RegisterData) -> Instruction {
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(user_record, false),
                AccountMeta::new(owner, true),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data: encode_instruction(discriminator::REGISTER, &data),
        }
    }

    /// Accounts: `[user_record (writable), owner (writable signer), system_program]`.
    pub fn set_sync_delegate(
        user_record: Pubkey,
        owner: Pubkey,
        data: SetSyncDelegateData,
    ) -> Instruction {
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(user_record, false),
                AccountMeta::new(owner, true),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data: encode_instruction(discriminator::SET_SYNC_DELEGATE, &data),
        }
    }

    /// Accounts: `[user_record (writable), sync_delegate (writable signer), system_program]`.
    pub fn rotate_sync_delegate_key(
        user_record: Pubkey,
        sync_delegate: Pubkey,
        data: RotateSyncDelegateKeyData,
    ) -> Instruction {
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(user_record, false),
                AccountMeta::new(sync_delegate, true),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data: encode_instruction(discriminator::ROTATE_SYNC_DELEGATE_KEY, &data),
        }
    }

    /// Accounts: `[user_record (writable), signer]`.
    pub fn revoke_sync_delegate(user_record: Pubkey, signer: Pubkey) -> Instruction {
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(user_record, false),
                AccountMeta::new_readonly(signer, true),
            ],
            data: vec![discriminator::REVOKE_SYNC_DELEGATE],
        }
    }
}
