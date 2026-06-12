use borsh::{BorshDeserialize, BorshSerialize};

use super::state::{NULLIFIER_PUBKEY_LEN, P256_PUBKEY_LEN};

/// First-byte instruction dispatch tags for the user-registry program.
pub mod tag {
    pub const REGISTER: u8 = 0;
    pub const SET_SYNC_DELEGATE: u8 = 1;
    pub const ROTATE_SYNC_DELEGATE: u8 = 2;
    pub const REVOKE: u8 = 3;
    pub const CLOSE: u8 = 4;
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
pub struct RotateSyncDelegateData {
    pub sync_pubkey: [u8; P256_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
}

#[cfg(feature = "solana")]
pub use builders::*;

#[cfg(feature = "solana")]
mod builders {
    use solana_instruction::{AccountMeta, Instruction};
    use solana_pubkey::Pubkey;

    use super::{tag, RegisterData, RotateSyncDelegateData, SetSyncDelegateData};
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
            data: encode_instruction(tag::REGISTER, &data),
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
            data: encode_instruction(tag::SET_SYNC_DELEGATE, &data),
        }
    }

    /// Accounts: `[user_record (writable), sync_delegate (writable signer), system_program]`.
    pub fn rotate_sync_delegate(
        user_record: Pubkey,
        sync_delegate: Pubkey,
        data: RotateSyncDelegateData,
    ) -> Instruction {
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(user_record, false),
                AccountMeta::new(sync_delegate, true),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data: encode_instruction(tag::ROTATE_SYNC_DELEGATE, &data),
        }
    }

    /// Accounts: `[user_record (writable), signer]`.
    pub fn revoke(user_record: Pubkey, signer: Pubkey) -> Instruction {
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(user_record, false),
                AccountMeta::new_readonly(signer, true),
            ],
            data: vec![tag::REVOKE],
        }
    }

    /// Accounts: `[user_record (writable), owner (writable signer)]`.
    pub fn close(user_record: Pubkey, owner: Pubkey) -> Instruction {
        Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(user_record, false),
                AccountMeta::new(owner, true),
            ],
            data: vec![tag::CLOSE],
        }
    }
}
