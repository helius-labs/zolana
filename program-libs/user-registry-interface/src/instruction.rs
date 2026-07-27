use borsh::{BorshDeserialize, BorshSerialize};

use super::state::{NULLIFIER_PUBKEY_LEN, P256_PUBKEY_LEN};

pub mod discriminator {
    pub const REGISTER: u8 = 0;
    pub const SET_MERGING_ENABLED: u8 = 1;
    pub const UPDATE_KEYS: u8 = 2;
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct RegisterData {
    pub owner_p256: Option<[u8; P256_PUBKEY_LEN]>,
    pub nullifier_pubkey: [u8; NULLIFIER_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct UpdateKeysData {
    pub owner_p256: Option<[u8; P256_PUBKEY_LEN]>,
    pub nullifier_pubkey: [u8; NULLIFIER_PUBKEY_LEN],
    pub viewing_pubkey: [u8; P256_PUBKEY_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct SetMergingEnabledData {
    pub enabled: bool,
}

#[cfg(feature = "solana")]
pub use builders::*;

#[cfg(feature = "solana")]
mod builders {
    use borsh::BorshSerialize;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_pubkey::Pubkey;

    use super::{discriminator, RegisterData, SetMergingEnabledData, UpdateKeysData};
    use crate::user_registry_program_id;

    const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

    fn encode_instruction<T: BorshSerialize>(tag: u8, payload: &T) -> Vec<u8> {
        let mut data = vec![tag];
        payload
            .serialize(&mut data)
            .expect("user-registry instruction serialization is infallible");
        data
    }

    /// Accounts: `[user_record (writable), owner (writable signer), system_program]`.
    pub fn register(user_record: Pubkey, owner: Pubkey, data: RegisterData) -> Instruction {
        Instruction {
            program_id: user_registry_program_id(),
            accounts: vec![
                AccountMeta::new(user_record, false),
                AccountMeta::new(owner, true),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data: encode_instruction(discriminator::REGISTER, &data),
        }
    }

    /// Accounts: `[user_record (writable), owner (signer)]`. Only the owner may
    /// enable or disable merging.
    pub fn set_merging_enabled(user_record: Pubkey, owner: Pubkey, enabled: bool) -> Instruction {
        Instruction {
            program_id: user_registry_program_id(),
            accounts: vec![
                AccountMeta::new(user_record, false),
                AccountMeta::new_readonly(owner, true),
            ],
            data: encode_instruction(
                discriminator::SET_MERGING_ENABLED,
                &SetMergingEnabledData { enabled },
            ),
        }
    }

    /// Accounts: `[user_record (writable), owner (signer)]`. The owner may rotate
    /// the shielded keys stored in its existing record without changing the PDA.
    pub fn update_keys(user_record: Pubkey, owner: Pubkey, data: UpdateKeysData) -> Instruction {
        Instruction {
            program_id: user_registry_program_id(),
            accounts: vec![
                AccountMeta::new(user_record, false),
                AccountMeta::new_readonly(owner, true),
            ],
            data: encode_instruction(discriminator::UPDATE_KEYS, &data),
        }
    }
}
