use borsh::{BorshDeserialize, BorshSerialize};

use super::state::{MergeEncryptionScheme, NULLIFIER_PUBKEY_LEN, VIEWING_PUBKEY_LEN};

pub mod discriminator {
    pub const REGISTER: u8 = 0;
    pub const SET_MERGE_ENCRYPTION: u8 = 1;
    pub const UPDATE_KEYS: u8 = 2;
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct RegisterData {
    pub nullifier_pubkey: [u8; NULLIFIER_PUBKEY_LEN],
    pub viewing_pubkey: [u8; VIEWING_PUBKEY_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct UpdateKeysData {
    pub nullifier_pubkey: [u8; NULLIFIER_PUBKEY_LEN],
    pub viewing_pubkey: [u8; VIEWING_PUBKEY_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct SetMergeEncryptionData {
    pub scheme: MergeEncryptionScheme,
}

#[cfg(feature = "solana")]
pub use builders::*;

#[cfg(feature = "solana")]
mod builders {
    use borsh::BorshSerialize;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_pubkey::Pubkey;

    use super::{
        discriminator, MergeEncryptionScheme, RegisterData, SetMergeEncryptionData, UpdateKeysData,
    };
    use crate::user_registry_program_id;

    const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

    fn encode_instruction<T: BorshSerialize>(tag: u8, payload: &T) -> Vec<u8> {
        let mut data = vec![tag];
        payload
            .serialize(&mut data)
            .expect("user-registry instruction serialization is infallible");
        data
    }

    /// Accounts: `[user_record (writable), owner (signer), payer (writable
    /// signer), system_program]`. `payer` funds the record's rent and may equal
    /// `owner`; the message compiler merges the two metas into one signer.
    pub fn register(
        user_record: Pubkey,
        owner: Pubkey,
        payer: Pubkey,
        data: RegisterData,
    ) -> Instruction {
        let accounts = vec![
            AccountMeta::new(user_record, false),
            AccountMeta::new_readonly(owner, true),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ];
        Instruction {
            program_id: user_registry_program_id(),
            accounts,
            data: encode_instruction(discriminator::REGISTER, &data),
        }
    }

    /// Accounts: `[user_record (writable), owner (signer)]`. Only the owner may
    /// select the merge encryption scheme or disable merging.
    pub fn set_merge_encryption(
        user_record: Pubkey,
        owner: Pubkey,
        scheme: MergeEncryptionScheme,
    ) -> Instruction {
        Instruction {
            program_id: user_registry_program_id(),
            accounts: vec![
                AccountMeta::new(user_record, false),
                AccountMeta::new_readonly(owner, true),
            ],
            data: encode_instruction(
                discriminator::SET_MERGE_ENCRYPTION,
                &SetMergeEncryptionData { scheme },
            ),
        }
    }

    /// Accounts: `[user_record (writable), owner (signer)]`. The owner may rotate the
    /// shielded keys stored in its existing record without changing the PDA.
    pub fn update_keys(user_record: Pubkey, owner: Pubkey, data: UpdateKeysData) -> Instruction {
        let accounts = vec![
            AccountMeta::new(user_record, false),
            AccountMeta::new_readonly(owner, true),
        ];
        Instruction {
            program_id: user_registry_program_id(),
            accounts,
            data: encode_instruction(discriminator::UPDATE_KEYS, &data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_pubkey::Pubkey;

    #[cfg(feature = "solana")]
    #[test]
    fn register_lists_owner_as_readonly_signer_and_payer_as_writable_signer() {
        let record = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let data = RegisterData {
            nullifier_pubkey: [0u8; 32],
            viewing_pubkey: [2u8; 33],
        };

        let ix = builders::register(record, owner, payer, data);

        assert_eq!(ix.accounts.len(), 4);
        assert_eq!(ix.accounts[0].pubkey, record);
        assert!(ix.accounts[0].is_writable && !ix.accounts[0].is_signer);
        assert_eq!(ix.accounts[1].pubkey, owner);
        assert!(ix.accounts[1].is_signer && !ix.accounts[1].is_writable);
        assert_eq!(ix.accounts[2].pubkey, payer);
        assert!(ix.accounts[2].is_signer && ix.accounts[2].is_writable);
        assert_eq!(ix.accounts[3].pubkey, Pubkey::default());
    }
}
