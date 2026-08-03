use borsh::{BorshDeserialize, BorshSerialize};
use solana_pubkey::Pubkey;

use super::state::{NULLIFIER_PUBKEY_LEN, P256_PUBKEY_LEN};

/// Fixed-size proof-of-possession message signed by `owner_p256`.
///
/// This is a durable certificate binding one P-256 key to one Solana owner and
/// its canonical registry PDA. The secp256r1 precompile applies SHA-256 before
/// verifying the ECDSA signature.
pub const P256_KEY_BINDING_MESSAGE_LEN: usize = 161;
pub const P256_KEY_BINDING_DOMAIN: [u8; 32] = *b"zolana:user-registry:p256:v1\0\0\0\0";

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

pub fn p256_key_binding_message(
    user_record: &Pubkey,
    owner: &Pubkey,
    owner_p256: &[u8; P256_PUBKEY_LEN],
) -> [u8; P256_KEY_BINDING_MESSAGE_LEN] {
    let mut message = [0u8; P256_KEY_BINDING_MESSAGE_LEN];
    let mut offset = 0usize;
    for bytes in [
        P256_KEY_BINDING_DOMAIN.as_slice(),
        crate::USER_REGISTRY_PROGRAM_ID.as_slice(),
        user_record.as_ref(),
        owner.as_ref(),
        owner_p256.as_slice(),
    ] {
        let end = offset + bytes.len();
        message[offset..end].copy_from_slice(bytes);
        offset = end;
    }
    debug_assert_eq!(offset, P256_KEY_BINDING_MESSAGE_LEN);
    message
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
    pub(super) const INSTRUCTIONS_SYSVAR_ID: Pubkey =
        Pubkey::from_str_const("Sysvar1nstructions1111111111111111111111111");

    fn encode_instruction<T: BorshSerialize>(tag: u8, payload: &T) -> Vec<u8> {
        let mut data = vec![tag];
        payload
            .serialize(&mut data)
            .expect("user-registry instruction serialization is infallible");
        data
    }

    /// Accounts: `[user_record (writable), owner (writable signer), system_program]`,
    /// followed by the Instructions sysvar when `owner_p256` is present.
    pub fn register(user_record: Pubkey, owner: Pubkey, data: RegisterData) -> Instruction {
        let has_p256_owner = data.owner_p256.is_some();
        let mut accounts = vec![
            AccountMeta::new(user_record, false),
            AccountMeta::new(owner, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ];
        if has_p256_owner {
            accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false));
        }
        Instruction {
            program_id: user_registry_program_id(),
            accounts,
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

    /// Accounts: `[user_record (writable), owner (signer)]`, followed by the
    /// Instructions sysvar when `owner_p256` is present. The owner may rotate the
    /// shielded keys stored in its existing record without changing the PDA.
    pub fn update_keys(user_record: Pubkey, owner: Pubkey, data: UpdateKeysData) -> Instruction {
        let has_p256_owner = data.owner_p256.is_some();
        let mut accounts = vec![
            AccountMeta::new(user_record, false),
            AccountMeta::new_readonly(owner, true),
        ];
        if has_p256_owner {
            accounts.push(AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false));
        }
        Instruction {
            program_id: user_registry_program_id(),
            accounts,
            data: encode_instruction(discriminator::UPDATE_KEYS, &data),
        }
    }

    /// Build the top-level secp256r1 verification instruction that must
    /// immediately precede a P-256 registry register/update instruction.
    pub fn p256_verify_instruction(
        message: &[u8],
        signature: &[u8; 64],
        pubkey: &[u8; 33],
    ) -> Instruction {
        solana_secp256r1_program::new_secp256r1_instruction_with_signature(
            message, signature, pubkey,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p256_binding_message_has_stable_layout() {
        let record = Pubkey::new_from_array([1u8; 32]);
        let owner = Pubkey::new_from_array([2u8; 32]);
        let owner_p256 = [3u8; 33];

        let message = p256_key_binding_message(&record, &owner, &owner_p256);

        assert_eq!(message.len(), P256_KEY_BINDING_MESSAGE_LEN);
        assert_eq!(&message[..32], &P256_KEY_BINDING_DOMAIN);
        assert_eq!(&message[32..64], &crate::USER_REGISTRY_PROGRAM_ID);
        assert_eq!(&message[64..96], record.as_ref());
        assert_eq!(&message[96..128], owner.as_ref());
        assert_eq!(&message[128..], &owner_p256);
    }

    #[cfg(feature = "solana")]
    #[test]
    fn p256_builders_include_instructions_sysvar() {
        let record = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let data = RegisterData {
            owner_p256: Some([2u8; 33]),
            nullifier_pubkey: [0u8; 32],
            viewing_pubkey: [2u8; 33],
        };

        let register = builders::register(record, owner, data.clone());
        let update = builders::update_keys(
            record,
            owner,
            UpdateKeysData {
                owner_p256: data.owner_p256,
                nullifier_pubkey: data.nullifier_pubkey,
                viewing_pubkey: data.viewing_pubkey,
            },
        );

        assert_eq!(
            register.accounts.last().unwrap().pubkey,
            builders::INSTRUCTIONS_SYSVAR_ID
        );
        assert_eq!(
            update.accounts.last().unwrap().pubkey,
            builders::INSTRUCTIONS_SYSVAR_ID
        );
    }
}
