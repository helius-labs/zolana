use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::{Pubkey, PubkeyError};

use crate::{
    instruction::{
        encode_instruction, tag, CreateRingConfigData, SetRingActivationData, UpdateRingConfigData,
    },
    pda, PROGRAM_ID_PUBKEY,
};

/// Permissionless: `payer` only funds rent and is checked against no authority.
/// The config is created inert unless the protocol config sets
/// `ring_activation_is_permissionless`; governance admits it with
/// [`SetRingActivation`].
pub struct CreateRingConfig {
    pub payer: Pubkey,
    pub program_id: Address,
    pub authority: Address,
}

impl CreateRingConfig {
    pub fn instruction(&self) -> Result<Instruction, PubkeyError> {
        let data = CreateRingConfigData {
            program_id: self.program_id,
            authority: self.authority,
        };

        // The config account IS the ring's `ring_auth` PDA (canonical); it signs
        // its own creation via the ring's `invoke_signed`.
        let ring_program = Pubkey::new_from_array(data.program_id.to_bytes());
        let ring_config = pda::ring_auth(&ring_program).0;

        Ok(Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(ring_config, true),
                AccountMeta::new_readonly(Pubkey::default(), false),
            ],
            data: encode_instruction(tag::CREATE_RING_CONFIG, &data),
        })
    }
}

pub struct UpdateRingConfigOwner {
    pub authority: Pubkey,
    pub ring_config: Pubkey,
    pub new_authority: Address,
}

impl UpdateRingConfigOwner {
    pub fn instruction(&self) -> Instruction {
        let new_authority = Pubkey::new_from_array(self.new_authority.to_bytes());
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new(self.ring_config, false),
                AccountMeta::new_readonly(new_authority, true),
            ],
            data: vec![tag::UPDATE_RING_CONFIG_OWNER],
        }
    }
}

pub struct UpdateRingConfig {
    pub authority: Pubkey,
    pub ring_config: Pubkey,
    /// Pauses every operational ring instruction while leaving config updates
    /// and authority rotation available.
    pub paused: bool,
}

impl UpdateRingConfig {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new(self.ring_config, false),
            ],
            data: encode_instruction(
                tag::UPDATE_RING_CONFIG,
                &UpdateRingConfigData {
                    paused: self.paused,
                },
            ),
        }
    }
}

/// Governance admits or contains a ring. `authority` must be
/// `protocol_config.ring_creation_authority`, and the pool is called directly so
/// no ring program is ever in the call chain.
pub struct SetRingActivation {
    pub authority: Pubkey,
    pub ring_config: Pubkey,
    pub activated: bool,
    pub ring_authority_transact_is_enabled: bool,
}

impl SetRingActivation {
    pub fn instruction(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                AccountMeta::new(self.ring_config, false),
            ],
            data: encode_instruction(
                tag::SET_RING_ACTIVATION,
                &SetRingActivationData {
                    activated: u8::from(self.activated),
                    ring_authority_transact_is_enabled: u8::from(
                        self.ring_authority_transact_is_enabled,
                    ),
                },
            ),
        }
    }
}
