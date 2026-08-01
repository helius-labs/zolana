use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::{Pubkey, PubkeyError};

use crate::{
    instruction::{encode_instruction, tag, CreateRingConfigData, UpdateRingConfigData},
    pda, PROGRAM_ID_PUBKEY,
};

pub struct CreateRingConfig {
    pub payer: Pubkey,
    pub program_id: Address,
    pub authority: Address,
    pub ring_authority_transact_is_enabled: bool,
}

impl CreateRingConfig {
    pub fn instruction(&self) -> Result<Instruction, PubkeyError> {
        let data = CreateRingConfigData {
            program_id: self.program_id,
            authority: self.authority,
            ring_authority_transact_is_enabled: self.ring_authority_transact_is_enabled,
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
    pub ring_authority_transact_is_enabled: bool,
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
                    ring_authority_transact_is_enabled: self.ring_authority_transact_is_enabled,
                },
            ),
        }
    }
}
