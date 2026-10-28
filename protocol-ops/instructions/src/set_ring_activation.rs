use alloc::vec;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use spr_interface::{
    instruction::{encode_instruction, tag, SetRingActivationData},
    pda, PROGRAM_ID_PUBKEY,
};

/// Governance admits or contains a ring. `authority` must be
/// `protocol_config.ring_creation_authority`, and the pool is called directly so
/// no ring program is ever in the call chain.
pub struct SetRingActivation {
    pub authority: Address,
    pub ring_config: Address,
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
