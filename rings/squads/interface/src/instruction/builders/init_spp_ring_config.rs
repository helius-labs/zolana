//! `init_spp_ring_config` (tag 16) instruction builder. One-time setup: the
//! ring CPIs SPP's `create_ring_config` to register itself, signed by its own
//! `ring_auth` PDA. Empty payload: only the dispatch tag rides the
//! instruction.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, PROGRAM_ID_PUBKEY};

/// Builder for the `init_spp_ring_config` instruction.
///
/// Account order: `authority` (signer, writable, pays for the SPP account),
/// `ring_config` (this program's own config, readonly), `protocol_config`
/// (SPP's, readonly), `ring_auth` (writable, the SPP account being created),
/// `system_program`, `spp_program`.
pub struct InitSppRingConfig {
    pub authority: Pubkey,
    pub ring_config: Pubkey,
    pub protocol_config: Pubkey,
    pub ring_auth: Pubkey,
    pub system_program: Pubkey,
    pub spp_program: Pubkey,
}

impl InitSppRingConfig {
    pub fn instruction(&self) -> Instruction {
        let accounts = vec![
            AccountMeta::new(self.authority, true),
            AccountMeta::new_readonly(self.ring_config, false),
            AccountMeta::new_readonly(self.protocol_config, false),
            AccountMeta::new(self.ring_auth, false),
            AccountMeta::new_readonly(self.system_program, false),
            AccountMeta::new_readonly(self.spp_program, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: vec![tag::INIT_SPP_RING_CONFIG],
        }
    }
}
