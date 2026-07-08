//! `init_spp_zone_config` (tag 16) instruction builder. One-time setup: the
//! zone CPIs SPP's `create_zone_config` to register itself, signed by its own
//! `zone_auth` PDA. Empty payload: only the dispatch tag rides the
//! instruction.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{instruction::tag, PROGRAM_ID_PUBKEY};

/// Builder for the `init_spp_zone_config` instruction.
///
/// Account order: `authority` (signer, writable, pays for the SPP account),
/// `zone_config` (this program's own config, readonly), `protocol_config`
/// (SPP's, readonly), `zone_auth` (writable, the SPP account being created),
/// `system_program`, `spp_program`.
pub struct InitSppZoneConfig {
    pub authority: Pubkey,
    pub zone_config: Pubkey,
    pub protocol_config: Pubkey,
    pub zone_auth: Pubkey,
    pub system_program: Pubkey,
    pub spp_program: Pubkey,
}

impl InitSppZoneConfig {
    pub fn instruction(&self) -> Instruction {
        let accounts = vec![
            AccountMeta::new(self.authority, true),
            AccountMeta::new_readonly(self.zone_config, false),
            AccountMeta::new_readonly(self.protocol_config, false),
            AccountMeta::new(self.zone_auth, false),
            AccountMeta::new_readonly(self.system_program, false),
            AccountMeta::new_readonly(self.spp_program, false),
        ];

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: vec![tag::INIT_SPP_ZONE_CONFIG],
        }
    }
}
