use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::pda;

use crate::{config_pda, ring_auth_pda, tag, PROGRAM_ID};

/// Registers the ring with SPP by creating its `RingConfig` account -- which is the
/// ring's own `ring_auth` PDA -- through a CPI that PDA signs.
///
/// Carries no instruction data: the CPI payload (ring program id, authority,
/// disabled authority-transact rail) is built on-chain from the config account, so
/// a client cannot influence what gets registered.
pub struct InitSppRingConfig {
    pub payer: Address,
    /// Must equal the authority stored in the config account; the program compares
    /// them and rejects any other signer.
    pub authority: Address,
}

impl InitSppRingConfig {
    pub fn instruction(self) -> Instruction {
        let Self { payer, authority } = self;

        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new_readonly(config_pda(), false),
                AccountMeta::new_readonly(pda::protocol_config(), false),
                // SPP allocates its `RingConfig` here. The account stays unsigned in
                // the outer instruction: nobody holds its key, and the ring program
                // is what flips the meta to a signer inside the CPI.
                AccountMeta::new(ring_auth_pda(), false),
                // The system program is the all-zero address.
                AccountMeta::new_readonly(Address::default(), false),
                AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
            ],
            data: vec![tag::INIT_SPP_RING_CONFIG],
        }
    }
}
