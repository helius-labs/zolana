use custom_ring_program::instructions::create_config::CreateConfigIxData;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_keypair::P256Pubkey;

use crate::{config_pda, program_data_pda, tag, PROGRAM_ID};

/// Creates the ring's singleton config account: the authority allowed to register
/// the ring with SPP, and the auditor key every `transact` must verifiably encrypt
/// the transaction viewing secret key to.
pub struct CreateConfig {
    pub payer: Address,
    /// Stored as the config authority. It signs the creation so the recorded
    /// authority is always a key that consented to the role. When the program
    /// was deployed with an upgrade authority, this must be that key.
    pub authority: Address,
    /// Auditor P256 public key. The type guarantees a point on the curve; the
    /// program only checks the SEC1 prefix, and an off-curve key would leave the
    /// ring without a provable transaction.
    pub auditor_pubkey: P256Pubkey,
}

impl CreateConfig {
    pub fn instruction(self) -> Instruction {
        let Self {
            payer,
            authority,
            auditor_pubkey,
        } = self;

        let mut data = vec![tag::CREATE_CONFIG];
        data.extend_from_slice(
            // A fixed 33-byte payload written into a growable buffer: wincode has
            // nothing to fail on here.
            &wincode::serialize(&CreateConfigIxData {
                auditor_pubkey: *auditor_pubkey.as_bytes(),
            })
            .expect("create_config instruction data is fixed size"),
        );

        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(authority, true),
                // The config is the canonical `[b"config"]` derivation; the program
                // rederives it and never accepts a bump from instruction data.
                AccountMeta::new(config_pda(), false),
                // The system program is the all-zero address.
                AccountMeta::new_readonly(Address::default(), false),
                // The program and its loader-v3 `ProgramData` account, read for
                // the upgrade-authority gate.
                AccountMeta::new_readonly(PROGRAM_ID, false),
                AccountMeta::new_readonly(program_data_pda(), false),
            ],
            data,
        }
    }
}
