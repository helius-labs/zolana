use custom_ring_interface::{tag, CreateConfigIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use thiserror::Error;
use zolana_keypair::P256Pubkey;

use crate::CustomRing;

#[must_use]
/// Creates the ring's singleton config account: the authority allowed to register
/// the ring with SPP, and the auditor key every `transact` must verifiably encrypt
/// the transaction viewing secret key to.
pub struct CreateConfig {
    pub ring: CustomRing,
    pub payer: Address,
    /// Stored as the config authority. It signs the creation so the recorded
    /// authority is always a key that consented to the role.
    pub authority: Address,
    /// Auditor P256 public key in SEC1 compressed form. The program rejects any
    /// prefix other than `0x02`/`0x03`: the circuit witnesses the uncompressed key
    /// and re-compresses it, so no other encoding could ever match a proof.
    pub auditor_pubkey: P256Pubkey,
    /// A policy ring enforces its compiled rules, an audit-only ring skips them.
    pub has_policy: bool,
}

#[derive(Debug, Error)]
pub enum CreateConfigError {
    #[error("auditor public key is reserved for protocol derivation")]
    ReservedAuditorKey,
    #[error(transparent)]
    Encoding(#[from] wincode::WriteError),
}

impl CreateConfig {
    pub fn instruction(self) -> Result<Instruction, CreateConfigError> {
        let Self {
            ring,
            payer,
            authority,
            auditor_pubkey,
            has_policy,
        } = self;
        if zolana_interface::is_reserved_p256_derivation_point(auditor_pubkey.as_bytes()) {
            return Err(CreateConfigError::ReservedAuditorKey);
        }

        let mut data = vec![tag::CREATE_CONFIG];
        data.extend_from_slice(&wincode::serialize(&CreateConfigIxData {
            auditor_pubkey: *auditor_pubkey.as_bytes(),
            has_policy: u8::from(has_policy),
        })?);

        Ok(Instruction {
            program_id: ring.program_id(),
            accounts: vec![
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(authority, true),
                // The config is the canonical `[b"config"]` derivation; the program
                // rederives it and never accepts a bump from instruction data.
                AccountMeta::new(ring.config_pda(), false),
                // The system program is the all-zero address.
                AccountMeta::new_readonly(Address::default(), false),
                AccountMeta::new_readonly(ring.program_id(), false),
                AccountMeta::new_readonly(ring.program_data_pda(), false),
            ],
            data,
        })
    }
}
