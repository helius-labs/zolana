use custom_ring_interface::{tag, SetDepositAuditIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::CustomRing;

/// Config authority update of the direct deposit disclosure requirement.
#[must_use]
pub struct SetDepositAudit {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub required: bool,
}

impl SetDepositAudit {
    pub fn instruction(self) -> Result<Instruction, wincode::Error> {
        let mut data = vec![tag::SET_DEPOSIT_AUDIT];
        data.extend(wincode::serialize(&SetDepositAuditIxData {
            required: u8::from(self.required),
        })?);
        Ok(Instruction {
            program_id: self.ring.program_id(),
            accounts: vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new_readonly(self.ring.config_pda(), false),
                AccountMeta::new(self.ring.deposit_audit_pda(), false),
                AccountMeta::new_readonly(Address::default(), false),
            ],
            data,
        })
    }
}
