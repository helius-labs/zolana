use custom_ring_interface::{tag, SetCoSignerIxData, WithdrawalThresholdIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::CustomRing;

/// Creates or replaces the ring's co-signer under the config authority.
#[must_use]
pub struct SetCoSigner {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub signer: Address,
    /// A nonzero subset of the `COSIGN_*` bits.
    pub scope: u8,
    /// Per mint, SOL under the zero address, a withdrawn mint without a row
    /// always needs the co-signer.
    pub thresholds: Vec<(Address, u64)>,
}

impl SetCoSigner {
    pub fn instruction(self) -> Result<Instruction, wincode::Error> {
        let Self {
            ring,
            payer,
            authority,
            signer,
            scope,
            thresholds,
        } = self;
        let mut data = vec![tag::SET_CO_SIGNER];
        data.extend_from_slice(&wincode::serialize(&SetCoSignerIxData {
            signer: signer.to_bytes(),
            scope,
            thresholds: thresholds
                .into_iter()
                .map(|(mint, amount)| WithdrawalThresholdIxData {
                    mint: mint.to_bytes(),
                    amount,
                })
                .collect(),
        })?);
        Ok(Instruction {
            program_id: ring.program_id(),
            accounts: vec![
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new_readonly(ring.config_pda(), false),
                AccountMeta::new(ring.cosigner_pda(), false),
                AccountMeta::new_readonly(Address::default(), false),
            ],
            data,
        })
    }
}

/// Removes the ring's co-signing requirement and returns its account rent.
#[must_use]
pub struct ClearCoSigner {
    pub ring: CustomRing,
    pub authority: Address,
    pub rent_recipient: Address,
}

impl ClearCoSigner {
    pub fn instruction(self) -> Instruction {
        let Self {
            ring,
            authority,
            rent_recipient,
        } = self;
        Instruction {
            program_id: ring.program_id(),
            accounts: vec![
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new_readonly(ring.config_pda(), false),
                AccountMeta::new(ring.cosigner_pda(), false),
                AccountMeta::new(rent_recipient, false),
            ],
            data: vec![tag::CLEAR_CO_SIGNER],
        }
    }
}

/// `[cosigner_pda, cosigner]`, unset the slot repeats the PDA, a top-level
/// slot inherits the message signer flag of its address.
pub(crate) fn cosigner_metas(ring: CustomRing, cosigner: Option<Address>) -> [AccountMeta; 2] {
    let pda = ring.cosigner_pda();
    [
        AccountMeta::new_readonly(pda, false),
        match cosigner {
            Some(cosigner) => AccountMeta::new_readonly(cosigner, true),
            None => AccountMeta::new_readonly(pda, false),
        },
    ]
}
