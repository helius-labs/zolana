use custom_ring_interface::{tag, CoSignScope, SetCoSignerIxData, WithdrawalThreshold};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::CustomRing;

/// SOL under the zero address, a mint without a row always needs the co-signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoSignThreshold {
    pub mint: Address,
    pub amount: u64,
}

#[must_use]
pub struct SetCoSigner {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub signer: Address,
    pub scope: CoSignScope,
    pub thresholds: Vec<CoSignThreshold>,
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
            scope: scope.bits(),
            thresholds: thresholds
                .into_iter()
                .map(|threshold| WithdrawalThreshold {
                    mint: threshold.mint.to_bytes(),
                    amount: threshold.amount,
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

#[derive(Clone, Copy)]
pub(crate) enum RingPolicy {
    Off,
    Config,
    Entries(Address),
}

/// `[config, cosigner_pda, cosigner, policy accounts]`, unset the co-signer slot repeats the PDA.
pub(crate) struct RingPrefix {
    pub ring: CustomRing,
    pub cosigner: Option<Address>,
    pub policy: RingPolicy,
}

impl RingPrefix {
    /// A top-level slot inherits the signer flag of its address.
    pub(crate) fn metas(self) -> Vec<AccountMeta> {
        let pda = self.ring.cosigner_pda();
        let mut metas = vec![
            AccountMeta::new_readonly(self.ring.config_pda(), false),
            AccountMeta::new_readonly(pda, false),
            match self.cosigner {
                Some(cosigner) => AccountMeta::new_readonly(cosigner, true),
                None => AccountMeta::new_readonly(pda, false),
            },
        ];
        match self.policy {
            RingPolicy::Off => {}
            RingPolicy::Config => {
                metas.push(AccountMeta::new_readonly(
                    self.ring.policy_config_pda(),
                    false,
                ));
            }
            RingPolicy::Entries(entries_tree) => {
                metas.push(AccountMeta::new_readonly(
                    self.ring.policy_config_pda(),
                    false,
                ));
                metas.push(AccountMeta::new_readonly(entries_tree, false));
            }
        }
        metas
    }
}
