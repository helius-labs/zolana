//! `deposit` (tag 1) instruction builder (spec: squads `deposit`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{tag, DepositIxData},
    PROGRAM_ID_PUBKEY,
};

/// Settlement accounts for a `deposit`, selecting the asset rail. The zone
/// forwards these to SPP's `zone_deposit`, which infers the asset from them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositSettlement {
    /// Native SOL: the depositor funds the SPP `sol_interface` PDA. SPP also
    /// reads the system program and the depositor as `user_sol`; both are
    /// derivable, so only the interface PDA is supplied here.
    Sol { sol_interface: Pubkey },
    /// SPL: the depositor's `user_token` account funds the per-mint `vault` PDA;
    /// `registry` supplies the mint and `token_program` moves the tokens.
    Spl {
        user_token: Pubkey,
        vault: Pubkey,
        registry: Pubkey,
        token_program: Pubkey,
    },
}

/// Builder for the `deposit` instruction.
///
/// Account order: `depositor`, `recipient_viewing_key_account`, `zone_auth`,
/// `spp_program`, `tree`, then the settlement accounts for the chosen rail.
pub struct Deposit {
    pub depositor: Pubkey,
    pub recipient_viewing_key_account: Pubkey,
    pub zone_auth: Pubkey,
    pub spp_program: Pubkey,
    pub tree: Pubkey,
    pub settlement: DepositSettlement,
    pub data: DepositIxData,
}

impl Deposit {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::DEPOSIT];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-zone instruction serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.depositor, true),
            AccountMeta::new_readonly(self.recipient_viewing_key_account, false),
            AccountMeta::new_readonly(self.zone_auth, false),
            AccountMeta::new_readonly(self.spp_program, false),
            AccountMeta::new(self.tree, false),
        ];
        match self.settlement {
            DepositSettlement::Sol { sol_interface } => accounts.extend([
                AccountMeta::new_readonly(Pubkey::default(), false),
                AccountMeta::new(sol_interface, false),
                AccountMeta::new(self.depositor, true),
            ]),
            DepositSettlement::Spl {
                user_token,
                vault,
                registry,
                token_program,
            } => accounts.extend([
                AccountMeta::new(user_token, false),
                AccountMeta::new(vault, false),
                AccountMeta::new_readonly(registry, false),
                AccountMeta::new_readonly(token_program, false),
            ]),
        }

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
