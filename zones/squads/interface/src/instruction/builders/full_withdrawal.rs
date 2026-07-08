//! `full_withdrawal` (tag 10) instruction builder (spec: squads
//! `full_withdrawal`).

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::{
    instruction::{builders::TransactWithdrawal, tag, FullWithdrawalIxData},
    PROGRAM_ID_PUBKEY,
};

/// Builder for the `full_withdrawal` instruction: the escape-hatch exit.
///
/// Account order: `payer` (signer, also the SPP payer bound in the proof),
/// `zone_auth`, `spp_program`, `tree`, then the SOL/SPL settlement tail. There is
/// no co-signer and no zone proof; the forwarded SPP proof authorizes the exit
/// (P256 UTXO ownership), and the signer is only a fee payer -- it need not be the
/// UTXO owner.
pub struct FullWithdrawal {
    pub payer: Pubkey,
    pub zone_auth: Pubkey,
    pub spp_program: Pubkey,
    pub tree: Pubkey,
    pub settlement: TransactWithdrawal,
    pub data: FullWithdrawalIxData,
}

impl FullWithdrawal {
    pub fn instruction(&self) -> Instruction {
        let mut instruction_data = vec![tag::FULL_WITHDRAWAL];
        instruction_data.extend_from_slice(
            &self
                .data
                .serialize()
                .expect("squads-zone instruction serialization is infallible"),
        );

        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.zone_auth, false),
            AccountMeta::new_readonly(self.spp_program, false),
            AccountMeta::new(self.tree, false),
        ];
        self.settlement.push_account_metas(&mut accounts);

        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts,
            data: instruction_data,
        }
    }
}
