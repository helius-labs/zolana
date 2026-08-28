use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, escrow_authority_pda, nullifier_marker_accounts, tag, SettleIxData, SettleProof};

/// Settles one escrow -- settle or price-refund -- and closes it. Permissionless:
/// `caller` only signs and pays fees. The instruction's shape, account list, and
/// verifying key are identical for both outcomes, and `max_price` is a private
/// circuit witness, so an observer cannot tell settle from refund.
pub struct Settle {
    pub caller: Pubkey,
    pub pair: Pubkey,
    pub escrow: Pubkey,
    pub rent_recipient: Pubkey,
    pub tree: Pubkey,
    pub proof: SettleProof,
    pub transact: TransactIxData,
}

impl Settle {
    pub fn instruction(self) -> Result<Instruction> {
        let Settle {
            caller,
            pair,
            escrow,
            rent_recipient,
            tree,
            proof,
            transact,
        } = self;

        let nullifier_markers = nullifier_marker_accounts(&tree, &transact);
        let ix_data = SettleIxData { proof, transact };
        let serialized = wincode::serialize(&ix_data).map_err(err)?;

        let mut instruction_data = vec![tag::SETTLE];
        instruction_data.extend_from_slice(&serialized);

        let mut accounts = vec![
            AccountMeta::new(caller, true),
            AccountMeta::new_readonly(pair, false),
            AccountMeta::new(escrow, false),
            AccountMeta::new(rent_recipient, false),
            // Forwarded SPP `transact` CPI tail: payer, input tree, output tree,
            // SPP, System Program, one nullifier marker per input, then escrow
            // authority.
            AccountMeta::new_readonly(caller, true),
            AccountMeta::new(tree, false),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ];
        accounts.extend(nullifier_markers);
        accounts.push(AccountMeta::new_readonly(
            escrow_authority_pda(&pair),
            false,
        ));

        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
