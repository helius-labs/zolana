use anyhow::{anyhow, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, escrow_authority_pda, tag, SettleIxData, SettleProof};

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
            mut transact,
        } = self;

        // Both inputs (order, reservation) are owned by the escrow_authority PDA,
        // forwarded at tail slot 2: [caller(payer)=0, tree=1, escrow_authority=2,
        // program=3]. The program flips the PDA to a signer via invoke_signed.
        const ESCROW_AUTHORITY_POSITION: u8 = 2;
        route_input(&mut transact, 0, ESCROW_AUTHORITY_POSITION)?;
        route_input(&mut transact, 1, ESCROW_AUTHORITY_POSITION)?;

        let ix_data = SettleIxData { proof, transact };
        let serialized = wincode::serialize(&ix_data).map_err(err)?;

        let mut instruction_data = vec![tag::SETTLE];
        instruction_data.extend_from_slice(&serialized);

        let accounts = vec![
            AccountMeta::new(caller, true),
            AccountMeta::new_readonly(pair, false),
            AccountMeta::new(escrow, false),
            AccountMeta::new(rent_recipient, false),
            // Forwarded SPP `transact` CPI tail: payer, tree, the escrow_authority
            // account (flipped to a signer in-program), then the program id last.
            AccountMeta::new_readonly(caller, true),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(escrow_authority_pda(&pair), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
        ];

        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}

/// Points `transact.inputs[input]`'s `eddsa_signer_index` at `position`, the
/// slot of that input's owner within the forwarded SPP `transact` account tail.
fn route_input(transact: &mut TransactIxData, input: usize, position: u8) -> Result<()> {
    transact
        .inputs
        .get_mut(input)
        .ok_or_else(|| anyhow!("transact input {input} out of range"))?
        .eddsa_signer_index = position;
    Ok(())
}
