use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, escrow_authority_pda, tag, CancelIxData, Groth16ProofBytes};

/// Refunds one expired escrow and closes it. Permissionless: `caller` only
/// signs and pays fees; only a holder of the order UTXO data can build a valid
/// proof, and the refund destination (the recipient committed as the order
/// UTXO's data hash) is fixed by the proof.
pub struct Cancel {
    pub caller: Pubkey,
    pub pair: Pubkey,
    pub escrow: Pubkey,
    pub rent_recipient: Pubkey,
    pub tree: Pubkey,
    pub proof: Groth16ProofBytes,
    pub transact: TransactIxData,
}

impl Cancel {
    pub fn instruction(self) -> Result<Instruction> {
        let Cancel {
            caller,
            pair,
            escrow,
            rent_recipient,
            tree,
            proof,
            transact,
        } = self;

        let ix_data = CancelIxData { proof, transact };
        let serialized = wincode::serialize(&ix_data).map_err(err)?;

        let mut instruction_data = vec![tag::CANCEL];
        instruction_data.extend_from_slice(&serialized);

        let accounts = vec![
            AccountMeta::new(caller, true),
            AccountMeta::new_readonly(pair, false),
            AccountMeta::new(escrow, false),
            AccountMeta::new(rent_recipient, false),
            // Forwarded SPP `transact` CPI tail: payer, input tree, output tree,
            // SPP, System Program, then the escrow authority (the single
            // owner-signer, flipped by the program's CPI, authorizing the order
            // input).
            AccountMeta::new_readonly(caller, true),
            AccountMeta::new(tree, false),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(escrow_authority_pda(&pair), false),
        ];

        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
