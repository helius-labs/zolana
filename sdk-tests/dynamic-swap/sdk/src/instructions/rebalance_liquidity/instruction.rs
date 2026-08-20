use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::instruction::{
    builders::Transact, instruction_data::transact::TransactIxData,
};

use crate::{err, pool_authority_pda, tag, Groth16ProofBytes, RebalanceLiquidityIxData};

/// Restructures the pool (merge, split, re-blind, redistribute booked) and
/// optionally publishes settle surplus into `available_liquidity` via the public
/// `credit`. Authority-only; the transact always declares shape IN5_OUT4 with
/// dummy-padded slots and carries no interface transfers.
pub struct RebalanceLiquidity {
    pub authority: Pubkey,
    pub pair: Pubkey,
    pub tree: Pubkey,
    pub credit: u64,
    pub proof: Groth16ProofBytes,
    pub transact: TransactIxData,
}

impl RebalanceLiquidity {
    pub fn instruction(self) -> Result<Instruction> {
        // The interface builder lays out the canonical transact tail: payer,
        // trees, SPP, System Program, the pool authority owner-signer. The
        // builder marks owner signers as transaction signers (the direct-call
        // convention); here the swap program flips the pool authority to a
        // signer in its CPI instead, so demote it in the outer transaction.
        let pool_authority = pool_authority_pda(&self.pair);
        let mut spp_ix = Transact {
            payer: self.authority,
            input_tree: self.tree,
            output_tree: self.tree,
            owner_signers: vec![pool_authority],
            interface_transfer_accounts: Vec::new(),
            data: self.transact.clone(),
        }
        .instruction();
        for meta in spp_ix
            .accounts
            .iter_mut()
            .filter(|meta| meta.pubkey == pool_authority)
        {
            meta.is_signer = false;
        }

        let ix_data = RebalanceLiquidityIxData {
            proof: self.proof,
            credit: self.credit,
            transact: self.transact,
        };
        let mut instruction_data = vec![tag::REBALANCE_LIQUIDITY];
        instruction_data.extend_from_slice(&wincode::serialize(&ix_data).map_err(err)?);

        let mut accounts = vec![
            AccountMeta::new(self.authority, true),
            AccountMeta::new(self.pair, false),
        ];
        accounts.extend(spp_ix.accounts);

        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
