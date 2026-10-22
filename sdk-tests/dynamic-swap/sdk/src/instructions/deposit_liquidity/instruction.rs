use anyhow::{bail, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_program::instruction::Transact;

use crate::{err, pool_authority_pda, tag, DepositLiquidityIxData, Groth16ProofBytes};

/// Moves a public `amount` of the depositor's shielded destination asset into
/// a new pool note that holds and books `amount`. A proven transact with no
/// public transfer: the `pool_deposit` proof binds its only input to a
/// non-pool note of exactly `amount` and its only output to the pool, and the
/// swap program raises `available_liquidity` by `amount`. Permissionless: the
/// depositor pays and owns the spent note, so it signs the outer transaction.
pub struct DepositLiquidity {
    pub depositor: Pubkey,
    pub pair: Pubkey,
    pub tree: Pubkey,
    pub amount: u64,
    pub proof: Groth16ProofBytes,
    pub transact: TransactIxData,
}

impl DepositLiquidity {
    pub fn instruction(self) -> Result<Instruction> {
        if self.amount == 0 {
            bail!("deposit amount must be nonzero");
        }
        if !self.transact.interface_transfers.is_empty() {
            bail!("a deposit transact carries no public transfer");
        }
        // The interface builder lays out the canonical transact tail: payer,
        // output tree, SPP, System Program, input tree, the source note's
        // nullifier PDA, then the depositor and pool authority owner-signers.
        // The depositor owns the source; the pool authority owns the
        // data-bearing pool note. A paying owner still takes an explicit
        // owner-signer slot. The builder marks owner signers as transaction
        // signers (the direct-call convention); here
        // the swap program flips the pool authority to a signer in its CPI
        // instead, so demote it in the outer transaction.
        let pool_authority = pool_authority_pda(&self.pair);
        let mut spp_ix = Transact {
            payer: self.depositor,
            input_trees: vec![self.tree],
            output_tree: self.tree,
            owner_signers: vec![self.depositor, pool_authority],
            interface_transfer_accounts: vec![],
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

        let ix_data = DepositLiquidityIxData {
            proof: self.proof,
            amount: self.amount,
            transact: self.transact,
        };
        let mut instruction_data = vec![tag::DEPOSIT_LIQUIDITY];
        instruction_data.extend_from_slice(&wincode::serialize(&ix_data).map_err(err)?);

        let mut accounts = vec![AccountMeta::new(self.pair, false)];
        accounts.extend(spp_ix.accounts);

        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
