use anyhow::{bail, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{
        builders::{Transact, TransactInterfaceTransferAccounts, TransactSplWithdrawalAccounts},
        instruction_data::transact::{InterfaceTransfer, TransactIxData},
    },
    pda,
};

use crate::{err, pool_authority_pda, tag, Groth16ProofBytes, WithdrawLiquidityIxData};

/// The SPL destination of a withdrawal.
#[derive(Clone, Copy, Debug)]
pub struct WithdrawSplAccounts {
    pub mint: Pubkey,
    /// Must be owned by the pair authority (the program checks the token
    /// account's owner field).
    pub user_token: Pubkey,
    pub token_program: Pubkey,
}

/// Unshields a public `amount` from one pool note to the authority's SPL token
/// account. Authority-only.
pub struct WithdrawLiquidity {
    pub authority: Pubkey,
    pub pair: Pubkey,
    pub tree: Pubkey,
    pub amount: u64,
    pub spl: WithdrawSplAccounts,
    pub proof: Groth16ProofBytes,
    pub transact: TransactIxData,
}

impl WithdrawLiquidity {
    pub fn instruction(self) -> Result<Instruction> {
        if self.amount == 0 {
            bail!("withdrawal amount must be nonzero");
        }
        match self.transact.interface_transfers.as_slice() {
            [InterfaceTransfer::SplWithdrawal { amount, .. }] if *amount == self.amount => {}
            _ => bail!("transact must contain one SPL withdrawal matching the amount"),
        }
        let transfer_accounts = vec![TransactInterfaceTransferAccounts::SplWithdrawal(
            TransactSplWithdrawalAccounts {
                mint: self.spl.mint,
                spl_interface: pda::spl_interface(&self.spl.mint),
                user_token_account: self.spl.user_token,
                token_program: self.spl.token_program,
            },
        )];
        // The interface builder lays out the canonical transact tail: payer,
        // trees, SPP, System Program, the pool authority owner-signer, then
        // the SplWithdrawal settlement group. The builder marks owner signers
        // as transaction signers (the direct-call convention); here the swap
        // program flips the pool authority to a signer in its CPI instead, so
        // demote it in the outer transaction.
        let pool_authority = pool_authority_pda(&self.pair);
        let mut spp_ix = Transact {
            payer: self.authority,
            input_tree: self.tree,
            output_tree: self.tree,
            owner_signers: vec![pool_authority],
            interface_transfer_accounts: transfer_accounts,
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

        let ix_data = WithdrawLiquidityIxData {
            proof: self.proof,
            amount: self.amount,
            transact: self.transact,
        };
        let mut instruction_data = vec![tag::WITHDRAW_LIQUIDITY];
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
