use crate::instructions::shared::caused_by;
use pinocchio::{
    cpi::{Seed, Signer},
    AccountView, ProgramResult, Resize,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};
use zolana_interface::{error::ShieldedPoolError, state::TREE_ALLOCATION_STEP, TREE_PDA_SEED};
use zolana_tree::UNINITIALIZED;

pub(super) fn is_unallocated(tree: &AccountView) -> bool {
    pinocchio_system::check_id(tree.owner()) && tree.data_len() == 0
}

pub(super) struct TreeAllocation<'a> {
    pub payer: &'a AccountView,
    pub tree: &'a mut AccountView,
    pub tree_id_seed: [u8; 2],
    pub bump: u8,
    pub full_size: usize,
    pub lamports: u64,
}

impl TreeAllocation<'_> {
    #[inline(never)]
    pub fn create(self) -> ProgramResult {
        let bump_seed = [self.bump];
        let seeds = [
            Seed::from(TREE_PDA_SEED),
            Seed::from(self.tree_id_seed.as_ref()),
            Seed::from(bump_seed.as_ref()),
        ];
        let signer = Signer::from(&seeds);
        let space = self.full_size.min(TREE_ALLOCATION_STEP) as u64;
        if self.tree.lamports() == 0 {
            return CreateAccount {
                from: self.payer,
                to: self.tree,
                lamports: self.lamports,
                space,
                owner: &crate::ID,
            }
            .invoke_signed(&[signer]);
        }
        Allocate {
            account: self.tree,
            space,
        }
        .invoke_signed(core::slice::from_ref(&signer))?;
        Assign {
            account: self.tree,
            owner: &crate::ID,
        }
        .invoke_signed(core::slice::from_ref(&signer))?;
        fund_tree(self.payer, self.tree, self.lamports)
    }
}

#[inline(never)]
pub(super) fn fund_tree(payer: &AccountView, tree: &AccountView, lamports: u64) -> ProgramResult {
    let missing = lamports.saturating_sub(tree.lamports());
    if missing == 0 {
        return Ok(());
    }
    Transfer {
        from: payer,
        to: tree,
        lamports: missing,
    }
    .invoke()
}

#[inline(never)]
pub(super) fn grow_tree(tree: &mut AccountView, full_size: usize) -> ProgramResult {
    if !tree.is_writable() || !tree.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidTreeAccounts.into());
    }
    let current = tree.data_len();
    if current >= full_size {
        return Ok(());
    }
    {
        let data = tree
            .try_borrow()
            .map_err(caused_by(ShieldedPoolError::InvalidTreeAccounts))?;
        if data.get(1).copied() != Some(UNINITIALIZED) {
            return Err(ShieldedPoolError::InvalidTreeAccounts.into());
        }
    }
    let target = current.saturating_add(TREE_ALLOCATION_STEP).min(full_size);
    tree.resize(target)
}
