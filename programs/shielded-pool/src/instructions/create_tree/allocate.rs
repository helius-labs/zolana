use crate::instructions::shared::caused_by;
use pinocchio::{
    cpi::{Seed, Signer},
    AccountView, ProgramResult, Resize,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};
use zolana_interface::{error::ShieldedPoolError, state::TREE_ALLOCATION_STEP, TREE_PDA_SEED};
use zolana_tree::UNINITIALIZED;

pub(crate) fn is_unallocated(tree: &AccountView) -> bool {
    pinocchio_system::check_id(tree.owner()) && tree.data_len() == 0
}

pub(crate) struct TreeAllocation<'a> {
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
        create_account(self.payer, self.tree, &seeds, self.full_size, self.lamports)
    }
}

#[inline(never)]
pub(crate) fn fund_tree(payer: &AccountView, tree: &AccountView, lamports: u64) -> ProgramResult {
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
pub(crate) fn grow_tree(tree: &mut AccountView, full_size: usize) -> ProgramResult {
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
    grow_account(tree, full_size)
}

pub(crate) fn create_account(
    payer: &AccountView,
    account: &mut AccountView,
    seeds: &[Seed<'_>],
    full_size: usize,
    lamports: u64,
) -> ProgramResult {
    let signer = Signer::from(seeds);
    let space = full_size.min(TREE_ALLOCATION_STEP) as u64;
    if account.lamports() == 0 {
        return CreateAccount {
            from: payer,
            to: account,
            lamports,
            space,
            owner: &crate::ID,
        }
        .invoke_signed(&[signer]);
    }
    Allocate { account, space }.invoke_signed(core::slice::from_ref(&signer))?;
    Assign {
        account,
        owner: &crate::ID,
    }
    .invoke_signed(core::slice::from_ref(&signer))?;
    fund_tree(payer, account, lamports)
}

pub(crate) fn grow_account(account: &mut AccountView, full_size: usize) -> ProgramResult {
    let target = account
        .data_len()
        .saturating_add(TREE_ALLOCATION_STEP)
        .min(full_size);
    account.resize(target)
}
