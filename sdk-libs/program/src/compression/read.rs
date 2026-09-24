use pinocchio::{address::address_eq, AccountView, Address};
use zolana_interface::{
    instruction::instruction_data::transact::TreeContext,
    pda::nullifier_pda,
    state::{discriminator::TREE_ACCOUNT_DISCRIMINATOR, tree::read_tree_id},
    PROGRAM_ID_PUBKEY,
};
use zolana_tree::TreeAccount;

use super::{CompressedAccountError, DataUtxo, UtxoKey};

/// The raw id of a shielded-pool tree, read from its account. Every UTXO hash
/// folds it in, so a program hashes with the id of the tree it passes to the
/// pool rather than assuming one.
pub fn load_tree_id(tree: &AccountView) -> Result<u16, CompressedAccountError> {
    if !tree.owned_by(&PROGRAM_ID_PUBKEY) {
        return Err(CompressedAccountError::InvalidTreeAccount);
    }
    let data = tree
        .try_borrow()
        .map_err(|_| CompressedAccountError::AccountBorrowFailed)?;
    if data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
        return Err(CompressedAccountError::InvalidTreeAccount);
    }
    read_tree_id(&data).ok_or(CompressedAccountError::InvalidTreeAccount)
}

/// The roots a read proves against and the tree they come from. Its fields are
/// private, so a program can only get roots out of a shielded-pool tree
/// account, and the UTXO hash and nullifier PDA it checks are bound to that
/// same tree.
///
/// A read is sound only with both of its checks:
/// 1. the program's proof shows the UTXO hash in the state tree under
///    [`Self::utxo_root`] and its nullifier absent from the nullifier tree
///    under [`Self::nullifier_root`], roots from the tree's root histories;
/// 2. [`Self::assert_unspent`] shows the nullifier PDA does not exist.
///
/// 1 alone misses a nullifier that is queued but not yet in the nullifier
/// tree; 2 alone misses a spend whose PDA was closed. A nullifier PDA closes
/// only once every root in the history contains its nullifier, so the two
/// together cover every spend.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadRoots {
    tree: Address,
    tree_id: u16,
    utxo_root: [u8; 32],
    nullifier_root: [u8; 32],
}

impl ReadRoots {
    /// The roots at `tree_context`'s history indexes. `TreeAccount` only loads
    /// through a mutable borrow, so the data is borrowed mutably even when the
    /// tree is passed read-only; nothing writes to it. The borrow ends before
    /// this returns.
    pub fn load(
        tree: &mut AccountView,
        tree_context: &TreeContext,
    ) -> Result<Self, CompressedAccountError> {
        if !tree.owned_by(&PROGRAM_ID_PUBKEY) {
            return Err(CompressedAccountError::InvalidTreeAccount);
        }
        let address = *tree.address();
        let mut data = tree
            .try_borrow_mut()
            .map_err(|_| CompressedAccountError::AccountBorrowFailed)?;
        if data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
            return Err(CompressedAccountError::InvalidTreeAccount);
        }
        let account = TreeAccount::from_bytes(&mut data, address.to_bytes())
            .map_err(|_| CompressedAccountError::InvalidTreeAccount)?;
        let utxo_root = account
            .get_utxo_tree_root(tree_context.utxo_tree_root_index)
            .map_err(|_| CompressedAccountError::InvalidRootIndex)?;
        let nullifier_root = account
            .get_nullifier_tree_root(tree_context.nullifier_tree_root_index)
            .map_err(|_| CompressedAccountError::InvalidRootIndex)?;
        Ok(Self {
            tree: address,
            tree_id: account.tree_id(),
            utxo_root,
            nullifier_root,
        })
    }

    pub fn tree(&self) -> &Address {
        &self.tree
    }

    pub fn tree_id(&self) -> u16 {
        self.tree_id
    }

    pub fn utxo_root(&self) -> &[u8; 32] {
        &self.utxo_root
    }

    pub fn nullifier_root(&self) -> &[u8; 32] {
        &self.nullifier_root
    }

    /// The UTXO's hash and nullifier in this tree.
    pub fn key(&self, utxo: &DataUtxo) -> Result<UtxoKey, CompressedAccountError> {
        utxo.key(self.tree_id)
    }

    /// Checks that `nullifier_pda` is the canonical nullifier PDA of `key` on
    /// this tree and that it does not exist. The canonical bump matters: a
    /// PDA under any other bump is a different address that is always empty.
    pub fn assert_unspent(
        &self,
        nullifier_pda_account: &AccountView,
        key: &UtxoKey,
    ) -> Result<(), CompressedAccountError> {
        let (expected, _) = nullifier_pda(&self.tree, key.nullifier());
        if !address_eq(nullifier_pda_account.address(), &expected) {
            return Err(CompressedAccountError::InvalidNullifierPda);
        }
        if !nullifier_pda_account.owned_by(&Address::default())
            || nullifier_pda_account.data_len() != 0
        {
            return Err(CompressedAccountError::StateSpent);
        }
        Ok(())
    }
}
