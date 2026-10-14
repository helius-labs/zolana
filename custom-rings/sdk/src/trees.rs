use futures::future::try_join_all;
use solana_address::Address;
use zolana_client::AsyncRpc;
use zolana_interface::{
    instruction::instruction_data::transact::TreeContext, pda,
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR, tree_slot::TreeSlot,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_transaction::utxo::SppProofInputUtxo;
use zolana_tree::TreeAccount;

use crate::{PoolTree, RingError};

/// Current roots with the history entries a statement names them by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TransactRoots {
    pub state: [u8; 32],
    pub state_index: u16,
    pub nullifier: [u8; 32],
    pub nullifier_index: u16,
}

impl TransactRoots {
    pub fn slot(&self, id: u16) -> TreeSlot {
        TreeSlot::new(id, self.state, self.nullifier)
    }

    pub fn context(&self) -> TreeContext {
        TreeContext {
            utxo_tree_root_index: self.state_index,
            nullifier_tree_root_index: self.nullifier_index,
        }
    }
}

pub(crate) struct TreeView {
    pub tree: PoolTree,
    /// Nullifier slots left above the state tree's capacity, queued ones counted.
    pub headroom: u64,
    pub roots: TransactRoots,
}

pub(crate) async fn read_tree(
    rpc: &(impl AsyncRpc + ?Sized),
    address: Address,
) -> Result<TreeView, RingError> {
    let mut account = rpc
        .get_account(address)
        .await?
        .ok_or(RingError::MissingTree { address })?;
    if account.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID
        || account.data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR)
    {
        return Err(RingError::InvalidTree { address });
    }
    let mut tree = TreeAccount::from_bytes(&mut account.data, address.to_bytes())?;
    let state_index = tree.utxo_tree().current_root_index();
    let nullifier_index = tree.nullifier_tree().get_root_index() as u16;
    Ok(TreeView {
        tree: PoolTree {
            address,
            id: tree.tree_id(),
        },
        headroom: tree.dummy_input_headroom()?,
        roots: TransactRoots {
            state: tree.get_utxo_tree_root(state_index)?,
            state_index,
            nullifier: tree.get_nullifier_tree_root(nullifier_index)?,
            nullifier_index,
        },
    })
}

/// The raw id of a pool tree, every UTXO in it hashes under this id.
pub async fn tree_id(rpc: &(impl AsyncRpc + ?Sized), tree: Address) -> Result<u16, RingError> {
    Ok(read_tree(rpc, tree).await?.tree.id)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SpendTrees {
    /// One per input tree, in first-use order.
    pub inputs: Vec<Address>,
    pub output: Address,
    /// SPP admits dummy inputs only when every input tree has headroom for its slots.
    pub allow_dummy_inputs: bool,
}

/// Input tree ids in first-use order with the slots each holds, dummies included.
pub(crate) fn input_groups(inputs: &[SppProofInputUtxo]) -> Vec<(u16, u64)> {
    let mut groups: Vec<(u16, u64)> = Vec::new();
    for input in inputs {
        match groups.iter_mut().find(|(id, _)| *id == input.tree_id) {
            Some((_, count)) => *count += 1,
            None => groups.push((input.tree_id, 1)),
        }
    }
    groups
}

pub(crate) async fn spend_trees(
    rpc: &(impl AsyncRpc + ?Sized),
    inputs: &[SppProofInputUtxo],
    output_tree_id: u16,
) -> Result<SpendTrees, RingError> {
    let groups = input_groups(inputs);
    let views = try_join_all(groups.iter().map(|(id, _)| read_tree(rpc, pda::tree(*id)))).await?;
    let output = read_tree(rpc, pda::tree(output_tree_id)).await?;
    bind_trees(&groups, &views, &output, output_tree_id)
}

/// Every UTXO hash commits to its tree id, a tree under another id proves nothing.
pub(crate) fn bind_trees(
    groups: &[(u16, u64)],
    views: &[TreeView],
    output: &TreeView,
    output_tree_id: u16,
) -> Result<SpendTrees, RingError> {
    let expected = groups.iter().map(|(id, _)| *id).chain([output_tree_id]);
    for (found, view) in expected.zip(views.iter().chain([output])) {
        if view.tree.id != found {
            return Err(RingError::TreeIdMismatch {
                tree: view.tree.address,
                expected: view.tree.id,
                found,
            });
        }
    }
    Ok(SpendTrees {
        allow_dummy_inputs: groups
            .iter()
            .zip(views)
            .all(|((_, count), view)| view.headroom >= *count),
        inputs: views.iter().map(|view| view.tree.address).collect(),
        output: output.tree.address,
    })
}
