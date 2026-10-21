use custom_ring_interface::CustomRingError;
use futures::future::try_join_all;
use solana_address::Address;
use zolana_client::AsyncRpc;
use zolana_interface::{
    pda, state::discriminator::TREE_ACCOUNT_DISCRIMINATOR, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_transaction::utxo::SppProofInputUtxo;
use zolana_tree::TreeAccount;

use crate::RingError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PoolTree {
    pub address: Address,
    pub id: u16,
}

pub(crate) struct TreeView {
    pub tree: PoolTree,
    /// Nullifier slots left above the state tree's capacity, queued ones counted.
    pub headroom: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SpendTrees {
    /// One per input tree, in first-use order.
    pub inputs: Vec<Address>,
    pub output: Address,
    /// SPP admits dummy inputs only when every input tree has headroom for its slots.
    pub allow_dummy_inputs: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundAnchor {
    pub tree: Address,
    pub root_index: u16,
    pub root: [u8; 32],
}

/// Every UTXO of the tree hashes under its raw id.
pub async fn tree_id(rpc: &(impl AsyncRpc + ?Sized), tree: Address) -> Result<u16, RingError> {
    Ok(read_tree(rpc, tree).await?.tree.id)
}

pub(crate) async fn read_tree(
    rpc: &(impl AsyncRpc + ?Sized),
    address: Address,
) -> Result<TreeView, RingError> {
    let mut data = tree_data(rpc, address).await?;
    let tree = TreeAccount::from_bytes(&mut data, address.to_bytes())?;
    Ok(TreeView {
        tree: PoolTree {
            address,
            id: tree.tree_id(),
        },
        headroom: tree.dummy_input_headroom()?,
    })
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

impl BoundAnchor {
    /// The program reads the root at the index of an unpaused tree.
    pub(crate) async fn holds(&self, rpc: &(impl AsyncRpc + ?Sized)) -> Result<bool, RingError> {
        let mut data = tree_data(rpc, self.tree).await?;
        let tree = TreeAccount::from_bytes(&mut data, self.tree.to_bytes())?;
        if tree.is_paused() {
            return Err(CustomRingError::FirstContactTreePaused.into());
        }
        Ok(tree.get_utxo_tree_root(self.root_index).ok() == Some(self.root))
    }
}

async fn tree_data(rpc: &(impl AsyncRpc + ?Sized), address: Address) -> Result<Vec<u8>, RingError> {
    let account = rpc
        .get_account(address)
        .await?
        .ok_or(RingError::MissingTree { address })?;
    if account.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID
        || account.data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR)
    {
        return Err(RingError::InvalidTree { address });
    }
    Ok(account.data)
}
