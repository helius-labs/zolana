//! Address-tree init helpers built on top of light-batched-merkle-tree.
//!
//! An address tree is a single Solana account hosting the batched merkle tree
//! state plus its in-account input queue. The caller must allocate the
//! account at exactly [`address_tree_account_size`] bytes before issuing
//! `create_address_tree`. No rollover is configured — shielded-pool trees
//! are immutable in terms of ownership after init.

use light_batched_merkle_tree::{
    initialize_address_tree::{
        init_batched_address_merkle_tree_account, InitAddressTreeAccountsInstructionData,
    },
    merkle_tree::get_merkle_tree_account_size,
};
use pinocchio::Address;

/// Tree height for shielded-pool address trees. Matches the upstream
/// `DEFAULT_BATCH_ADDRESS_TREE_HEIGHT`.
pub const ADDRESS_TREE_HEIGHT: u32 = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressTreeAccountError {
    BufferTooSmall,
    InitFailed,
}

/// Builds the `InitAddressTreeAccountsInstructionData` used by every shielded-
/// pool address tree. Rolls over and forester delegation are disabled.
pub fn address_tree_params() -> InitAddressTreeAccountsInstructionData {
    InitAddressTreeAccountsInstructionData {
        rollover_threshold: None,
        network_fee: None,
        forester: None,
        program_owner: None,
        ..Default::default()
    }
}

/// Bytes required for a shielded-pool address-tree account.
pub fn address_tree_account_size() -> usize {
    let p = address_tree_params();
    get_merkle_tree_account_size(
        p.input_queue_batch_size,
        p.bloom_filter_capacity,
        p.input_queue_zkp_batch_size,
        p.root_history_capacity,
        p.height,
    )
}

/// Initialize a freshly-allocated address-tree account in place.
pub fn init_address_tree_account(
    bytes: &mut [u8],
    owner: &Address,
    tree_pubkey: &Address,
) -> Result<(), AddressTreeAccountError> {
    if bytes.len() < address_tree_account_size() {
        return Err(AddressTreeAccountError::BufferTooSmall);
    }
    init_batched_address_merkle_tree_account(
        *owner,
        address_tree_params(),
        bytes,
        0, // merkle_tree_rent is only used to compute rollover_fee; we disable rollover.
        *tree_pubkey,
    )
    .map(|_| ())
    .map_err(|_| AddressTreeAccountError::InitFailed)
}
