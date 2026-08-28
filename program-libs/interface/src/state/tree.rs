use solana_rent::{ACCOUNT_STORAGE_OVERHEAD, DEFAULT_LAMPORTS_PER_BYTE};
use zolana_batched_merkle_tree::nullifier_marker::NULLIFIER_MARKER_SIZE;
use zolana_tree::{InitAddressTreeAccountsInstructionData, TreeAccount};

pub const STATE_HEIGHT: usize = 32;

// Production batched-address-tree parameters.
pub const ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE: u64 = 30_000;
pub const ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE: u64 = 250;
pub const ADDRESS_TREE_HEIGHT: u32 = 40;
pub const ADDRESS_TREE_ROOT_HISTORY_CAPACITY: u32 = 120;
/// Lamports reimbursed for each applied nullifier-tree ZKP batch.
pub const FORESTER_REIMBURSEMENT_LAMPORTS: u64 = 5_000;
/// Default rent-exempt balance of one nullifier marker.
const NULLIFIER_MARKER_RENT_LAMPORTS: u64 =
    (ACCOUNT_STORAGE_OVERHEAD + NULLIFIER_MARKER_SIZE as u64) * DEFAULT_LAMPORTS_PER_BYTE;
/// Two full queue batches of recoverable nullifier-marker rent.
///
/// A batch cannot retire until its successor is at least half full. Funding a
/// full two-batch rotation keeps insertion live through that overlap and gives
/// the permissionless closer the remainder of the rotation to return rent.
pub const TREE_WORKING_CAPITAL_LAMPORTS: u64 =
    2 * ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE * NULLIFIER_MARKER_RENT_LAMPORTS;

/// Derive the fee charged for each element inserted into a tree's nullifier
/// queue. The standard tree configuration is pinned by the test below so the
/// division is exact.
pub fn forester_fee_per_queue_element(zkp_batch_size: u64) -> Option<u64> {
    FORESTER_REIMBURSEMENT_LAMPORTS.checked_div(zkp_batch_size)
}

/// Canonical nullifier (batched address) tree parameters for the shielded pool.
pub fn address_tree_params() -> InitAddressTreeAccountsInstructionData {
    InitAddressTreeAccountsInstructionData {
        input_queue_batch_size: ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
        input_queue_zkp_batch_size: ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
        height: ADDRESS_TREE_HEIGHT,
        root_history_capacity: ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
    }
}

/// Total tree-account byte length. Delegates to the canonical `zolana-tree`
/// layout so the account allocator and `TreeAccount::init` agree exactly.
pub fn tree_account_size() -> usize {
    TreeAccount::account_size()
}

/// Byte offset of the state (utxo) tree's current root within the account.
pub fn state_root_offset() -> usize {
    TreeAccount::state_root_offset()
}

#[cfg(test)]
mod tests {
    use solana_rent::Rent;

    use super::*;

    #[test]
    fn standard_tree_forester_fee_exactly_funds_reimbursement() {
        let zkp_batch_size = address_tree_params().input_queue_zkp_batch_size;

        assert_eq!(FORESTER_REIMBURSEMENT_LAMPORTS % zkp_batch_size, 0);
        let fee_per_element =
            forester_fee_per_queue_element(zkp_batch_size).expect("non-zero ZKP batch size");
        assert_eq!(fee_per_element, 20);
        assert_eq!(
            fee_per_element * zkp_batch_size,
            FORESTER_REIMBURSEMENT_LAMPORTS
        );
    }

    #[test]
    fn working_capital_funds_two_full_marker_batches() {
        let marker_rent = Rent::default().minimum_balance(NULLIFIER_MARKER_SIZE);
        assert_eq!(marker_rent, NULLIFIER_MARKER_RENT_LAMPORTS);
        assert_eq!(
            TREE_WORKING_CAPITAL_LAMPORTS,
            2 * ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE * marker_rent
        );
    }
}
