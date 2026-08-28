use zolana_batched_merkle_tree::constants::NUM_BATCHES;
use zolana_tree::{InitAddressTreeAccountsInstructionData, TreeAccount};

pub const STATE_HEIGHT: usize = 32;

// Production batched-address-tree parameters.
pub const ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE: u64 = 30_000;
pub const ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE: u64 = 250;
pub const ADDRESS_TREE_HEIGHT: u32 = 40;
pub const ADDRESS_TREE_ROOT_HISTORY_CAPACITY: u32 =
    (ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE / ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE) as u32;
/// Lamports reimbursed for each applied nullifier-tree ZKP batch.
pub const FORESTER_REIMBURSEMENT_LAMPORTS: u64 = 5_000;

/// Marker rent needed while one reused batch overlaps the two preceding marker
/// generations. Prompt cleanup keeps the maximum at `NUM_BATCHES + 1` batches.
pub fn tree_working_capital_lamports(
    nullifier_params: &InitAddressTreeAccountsInstructionData,
    marker_rent: u64,
) -> Option<u64> {
    (NUM_BATCHES as u64)
        .checked_add(1)?
        .checked_mul(nullifier_params.input_queue_batch_size)?
        .checked_mul(marker_rent)
}

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
    use crate::NULLIFIER_MARKER_SIZE;

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
    fn working_capital_funds_three_batches_of_live_markers() {
        let marker_rent = Rent::default().minimum_balance(NULLIFIER_MARKER_SIZE);
        assert_eq!(marker_rent, 953_520);

        let canonical = address_tree_params();
        assert_eq!(
            tree_working_capital_lamports(&canonical, marker_rent),
            Some(3 * 30_000 * 953_520)
        );

        let half = InitAddressTreeAccountsInstructionData {
            input_queue_batch_size: canonical.input_queue_batch_size / 2,
            ..canonical
        };
        assert_eq!(
            tree_working_capital_lamports(&half, marker_rent),
            Some(45_000 * 953_520)
        );

        assert_eq!(tree_working_capital_lamports(&canonical, u64::MAX), None);
    }
}
