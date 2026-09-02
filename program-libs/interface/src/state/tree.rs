use zolana_tree::nullifier_tree::constants::NUM_BATCHES;
use zolana_tree::{NullifierTreeInitParams, TreeAccount};

pub const STATE_HEIGHT: usize = 32;

// Production nullifier-tree parameters.
pub const NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE: u64 = 30_000;
pub const NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE: u64 = 250;
pub const NULLIFIER_TREE_HEIGHT: u32 = 40;
pub const NULLIFIER_TREE_ROOT_HISTORY_CAPACITY: u32 =
    (NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE / NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE) as u32;
/// Lamports reimbursed for each applied nullifier-tree ZKP batch.
pub const FORESTER_REIMBURSEMENT_LAMPORTS: u64 = 5_000;

/// Nullifier-PDA rent needed while one reused batch overlaps the two preceding
/// PDA generations. Prompt cleanup keeps the maximum at `NUM_BATCHES + 1`
/// batches.
pub fn tree_working_capital_lamports(
    nullifier_params: &NullifierTreeInitParams,
    nullifier_pda_rent: u64,
) -> Option<u64> {
    (NUM_BATCHES as u64)
        .checked_add(1)?
        .checked_mul(nullifier_params.input_queue_batch_size)?
        .checked_mul(nullifier_pda_rent)
}

/// Lamports a tree account must be created with: its own rent exemption plus
/// the working capital it needs to fund nullifier PDAs.
pub fn tree_creation_lamports(
    nullifier_params: &NullifierTreeInitParams,
    tree_rent: u64,
    nullifier_pda_rent: u64,
) -> Option<u64> {
    tree_rent.checked_add(tree_working_capital_lamports(
        nullifier_params,
        nullifier_pda_rent,
    )?)
}

/// Derive the fee charged for each element inserted into a tree's nullifier
/// queue. The standard tree configuration is pinned by the test below so the
/// division is exact.
pub fn forester_fee_per_queue_element(zkp_batch_size: u64) -> Option<u64> {
    FORESTER_REIMBURSEMENT_LAMPORTS.checked_div(zkp_batch_size)
}

/// Canonical nullifier-tree parameters for the shielded pool.
pub fn nullifier_tree_params() -> NullifierTreeInitParams {
    NullifierTreeInitParams {
        input_queue_batch_size: NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE,
        input_queue_zkp_batch_size: NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
        height: NULLIFIER_TREE_HEIGHT,
    }
}

/// Total tree-account byte length. Delegates to the canonical `zolana-tree`
/// layout so the account allocator and `TreeAccount::init` agree exactly.
pub fn tree_account_size() -> usize {
    TreeAccount::account_size()
}

pub const TREE_ALLOCATION_STEP: usize = 10 * 1024;

pub fn tree_creation_step_count() -> usize {
    tree_account_size().div_ceil(TREE_ALLOCATION_STEP)
}

/// Byte offset of the state (utxo) tree's current root within the account.
pub fn state_root_offset() -> usize {
    TreeAccount::state_root_offset()
}

#[cfg(test)]
mod tests {
    use solana_rent::Rent;

    use super::*;
    use crate::NULLIFIER_PDA_SIZE;

    #[test]
    fn standard_tree_forester_fee_exactly_funds_reimbursement() {
        let zkp_batch_size = nullifier_tree_params().input_queue_zkp_batch_size;

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
    fn working_capital_funds_three_batches_of_live_nullifier_pdas() {
        let nullifier_pda_rent = Rent::default().minimum_balance(NULLIFIER_PDA_SIZE);
        assert_eq!(nullifier_pda_rent, 960_480);

        let canonical = nullifier_tree_params();
        assert_eq!(
            tree_working_capital_lamports(&canonical, nullifier_pda_rent),
            Some(3 * 30_000 * 960_480)
        );

        let half = NullifierTreeInitParams {
            input_queue_batch_size: canonical.input_queue_batch_size / 2,
            ..canonical
        };
        assert_eq!(
            tree_working_capital_lamports(&half, nullifier_pda_rent),
            Some(45_000 * 960_480)
        );

        assert_eq!(tree_working_capital_lamports(&canonical, u64::MAX), None);
    }

    #[test]
    fn tree_creation_takes_four_allocation_steps() {
        assert_eq!(tree_account_size(), 34_856);
        assert_eq!(tree_creation_step_count(), 4);
        assert!(tree_account_size() > 3 * TREE_ALLOCATION_STEP);
        assert!(tree_account_size() <= 4 * TREE_ALLOCATION_STEP);
    }
}
