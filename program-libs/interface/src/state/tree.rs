use zolana_tree::nullifier_tree::constants::NUM_BATCHES;
use zolana_tree::{NullifierTreeInitParams, TreeAccount, TreeFeeSchedule};

pub const STATE_HEIGHT: usize = 32;
/// Maximum number of updated Solana slots whose final state-tree roots can
/// coexist on chain. Slots without a tree update consume no history entry.
pub const STATE_ROOT_HISTORY_CAPACITY: usize = zolana_tree::smt::ROOT_HISTORY_CAPACITY;

// Production nullifier-tree parameters.
pub const NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE: u64 = 25_000;
pub const NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE: u64 = 250;
pub const NULLIFIER_TREE_HEIGHT: u32 = 40;
pub const NULLIFIER_TREE_ROOT_HISTORY_CAPACITY: u32 =
    (NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE / NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE) as u32;

pub const DEFAULT_APPEND_REIMBURSEMENT_LAMPORTS: u64 = 5_000;
pub const DEFAULT_CLOSE_REIMBURSEMENT_LAMPORTS: u64 = 170;

/// Fee schedule that exactly covers the default reimbursements for one zkp
/// batch. `None` when `zkp_batch_size` is zero or the schedule overflows.
pub fn default_tree_fees(zkp_batch_size: u64) -> Option<TreeFeeSchedule> {
    TreeFeeSchedule::at_cost(
        zkp_batch_size,
        DEFAULT_APPEND_REIMBURSEMENT_LAMPORTS,
        DEFAULT_CLOSE_REIMBURSEMENT_LAMPORTS,
    )
}

/// Nullifier-PDA rent needed while one reused batch overlaps the two preceding
/// PDA generations. Prompt cleanup keeps the maximum at `NUM_BATCHES + 1`
/// batches.
pub fn tree_working_capital_lamports(
    input_queue_batch_size: u64,
    nullifier_pda_rent: u64,
) -> Option<u64> {
    (NUM_BATCHES as u64)
        .checked_add(1)?
        .checked_mul(input_queue_batch_size)?
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
        nullifier_params.input_queue_batch_size,
        nullifier_pda_rent,
    )?)
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

/// Byte offset of the little-endian `u16` tree id within the account
/// (`TreeAccountLayout { discriminator: u8, state: u8, tree_id: u16, .. }`).
pub fn tree_id_offset() -> usize {
    TreeAccount::tree_id_offset()
}

/// The tree id stored in raw tree-account data, `None` when the data is too
/// short. Lets a client resolve the id a UTXO is hashed under without
/// deserializing the whole account.
pub fn read_tree_id(account_data: &[u8]) -> Option<u16> {
    let bytes =
        account_data.get(tree_id_offset()..tree_id_offset() + core::mem::size_of::<u16>())?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use solana_rent::Rent;

    use super::*;
    use crate::{tree_slot::tree_id_field, NULLIFIER_PDA_SIZE};

    #[test]
    fn default_tree_fees_are_exact_cost_for_the_supported_batch_sizes() {
        for (zkp_batch_size, fee_per_nullifier) in [
            (nullifier_tree_params().input_queue_zkp_batch_size, 190),
            (10, 670),
        ] {
            let fees = default_tree_fees(zkp_batch_size).expect("default tree fees");
            assert_eq!(
                fees.fee_per_nullifier * zkp_batch_size,
                fees.append_reimbursement + zkp_batch_size * fees.close_reimbursement
            );
            assert_eq!(fees.fee_per_nullifier, fee_per_nullifier);
        }
        assert_eq!(default_tree_fees(0), None);
    }

    #[test]
    fn working_capital_funds_three_batches_of_live_nullifier_pdas() {
        let nullifier_pda_rent = Rent::default().minimum_balance(NULLIFIER_PDA_SIZE);
        assert_eq!(nullifier_pda_rent, 960_480);

        let canonical = nullifier_tree_params().input_queue_batch_size;
        assert_eq!(
            tree_working_capital_lamports(canonical, nullifier_pda_rent),
            Some(3 * 25_000 * 960_480)
        );
        assert_eq!(
            tree_working_capital_lamports(canonical / 2, nullifier_pda_rent),
            Some(37_500 * 960_480)
        );
        assert_eq!(tree_working_capital_lamports(canonical, u64::MAX), None);
    }

    #[test]
    fn read_tree_id_reads_the_initialized_id_at_offset_two() {
        assert_eq!(tree_id_offset(), 2);
        let mut bytes = vec![0u8; tree_account_size()];
        // The `TreeAccount` borrows `bytes` mutably; read the id field off the
        // temporary so the borrow ends before the raw-byte reads below.
        let tree_id_array = TreeAccount::init(
            &mut bytes,
            1,
            STATE_HEIGHT as u8,
            [7u8; 32],
            0x1234,
            nullifier_tree_params(),
            default_tree_fees(NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE)
                .expect("default tree fees"),
        )
        .expect("init tree")
        .tree_id_array();
        // The tree crate cannot depend on the interface, so it spells out the
        // field encoding itself; both must agree byte for byte.
        assert_eq!(tree_id_array, tree_id_field(0x1234));
        assert_eq!(read_tree_id(&bytes), Some(0x1234));
        assert_eq!(bytes.get(2..4), Some(&0x1234u16.to_le_bytes()[..]));
        assert_eq!(read_tree_id(&bytes[..3]), None);
    }

    #[test]
    fn tree_creation_takes_four_allocation_steps() {
        assert_eq!(STATE_ROOT_HISTORY_CAPACITY, 500);
        assert_eq!(tree_account_size(), 39_952);
        assert_eq!(tree_creation_step_count(), 4);
        assert!(tree_account_size() > 3 * TREE_ALLOCATION_STEP);
        assert!(tree_account_size() <= 4 * TREE_ALLOCATION_STEP);
    }
}
