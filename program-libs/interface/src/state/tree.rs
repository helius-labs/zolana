use spr_tree::nullifier_tree::constants::NUM_BATCHES;
use spr_tree::{NullifierTreeInitParams, TreeAccount, TreeFeeSchedule};

pub const STATE_HEIGHT: usize = 32;
/// Maximum number of updated Solana slots whose final state-tree roots can
/// coexist on chain. Slots without a tree update consume no history entry.
pub const STATE_ROOT_HISTORY_CAPACITY: usize = spr_tree::smt::ROOT_HISTORY_CAPACITY;

// Production nullifier-tree parameters.
pub const NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE: u64 =
    spr_tree::nullifier_tree::constants::DEFAULT_NULLIFIER_BATCH_SIZE;
pub const NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE: u64 =
    spr_tree::nullifier_tree::constants::DEFAULT_NULLIFIER_ZKP_BATCH_SIZE;
pub const NULLIFIER_TREE_HEIGHT: u32 = 40;
pub const NULLIFIER_TREE_ROOT_HISTORY_CAPACITY: u32 =
    spr_tree::nullifier_tree::constants::NULLIFIER_TREE_ZKP_BATCHES as u32;

/// What one nullifier-tree batch append reimburses by default: nothing. The
/// protocol sponsors nullifier-tree maintenance.
pub const DEFAULT_APPEND_REIMBURSEMENT_LAMPORTS: u64 = 0;
/// What one nullifier-PDA close reimburses by default: nothing, for the same
/// reason as [`DEFAULT_APPEND_REIMBURSEMENT_LAMPORTS`].
pub const DEFAULT_CLOSE_REIMBURSEMENT_LAMPORTS: u64 = 0;

/// What one nullifier-tree batch append costs a forester: one transaction base
/// fee. `xtask set-tree-fees` spreads it over the zkp batch when it computes a
/// schedule that runs at cost.
pub const AT_COST_APPEND_REIMBURSEMENT_LAMPORTS: u64 = 5_000;

/// What one nullifier-PDA close costs a forester:
/// `ceil(AT_COST_APPEND_REIMBURSEMENT_LAMPORTS / closes_per_transaction)`. A
/// forester pays one base fee per transaction and closes as many PDAs as fit in
/// it, so the per-close figure only means anything against a transaction's
/// limits -- and the 64-address limit of a v1 transaction binds before its
/// 4,096 bytes do. 57 closes fit (`forester/tests/close_nullifier_pdas.rs` pins that),
/// which makes this 88, and the two together price a 4999-nullifier zkp batch at
/// 90 lamports per nullifier (`xtask::tree_fees` pins that).
///
/// `xtask set-tree-fees` measures `closes_per_transaction` from a real
/// transaction rather than reading this constant, so an operator's schedule
/// tracks the instruction it will actually send.
pub const AT_COST_CLOSE_REIMBURSEMENT_LAMPORTS: u64 = 88;

/// The sponsored fee schedule every tree is created with: a transaction pays
/// nothing per nullifier, so the fee balance stays empty and a forester claims
/// nothing back from the tree. `None` when `zkp_batch_size` is zero.
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
    tree_liquid_working_capital_lamports(input_queue_batch_size, 0, nullifier_pda_rent)
}

/// The part of the working capital that must stay liquid in the tree: rent at
/// the current rate for every nullifier PDA that may still be created while
/// `live_nullifier_pdas` are open. Rent held by open PDAs returns to the tree
/// on close, so it is not reserved twice.
pub fn tree_liquid_working_capital_lamports(
    input_queue_batch_size: u64,
    live_nullifier_pdas: u64,
    nullifier_pda_rent: u64,
) -> Option<u64> {
    (NUM_BATCHES as u64)
        .checked_add(1)?
        .checked_mul(input_queue_batch_size)?
        .saturating_sub(live_nullifier_pdas)
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

/// Total tree-account byte length. Delegates to the canonical `spr-tree`
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
