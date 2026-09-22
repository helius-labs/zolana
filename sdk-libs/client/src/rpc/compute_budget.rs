use solana_message::v1;

use super::constants::MAX_LOADED_ACCOUNTS_DATA_SIZE;

/// What the runtime grants an instruction that asks for nothing, and the
/// ceiling it caps the whole transaction at. A legacy transaction carrying no
/// compute-budget instruction received `min(200_000 * instructions, 1_400_000)`
/// implicitly; a v1 header has to say so.
const DEFAULT_COMPUTE_UNITS_PER_INSTRUCTION: u32 = 200_000;
const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

const MICRO_LAMPORTS_PER_LAMPORT: u128 = 1_000_000;

/// Compute ceilings for a v1 transaction.
///
/// v1 carries them in the message header rather than in compute-budget
/// instructions, and reads an absent header field as zero rather than as a
/// default, so every ceiling is written explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComputeBudgetConfig {
    pub cu_limit: u32,
    /// Priority bid in micro-lamports per compute unit, the unit
    /// `ComputeBudgetInstruction::set_compute_unit_price` took.
    pub cu_price_micro_lamports: Option<u64>,
}

impl ComputeBudgetConfig {
    pub const fn new(cu_limit: u32) -> Self {
        Self {
            cu_limit,
            cu_price_micro_lamports: None,
        }
    }

    /// The budget a legacy transaction of `instructions` instructions received
    /// without asking.
    ///
    /// A v1 header must state a ceiling, so every caller that previously sent
    /// no compute-budget instruction needs one written for it. Reproducing the
    /// runtime's own implicit rule keeps those callers on exactly the budget
    /// they already had rather than inventing a number per call site.
    pub const fn for_instruction_count(instructions: usize) -> Self {
        let requested = DEFAULT_COMPUTE_UNITS_PER_INSTRUCTION.saturating_mul(
            if instructions > u32::MAX as usize {
                u32::MAX
            } else {
                instructions as u32
            },
        );
        let cu_limit = if requested > MAX_COMPUTE_UNIT_LIMIT {
            MAX_COMPUTE_UNIT_LIMIT
        } else {
            requested
        };
        Self::new(cu_limit)
    }

    #[must_use]
    pub const fn with_compute_unit_price(mut self, micro_lamports: u64) -> Self {
        self.cu_price_micro_lamports = Some(micro_lamports);
        self
    }

    pub fn transaction_config(&self) -> v1::TransactionConfig {
        let config = v1::TransactionConfig::empty()
            .with_compute_unit_limit(self.cu_limit)
            .with_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE);
        match self.cu_price_micro_lamports {
            Some(price) => config.with_priority_fee(priority_fee_lamports(price, self.cu_limit)),
            None => config,
        }
    }
}

/// The lamport priority fee a compute-unit price buys.
///
/// Both formats charge the same thing in different units: the runtime turned a
/// legacy `set_compute_unit_price` bid into `ceil(price * cu_limit / 1_000_000)`
/// lamports (`solana_compute_budget::compute_budget_limits::get_prioritization_fee`)
/// and charges a v1 header's `priority_fee` as lamports directly, so converting
/// with that same formula bills a caller exactly what the instruction did.
fn priority_fee_lamports(cu_price_micro_lamports: u64, cu_limit: u32) -> u64 {
    u128::from(cu_price_micro_lamports)
        .saturating_mul(u128::from(cu_limit))
        .saturating_add(MICRO_LAMPORTS_PER_LAMPORT.saturating_sub(1))
        .checked_div(MICRO_LAMPORTS_PER_LAMPORT)
        .and_then(|fee| u64::try_from(fee).ok())
        .unwrap_or(u64::MAX)
}
