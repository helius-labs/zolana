use solana_message::v1;

use super::constants::MAX_LOADED_ACCOUNTS_DATA_SIZE;

/// What the runtime grants an instruction that asks for nothing, and the
/// ceiling it caps the whole transaction at. A legacy transaction carrying no
/// compute-budget instruction received `min(200_000 * instructions, 1_400_000)`
/// implicitly; a v1 header has to say so.
const DEFAULT_COMPUTE_UNITS_PER_INSTRUCTION: u32 = 200_000;
const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// Compute ceilings for a v1 transaction.
///
/// v1 carries them in the message header rather than in compute-budget
/// instructions, and reads an absent header field as zero rather than as a
/// default, so every ceiling is written explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComputeBudgetConfig {
    pub cu_limit: u32,
    /// Priority fee in lamports, the unit a v1 header charges for the whole
    /// transaction.
    pub priority_fee_lamports: Option<u64>,
}

impl ComputeBudgetConfig {
    pub const fn new(cu_limit: u32) -> Self {
        Self {
            cu_limit,
            priority_fee_lamports: None,
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
    pub const fn with_priority_fee(mut self, lamports: u64) -> Self {
        self.priority_fee_lamports = Some(lamports);
        self
    }

    pub fn transaction_config(&self) -> v1::TransactionConfig {
        let config = v1::TransactionConfig::empty()
            .with_compute_unit_limit(self.cu_limit)
            .with_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE);
        match self.priority_fee_lamports {
            Some(fee) => config.with_priority_fee(fee),
            None => config,
        }
    }
}
