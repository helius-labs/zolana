//! Solana v1 transaction construction for this operator.
use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::{v1, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

pub const MAX_LOADED_ACCOUNTS_DATA_SIZE: u32 = 64 * 1024 * 1024;

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

/// Compile `instructions` into an unsigned v1 message.
///
/// v1 takes no compute-budget instructions, which is where the ceilings in
/// `compute_budget` would otherwise go, and it has no address lookup tables.
pub fn compile_message(
    payer: &Address,
    instructions: &[Instruction],
    recent_blockhash: Hash,
    compute_budget: ComputeBudgetConfig,
) -> Result<VersionedMessage> {
    v1::Message::try_compile_with_config(
        payer,
        instructions,
        recent_blockhash,
        compute_budget.transaction_config(),
    )
    .map(VersionedMessage::V1)
    .map_err(|error| anyhow!("compile transaction: {error}"))
}

pub(crate) fn ensure_version_1(message: &VersionedMessage) -> Result<()> {
    match message {
        VersionedMessage::V1(_) => Ok(()),
        VersionedMessage::Legacy(_) | VersionedMessage::V0(_) => {
            Err(anyhow!("only transaction version 1 is supported"))
        }
    }
}

/// Sign a compiled message, passing each signer once.
///
/// `VersionedTransaction::try_new` refuses a signer list longer than the
/// message's required signatures, where legacy partial signing tolerated a
/// repeat. A fee payer that also owns a shielded input is one account key but
/// two entries in the caller's list (payer and owner signer), so the
/// duplicates are dropped here rather than at every call site.
pub fn sign_transaction(
    message: VersionedMessage,
    signers: &[&dyn Signer],
) -> Result<VersionedTransaction> {
    ensure_version_1(&message)?;
    let mut unique: Vec<(Address, &dyn Signer)> = Vec::with_capacity(signers.len());
    for signer in signers {
        let pubkey = signer
            .try_pubkey()
            .map_err(|error| anyhow!("sign transaction: {error}"))?;
        if unique.iter().any(|(kept, _)| *kept == pubkey) {
            continue;
        }
        unique.push((pubkey, *signer));
    }
    let unique = unique
        .into_iter()
        .map(|(_, signer)| signer)
        .collect::<Vec<_>>();
    VersionedTransaction::try_new(message, &unique)
        .map_err(|error| anyhow!("sign transaction: {error}"))
}

/// The one-byte version prefix a v1 transaction carries ahead of its message.
const VERSION_PREFIX_LEN: usize = 1;
pub const SIGNATURE_LEN: usize = 64;

/// What a compiled transaction costs against each v1 ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionSize {
    pub bytes: usize,
    pub addresses: usize,
}

impl TransactionSize {
    /// Whether the transaction clears both ceilings. Neither alone is enough.
    pub fn fits(&self) -> bool {
        self.bytes <= v1::MAX_TRANSACTION_SIZE && self.addresses <= usize::from(v1::MAX_ADDRESSES)
    }
}

/// Measure `instructions` as the v1 transaction they would be sent as.
///
/// Includes the configured header fields and every signature required by the
/// compiled message. Use the same budget as the sender.
pub fn transaction_size(
    payer: &Address,
    instructions: &[Instruction],
    compute_budget: ComputeBudgetConfig,
) -> Result<TransactionSize> {
    let message = v1::Message::try_compile_with_config(
        payer,
        instructions,
        Hash::default(),
        compute_budget.transaction_config(),
    )
    .map_err(|error| anyhow!("compile transaction: {error}"))?;
    let signatures = usize::from(message.header.num_required_signatures);
    let bytes = signatures
        .checked_mul(SIGNATURE_LEN)
        .and_then(|signatures| signatures.checked_add(VERSION_PREFIX_LEN))
        .and_then(|overhead| overhead.checked_add(message.size()))
        .ok_or_else(|| anyhow!("transaction size overflow"))?;
    Ok(TransactionSize {
        bytes,
        addresses: message.account_keys.len(),
    })
}
