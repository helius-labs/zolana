//! Transaction diagnostics captured by [`crate::ZolanaProgramTest`].
//!
//! Every submission records the complete set of message accounts before and
//! after execution, the instruction layout, logs, compute units, and the typed
//! outcome.  Tests can therefore explain a failure without first reproducing
//! it with ad-hoc account logging, and can assert rollback from the same data
//! that was captured before the transaction ran.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction_error::TransactionError;

/// Compact, content-addressed account state. Keeping digests instead of raw
/// tree bytes makes an unbounded transaction journal practical even when every
/// operation touches a megabyte-sized tree account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountSnapshot {
    pub lamports: u64,
    pub owner: Pubkey,
    pub executable: bool,
    pub rent_epoch: u64,
    pub data_len: usize,
    pub data_sha256: [u8; 32],
}

impl AccountSnapshot {
    pub(crate) fn from_account(account: Account) -> Self {
        let data_len = account.data.len();
        let data_sha256 = Sha256::digest(&account.data).into();
        Self {
            lamports: account.lamports,
            owner: account.owner,
            executable: account.executable,
            rent_epoch: account.rent_epoch,
            data_len,
            data_sha256,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountTransition {
    pub address: Pubkey,
    pub before: Option<AccountSnapshot>,
    pub after: Option<AccountSnapshot>,
}

impl AccountTransition {
    pub fn changed(&self) -> bool {
        self.before != self.after
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstructionTrace {
    pub program_id: Pubkey,
    pub accounts: Vec<Pubkey>,
    pub data_len: usize,
    /// The first eight instruction-data bytes, sufficient to identify every
    /// current shielded-pool discriminator without retaining another copy of
    /// the full transaction payload.
    pub discriminator: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionOutcome {
    Succeeded,
    Failed(TransactionError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionTrace {
    pub signature: Signature,
    pub instructions: Vec<InstructionTrace>,
    pub accounts: Vec<AccountTransition>,
    pub logs: Vec<String>,
    pub compute_units_consumed: u64,
    pub outcome: TransactionOutcome,
}

impl TransactionTrace {
    pub fn changed_accounts(&self) -> impl Iterator<Item = &AccountTransition> {
        self.accounts.iter().filter(|account| account.changed())
    }

    /// Assert that the journaled snapshots of a rejected transaction show no
    /// message account changed. The runtime itself guarantees rollback; this
    /// catches journal drift and unexpected writes adjacent to the fee payer,
    /// which is intentionally excluded because a failed Solana transaction may
    /// still charge a fee.
    #[track_caller]
    pub fn assert_rolled_back_except(&self, allowed: &[Pubkey]) {
        let allowed: BTreeSet<Pubkey> = allowed.iter().copied().collect();
        let changed: Vec<Pubkey> = self
            .changed_accounts()
            .filter(|account| !allowed.contains(&account.address))
            .map(|account| account.address)
            .collect();
        assert!(
            changed.is_empty(),
            "transaction changed accounts that should have rolled back: {changed:?}\n{}",
            self.diagnostic()
        );
    }

    pub fn diagnostic(&self) -> String {
        let instructions = self
            .instructions
            .iter()
            .enumerate()
            .map(|(index, ix)| {
                format!(
                    "  {index}: program={} discriminator={:02x?} data_len={} accounts={}",
                    ix.program_id,
                    ix.discriminator,
                    ix.data_len,
                    ix.accounts.len()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let changed = self
            .changed_accounts()
            .map(|account| format!("  {}", account.address))
            .collect::<Vec<_>>()
            .join("\n");
        let logs = self
            .logs
            .iter()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "signature={} outcome={:?} compute_units={}\ninstructions:\n{}\nchanged accounts:\n{}\nlogs:\n{}",
            self.signature,
            self.outcome,
            self.compute_units_consumed,
            instructions,
            changed,
            logs
        )
    }
}
