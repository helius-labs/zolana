use anyhow::{anyhow, bail, Result};
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;
use zolana_interface::instruction::CloseNullifierPdas;
use zolana_smart_account_client::{execute_sync_ix, smart_account_pda};
use zolana_tree::TreeFeeSchedule;

pub const BASE_TRANSACTION_FEE_LAMPORTS: u64 = 5_000;

/// Which transaction format the forester's close batches are budgeted against.
///
/// This must match `forester::close_nullifier_pdas::LEGACY_TRANSACTION_SIZE_LIMIT`:
/// the schedule divides one base fee across the closes that fit in a
/// transaction, so budgeting for v1 while the forester sends legacy would
/// under-reimburse it by about threefold. The forester is on legacy today, so
/// `V0` is the honest choice; move both together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionSize {
    V0,
    V1,
}

impl TransactionSize {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "v0" => Ok(Self::V0),
            "v1" => Ok(Self::V1),
            other => bail!("unknown transaction size {other:?} (expected v0|v1)"),
        }
    }

    pub const fn limit_bytes(self) -> usize {
        match self {
            Self::V0 => 1232,
            Self::V1 => 4096,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::V0 => "v0",
            Self::V1 => "v1",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ForesterClose {
    pub settings: Pubkey,
    pub member: Pubkey,
    pub tree: Pubkey,
}

impl ForesterClose {
    fn serialized_size(&self, nullifiers: &[[u8; 32]]) -> Result<usize> {
        let inner = CloseNullifierPdas {
            authority: smart_account_pda(&self.settings, 0).0,
            tree: self.tree,
            reimbursement_recipient: self.member,
            nullifiers: nullifiers.to_vec(),
        }
        .instruction();
        let outer = execute_sync_ix(&self.settings, 0, &[self.member], &[inner]);
        let transaction = Transaction::new_unsigned(Message::new(&[outer], Some(&self.member)));
        bincode::serialize(&transaction)
            .map(|bytes| bytes.len())
            .map_err(|e| anyhow!("serialize close-nullifier-pdas transaction: {e}"))
    }

    pub fn closes_per_transaction(&self, size: TransactionSize) -> Result<u64> {
        let mut nullifiers = Vec::new();
        for sequence in 0..=u64::from(u8::MAX) {
            let mut nullifier = [0u8; 32];
            nullifier[24..].copy_from_slice(&sequence.to_be_bytes());
            nullifiers.push(nullifier);
            if self.serialized_size(&nullifiers)? <= size.limit_bytes() {
                continue;
            }
            let capacity = nullifiers.len().saturating_sub(1);
            if capacity == 0 {
                bail!(
                    "a single nullifier PDA close does not fit in a {} transaction",
                    size.name()
                );
            }
            return Ok(capacity as u64);
        }
        bail!(
            "{} transaction size did not bound the nullifier PDA count",
            size.name()
        )
    }
}

pub fn at_cost_for_transaction_size(
    zkp_batch_size: u64,
    closes_per_transaction: u64,
) -> Result<TreeFeeSchedule> {
    if closes_per_transaction == 0 {
        bail!("closes per transaction must be positive");
    }
    let close_reimbursement = BASE_TRANSACTION_FEE_LAMPORTS.div_ceil(closes_per_transaction);
    TreeFeeSchedule::at_cost(
        zkp_batch_size,
        BASE_TRANSACTION_FEE_LAMPORTS,
        close_reimbursement,
    )
    .ok_or_else(|| anyhow!("fee schedule overflow for zkp_batch_size={zkp_batch_size}"))
}

pub fn print_schedule(size: TransactionSize, closes_per_transaction: u64, fees: &TreeFeeSchedule) {
    println!("transaction_size={}", size.name());
    println!("closes_per_transaction={closes_per_transaction}");
    println!("fee_per_nullifier={}", fees.fee_per_nullifier);
    println!("append_reimbursement={}", fees.append_reimbursement);
    println!("close_reimbursement={}", fees.close_reimbursement);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forester() -> ForesterClose {
        ForesterClose {
            settings: Pubkey::new_unique(),
            member: Pubkey::new_unique(),
            tree: Pubkey::new_unique(),
        }
    }

    #[test]
    fn capacity_is_the_last_count_that_fits() {
        let forester = forester();
        for size in [TransactionSize::V0, TransactionSize::V1] {
            let capacity = forester.closes_per_transaction(size).unwrap() as usize;
            let nullifiers: Vec<[u8; 32]> = (0..=capacity as u64)
                .map(|sequence| {
                    let mut nullifier = [0u8; 32];
                    nullifier[24..].copy_from_slice(&sequence.to_be_bytes());
                    nullifier
                })
                .collect();
            let fits = forester.serialized_size(&nullifiers[..capacity]).unwrap();
            let overflows = forester.serialized_size(&nullifiers).unwrap();
            assert!(fits <= size.limit_bytes());
            assert!(overflows > size.limit_bytes());
        }
    }

    #[test]
    fn larger_transactions_carry_more_closes_and_cost_less_per_close() {
        let forester = forester();
        let v0 = forester
            .closes_per_transaction(TransactionSize::V0)
            .unwrap();
        let v1 = forester
            .closes_per_transaction(TransactionSize::V1)
            .unwrap();
        assert!(v1 > 3 * v0);
        let fees_v0 = at_cost_for_transaction_size(250, v0).unwrap();
        let fees_v1 = at_cost_for_transaction_size(250, v1).unwrap();
        assert!(fees_v1.close_reimbursement < fees_v0.close_reimbursement);
        assert!(fees_v1.fee_per_nullifier < fees_v0.fee_per_nullifier);
    }

    #[test]
    fn schedule_is_solvent_and_at_cost() {
        for (zkp_batch_size, closes) in [(250, 24), (10, 24), (250, 100)] {
            let fees = at_cost_for_transaction_size(zkp_batch_size, closes).unwrap();
            assert_eq!(fees.append_reimbursement, BASE_TRANSACTION_FEE_LAMPORTS);
            assert_eq!(
                fees.close_reimbursement,
                BASE_TRANSACTION_FEE_LAMPORTS.div_ceil(closes)
            );
            let collected = fees.fee_per_nullifier * zkp_batch_size;
            let paid = fees.append_reimbursement + zkp_batch_size * fees.close_reimbursement;
            assert!(collected >= paid);
            assert!(collected - paid < zkp_batch_size);
        }
        assert!(at_cost_for_transaction_size(250, 0).is_err());
    }

    #[test]
    fn canonical_batch_size_schedules_are_pinned() {
        let forester = forester();
        for (size, closes, fee_per_nullifier, close_reimbursement) in [
            (TransactionSize::V0, 25, 220, 200),
            (TransactionSize::V1, 109, 66, 46),
        ] {
            assert_eq!(forester.closes_per_transaction(size).unwrap(), closes);
            assert_eq!(
                at_cost_for_transaction_size(250, closes).unwrap(),
                TreeFeeSchedule {
                    fee_per_nullifier,
                    append_reimbursement: BASE_TRANSACTION_FEE_LAMPORTS,
                    close_reimbursement,
                }
            );
        }
    }

    #[test]
    fn transaction_size_round_trips_through_parse() {
        for size in [TransactionSize::V0, TransactionSize::V1] {
            assert_eq!(TransactionSize::parse(size.name()).unwrap(), size);
        }
        assert!(TransactionSize::parse("legacy").is_err());
    }
}
