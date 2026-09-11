use anyhow::{anyhow, bail, Result};
use solana_pubkey::Pubkey;
use zolana_client::{transaction_size, ComputeBudgetConfig, TransactionSize};
use zolana_interface::instruction::CloseNullifierPdas;
use zolana_smart_account_client::{execute_sync_ix, smart_account_pda};
use zolana_tree::TreeFeeSchedule;

pub const BASE_TRANSACTION_FEE_LAMPORTS: u64 = 5_000;

#[derive(Clone, Copy, Debug)]
pub struct ForesterClose {
    pub settings: Pubkey,
    pub member: Pubkey,
    pub tree: Pubkey,
}

impl ForesterClose {
    fn size(&self, nullifiers: &[[u8; 32]]) -> Result<TransactionSize> {
        let inner = CloseNullifierPdas {
            authority: smart_account_pda(&self.settings, 0).0,
            tree: self.tree,
            reimbursement_recipient: self.member,
            nullifiers: nullifiers.to_vec(),
        }
        .instruction();
        let outer = execute_sync_ix(&self.settings, 0, &[self.member], &[inner]);
        transaction_size(
            &self.member,
            &[outer],
            ComputeBudgetConfig::for_instruction_count(1),
        )
        .map_err(|e| anyhow!("measure close-nullifier-pdas transaction: {e}"))
    }

    pub fn closes_per_transaction(&self) -> Result<u64> {
        let mut nullifiers = Vec::new();
        for sequence in 0..=u64::from(u8::MAX) {
            let mut nullifier = [0u8; 32];
            nullifier[24..].copy_from_slice(&sequence.to_be_bytes());
            nullifiers.push(nullifier);
            if self.size(&nullifiers)?.fits() {
                continue;
            }
            let capacity = nullifiers.len().saturating_sub(1);
            if capacity == 0 {
                bail!("a single nullifier PDA close does not fit in a transaction");
            }
            return Ok(capacity as u64);
        }
        bail!("the transaction size did not bound the nullifier PDA count")
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

pub fn print_schedule(closes_per_transaction: u64, fees: &TreeFeeSchedule) {
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
        let capacity = forester.closes_per_transaction().unwrap() as usize;
        let nullifiers: Vec<[u8; 32]> = (0..=capacity as u64)
            .map(|sequence| {
                let mut nullifier = [0u8; 32];
                nullifier[24..].copy_from_slice(&sequence.to_be_bytes());
                nullifier
            })
            .collect();
        let fits = forester.size(nullifiers.get(..capacity).unwrap()).unwrap();
        let overflows = forester.size(&nullifiers).unwrap();
        assert!(fits.fits());
        assert!(!overflows.fits());
        assert_eq!(
            fits.addresses,
            usize::from(solana_message::v1::MAX_ADDRESSES)
        );
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
        assert_eq!(forester.closes_per_transaction().unwrap(), 57);
        assert_eq!(
            at_cost_for_transaction_size(250, 57).unwrap(),
            TreeFeeSchedule {
                fee_per_nullifier: 108,
                append_reimbursement: BASE_TRANSACTION_FEE_LAMPORTS,
                close_reimbursement: 88,
            }
        );
    }
}
