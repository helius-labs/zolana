use crate::transaction::{transaction_size, ComputeBudgetConfig, TransactionSize};
use anyhow::{anyhow, bail, Result};
use solana_pubkey::Pubkey;
use spr_protocol_instructions::CloseNullifierPdas;
use spr_smart_account_client::{execute_sync_ix, smart_account_pda};
use spr_tree::TreeFeeSchedule;

/// One transaction base fee, the cost a forester carries for one batch append.
pub const BASE_TRANSACTION_FEE_LAMPORTS: u64 =
    spr_interface::state::AT_COST_APPEND_REIMBURSEMENT_LAMPORTS;

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

/// A schedule that charges `fee_per_tree` and reimburses foresters at cost:
/// one base fee per batch append, and one base fee spread over the closes that
/// fit in one transaction.
pub fn at_cost_for_transaction_size(
    fee_per_tree: u64,
    closes_per_transaction: u64,
) -> Result<TreeFeeSchedule> {
    if closes_per_transaction == 0 {
        bail!("closes per transaction must be positive");
    }
    Ok(TreeFeeSchedule {
        fee_per_tree,
        append_reimbursement: BASE_TRANSACTION_FEE_LAMPORTS,
        close_reimbursement: BASE_TRANSACTION_FEE_LAMPORTS.div_ceil(closes_per_transaction),
    })
}

pub fn print_schedule(closes_per_transaction: u64, fees: &TreeFeeSchedule) {
    println!("closes_per_transaction={closes_per_transaction}");
    println!("fee_per_tree={}", fees.fee_per_tree);
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
    fn schedule_is_at_cost() {
        for closes in [24, 57, 100] {
            let fees = at_cost_for_transaction_size(7, closes).unwrap();
            assert_eq!(
                fees,
                TreeFeeSchedule {
                    fee_per_tree: 7,
                    append_reimbursement: BASE_TRANSACTION_FEE_LAMPORTS,
                    close_reimbursement: BASE_TRANSACTION_FEE_LAMPORTS.div_ceil(closes),
                }
            );
        }
        assert!(at_cost_for_transaction_size(7, 0).is_err());
    }

    #[test]
    fn canonical_schedule_is_the_default() {
        let forester = forester();
        assert_eq!(forester.closes_per_transaction().unwrap(), 57);
        assert_eq!(
            at_cost_for_transaction_size(spr_interface::state::DEFAULT_FEE_PER_TREE_LAMPORTS, 57)
                .unwrap(),
            spr_interface::state::default_tree_fees()
        );
    }
}
