//! The co-signer a ring operation must carry, one rule for the program and the SDKs.

use solana_address::Address;
use zolana_interface::{instruction::instruction_data::PublicLeg, SOL_ASSET_ADDRESS};

use crate::{CoSignScope, CustomRingError, RingProgramConfig};

pub struct CoSignDemand {
    /// Demands the co-signer whatever its scope.
    pub approval_required: bool,
    pub classes: CoSignScope,
    /// Public withdrawal total per mint, each mint once.
    pub withdrawals: Vec<(Address, u128)>,
}

impl CoSignDemand {
    /// A transact is a transfer, each public leg adds its class and its withdrawal.
    pub fn transact(approval_required: bool, legs: &[PublicLeg]) -> Self {
        let mut classes = CoSignScope::TRANSFERS;
        let mut withdrawals: Vec<(Address, u128)> = Vec::new();
        for leg in legs {
            if leg.transfer.is_deposit() {
                classes = classes | CoSignScope::DEPOSITS;
                continue;
            }
            classes = classes | CoSignScope::WITHDRAWALS;
            let mint = Address::new_from_array(leg.mint.unwrap_or(SOL_ASSET_ADDRESS));
            let amount = u128::from(leg.transfer.amount());
            // A u128 sum of u64 legs never overflows.
            match withdrawals.iter_mut().find(|(seen, _)| *seen == mint) {
                Some((_, total)) => *total += amount,
                None => withdrawals.push((mint, amount)),
            }
        }
        Self {
            approval_required,
            classes,
            withdrawals,
        }
    }

    /// A shared class demands the co-signer, withdrawals only for a mint past or without its threshold.
    pub fn signer(&self, config: &RingProgramConfig) -> Result<Option<Address>, CustomRingError> {
        let co_signer = config.co_signer().copied();
        if self.approval_required {
            return co_signer
                .map(Some)
                .ok_or(CustomRingError::ApprovalWithoutCoSigner);
        }
        let (Some(co_signer), Some(scope)) = (co_signer, config.co_sign_scope()) else {
            return Ok(None);
        };
        let shared = |class| scope.contains(class) && self.classes.contains(class);
        let in_scope = shared(CoSignScope::TRANSFERS)
            || shared(CoSignScope::DEPOSITS)
            || (shared(CoSignScope::WITHDRAWALS)
                && self.withdrawals.iter().any(|(mint, total)| {
                    config
                        .threshold(mint)
                        .is_none_or(|threshold| *total > u128::from(threshold))
                }));
        Ok(in_scope.then_some(co_signer))
    }
}
