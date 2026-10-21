//! The co-signer a ring operation must carry, one rule for the program and the SDKs.

use solana_address::Address;

use crate::{CoSignScope, CustomRingError, RingProgramConfig};

pub struct CoSignDemand<W> {
    /// Demands the co-signer whatever its scope.
    pub approval_required: bool,
    pub classes: CoSignScope,
    /// Public withdrawal total per mint.
    pub withdrawals: W,
}

impl<'a, W: IntoIterator<Item = (&'a Address, u128)>> CoSignDemand<W> {
    /// A shared class demands the co-signer, withdrawals only for a mint past or without its threshold.
    pub fn signer(self, config: &RingProgramConfig) -> Result<Option<Address>, CustomRingError> {
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
                && self.withdrawals.into_iter().any(|(mint, total)| {
                    config
                        .threshold(mint)
                        .is_none_or(|threshold| total > u128::from(threshold))
                }));
        Ok(in_scope.then_some(co_signer))
    }
}

impl RingProgramConfig {
    pub fn demanded_co_signer<'a>(
        &self,
        approval_required: bool,
        classes: CoSignScope,
        withdrawals: impl IntoIterator<Item = (&'a Address, u128)>,
    ) -> Result<Option<Address>, CustomRingError> {
        CoSignDemand {
            approval_required,
            classes,
            withdrawals,
        }
        .signer(self)
    }
}
