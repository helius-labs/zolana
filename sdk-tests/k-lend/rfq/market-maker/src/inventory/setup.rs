use k_lend_rfq_sdk::pair::Pair;

use super::rebalance::{RebalanceKind, RebalanceOrder};
use crate::{
    api::{Inner, VaultOperation},
    error::MakerError,
    transactions::{
        kvault::read_vault,
        send::{SendOutcome, SendRequest},
        shield::{ShieldPlan, REBALANCE_COMPUTE_BUDGET},
    },
};

impl Inner {
    pub async fn seed_inventory(
        &self,
        pair: &Pair,
        deposit: u64,
        collateral: u64,
    ) -> Result<VaultOperation, MakerError> {
        if deposit == 0 && collateral == 0 {
            return Err(MakerError::AmountZero);
        }
        let before = read_vault(self.services.rpc.as_ref(), pair.vault).await?;
        let instructions = {
            let settings = self.settings();
            let reservations = &self.services.pending.reservations;
            let collateral_utxos: Vec<_> =
                ShieldPlan::new(&settings, reservations, &pair.token_mint)
                    .amounts(collateral)
                    .into_iter()
                    .map(|amount| (pair.token_mint, amount))
                    .collect();
            if deposit == 0 {
                vec![self.identity.shield(collateral_utxos)?]
            } else {
                let order = RebalanceOrder {
                    pair: *pair,
                    kind: RebalanceKind::Shares,
                    amount: deposit,
                };
                let shield = ShieldPlan::new(&settings, reservations, &order.shielded_asset());
                order
                    .tail(before, &self.identity, &shield, collateral_utxos)?
                    .instructions
            }
        };
        let request = SendRequest {
            instructions,
            compute_units: REBALANCE_COMPUTE_BUDGET.cu_limit,
        };
        let sender = &self.services.sender;
        sender.check_size(&request)?;
        let signature = match sender.send(&request).await {
            SendOutcome::Sent(sent) | SendOutcome::OutcomeUnknown { sent, .. } => sent.signature,
            SendOutcome::Rejected(error) | SendOutcome::NotSent(error) => return Err(error),
        };
        self.settled(pair, before, signature, 0).await
    }
}
