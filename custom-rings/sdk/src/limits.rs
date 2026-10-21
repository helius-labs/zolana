//! The outflow of one transfer per limit row, as the member policy key sums it.

use solana_address::Address;
use zolana_interface::N_PUBLIC_SLOTS;
use zolana_ring_policy::{Member, OutflowLimit};
use zolana_transaction::instructions::transact::SppProofOutputUtxo;

use crate::RingError;

pub(crate) struct Outflows<'a> {
    /// The sender's owner identity.
    pub sender: [u8; 32],
    pub ring: Address,
    pub outputs: &'a [SppProofOutputUtxo],
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    /// Signed nets, a withdrawal negative.
    pub public_amounts: &'a [i128; N_PUBLIC_SLOTS],
}

impl Outflows<'_> {
    /// Every UTXO output but the sender's change inside the ring, less the asset's public net.
    fn outflow(&self, asset: &[u8; 32]) -> Result<i128, RingError> {
        let mut others: i128 = 0;
        for output in self.outputs {
            let Some(owner) = output.owner_address.as_ref() else {
                continue;
            };
            let change = owner.signing_pubkey.owner_proof_input_hash()? == self.sender
                && output.ring_program_id == Some(self.ring);
            if !change && Member::asset(&output.asset.asset)?.as_bytes() == asset {
                others += i128::from(output.amount);
            }
        }
        let net: i128 = self
            .public_assets
            .iter()
            .zip(self.public_amounts)
            .filter(|(public, _)| *public == asset)
            .map(|(_, amount)| *amount)
            .sum();
        if net > others {
            return Err(RingError::DepositAboveOutflow { asset: *asset });
        }
        Ok(others - net)
    }

    /// Refuses an outflow above a nonzero cap, `true` past a nonzero co-sign bound.
    pub fn approval_required(&self, limits: &[OutflowLimit]) -> Result<bool, RingError> {
        let mut approval = false;
        for limit in limits {
            let outflow = self.outflow(&limit.asset)?;
            let over = |bound: u64| bound != 0 && outflow > i128::from(bound);
            if over(limit.cap) {
                return Err(RingError::OutflowCapExceeded {
                    asset: limit.asset,
                    cap: limit.cap,
                    outflow: u64::try_from(outflow).map_err(|_| RingError::OutflowOverflow)?,
                });
            }
            approval |= over(limit.cosign_above);
        }
        Ok(approval)
    }
}
