use zolana_client::Shape;
use zolana_keypair::ShieldedAddress;

use kamino_vault_rfq_sdk::budget::smallest_shape;

use super::Selection;
use crate::error::MakerError;

#[derive(Clone)]
pub struct TransferPlan {
    pub selection: Selection,
    pub recipient: Option<(ShieldedAddress, u64)>,
    pub withdrawal: u64,
    pub own_parts: Vec<u64>,
    pub shape: Shape,
}

impl TransferPlan {
    fn new(
        selection: Selection,
        recipient: Option<(ShieldedAddress, u64)>,
        withdrawal: u64,
        own_parts: Vec<u64>,
    ) -> Result<Self, MakerError> {
        let spent = recipient
            .map(|(_, amount)| amount)
            .unwrap_or(0)
            .saturating_add(withdrawal);
        let own_value = own_value(&selection, spent)?;
        let planned: u64 = own_parts.iter().sum();
        if planned != own_value {
            return Err(MakerError::OwnPartsMismatch { planned, own_value });
        }
        let outputs = usize::from(recipient.is_some()) + own_parts.len();
        let inputs = selection.inputs.len();
        let shape = smallest_shape(inputs, outputs)
            .ok_or(MakerError::NoSupportedShape { inputs, outputs })?;
        Ok(Self {
            selection,
            recipient,
            withdrawal,
            own_parts,
            shape,
        })
    }
}

pub fn own_value(selection: &Selection, spent: u64) -> Result<u64, MakerError> {
    selection
        .total
        .checked_sub(spent)
        .ok_or(MakerError::InsufficientBalance {
            asset: selection
                .inputs
                .first()
                .map(|input| input.utxo.asset())
                .unwrap_or_default(),
            available: selection.total,
            requested: spent,
        })
}

pub fn plan_payment(
    selection: Selection,
    recipient: ShieldedAddress,
    amount: u64,
    own_parts: Vec<u64>,
) -> Result<TransferPlan, MakerError> {
    TransferPlan::new(selection, Some((recipient, amount)), 0, own_parts)
}

pub fn plan_consolidate(
    selection: Selection,
    withdrawal: u64,
    own_parts: Vec<u64>,
) -> Result<TransferPlan, MakerError> {
    TransferPlan::new(selection, None, withdrawal, own_parts)
}
