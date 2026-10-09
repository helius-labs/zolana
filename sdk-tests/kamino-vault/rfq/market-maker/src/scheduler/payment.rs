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
    pub own_splits: Vec<u64>,
    pub change: u64,
    pub shape: Shape,
}

impl TransferPlan {
    pub fn own_output_count(&self, own: &ShieldedAddress) -> usize {
        let paid_to_self = self
            .recipient
            .is_some_and(|(recipient, amount)| recipient == *own && amount > 0);
        self.own_splits.len() + usize::from(self.change > 0) + usize::from(paid_to_self)
    }

    fn new(
        selection: Selection,
        recipient: Option<(ShieldedAddress, u64)>,
        withdrawal: u64,
        own_value: u64,
        own_parts: usize,
    ) -> Result<Self, MakerError> {
        let (own_splits, change) = split(own_value, own_parts);
        let outputs = usize::from(recipient.is_some()) + own_splits.len() + usize::from(change > 0);
        let inputs = selection.inputs.len();
        let shape = smallest_shape(inputs, outputs)
            .ok_or(MakerError::NoSupportedShape { inputs, outputs })?;
        Ok(Self {
            selection,
            recipient,
            withdrawal,
            own_splits,
            change,
            shape,
        })
    }
}

fn own_value(selection: &Selection, spent: u64) -> Result<u64, MakerError> {
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
    change_outputs: usize,
) -> Result<TransferPlan, MakerError> {
    let change = own_value(&selection, amount)?;
    TransferPlan::new(
        selection,
        Some((recipient, amount)),
        0,
        change,
        change_outputs,
    )
}

pub fn plan_consolidate(
    selection: Selection,
    withdrawal: u64,
    parts: usize,
) -> Result<TransferPlan, MakerError> {
    let change = own_value(&selection, withdrawal)?;
    TransferPlan::new(selection, None, withdrawal, change, parts)
}

fn split(value: u64, parts: usize) -> (Vec<u64>, u64) {
    let Ok(count) = u64::try_from(parts) else {
        return (Vec::new(), value);
    };
    if value == 0 || count <= 1 || value / count == 0 {
        return (Vec::new(), value);
    }
    let part = value / count;
    (vec![part; parts - 1], value - part * (count - 1))
}
