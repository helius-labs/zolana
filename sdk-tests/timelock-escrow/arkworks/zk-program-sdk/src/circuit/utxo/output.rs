use crate::circuit::{zero, Asset, CircuitVar, Owner};

#[derive(Clone, Debug)]
pub(crate) struct Output {
    pub(crate) owner: Owner,
    pub(crate) asset: Asset,
    pub(crate) amount: CircuitVar,
    pub(crate) data_hash: CircuitVar,
    pub(crate) data: Option<Vec<u8>>,
}

#[must_use]
#[derive(Clone, Debug)]
pub struct OutputTokenUtxo {
    pub(super) owner: Owner,
    pub(super) asset: Asset,
    pub(super) amount: CircuitVar,
}

impl OutputTokenUtxo {
    pub fn owner(&self) -> &Owner {
        &self.owner
    }

    pub fn asset(&self) -> &Asset {
        &self.asset
    }

    pub fn amount(&self) -> &CircuitVar {
        &self.amount
    }
}

impl From<OutputTokenUtxo> for Output {
    fn from(output: OutputTokenUtxo) -> Self {
        Self {
            owner: output.owner,
            asset: output.asset,
            amount: output.amount,
            data_hash: zero(),
            data: None,
        }
    }
}
