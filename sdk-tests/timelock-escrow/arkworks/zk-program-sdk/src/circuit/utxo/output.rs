use super::sol_asset;
use crate::{
    circuit::{zero, CircuitVar},
    RelationError,
};

#[derive(Clone, Debug)]
pub(crate) struct Output {
    pub(crate) owner: CircuitVar,
    pub(crate) asset: CircuitVar,
    pub(crate) amount: CircuitVar,
    pub(crate) data_hash: CircuitVar,
    pub(crate) data: Option<Vec<u8>>,
}

impl Output {
    pub(crate) fn padding(owner: &CircuitVar) -> Result<Self, RelationError> {
        Ok(Self {
            owner: owner.clone(),
            asset: sol_asset()?,
            amount: zero(),
            data_hash: zero(),
            data: None,
        })
    }
}

#[must_use]
#[derive(Clone, Debug)]
pub struct OutputTokenUtxo {
    pub(super) owner: CircuitVar,
    pub(super) asset: CircuitVar,
    pub(super) amount: CircuitVar,
}

impl OutputTokenUtxo {
    pub fn owner(&self) -> &CircuitVar {
        &self.owner
    }

    pub fn asset(&self) -> &CircuitVar {
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
