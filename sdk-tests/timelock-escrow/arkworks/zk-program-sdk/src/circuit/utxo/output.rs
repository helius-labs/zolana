use crate::circuit::{Asset, CircuitVar, Owner};

#[derive(Clone, Debug)]
pub(crate) struct Output {
    pub(crate) owner: Owner,
    pub(crate) asset: Asset,
    pub(crate) amount: CircuitVar,
    pub(crate) data_hash: CircuitVar,
    pub(crate) data: Option<Vec<u8>>,
}
