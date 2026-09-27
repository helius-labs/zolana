use crate::circuit::{Asset, CircuitVar, Owner, Uint};

#[derive(Clone, Debug)]
pub(crate) struct Output {
    pub(crate) owner: Owner,
    pub(crate) asset: Asset,
    pub(crate) amount: Uint<64>,
    pub(crate) data_hash: CircuitVar,
    pub(crate) data: Option<Vec<u8>>,
}
