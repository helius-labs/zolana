use spr_program::circuit::Utxo;
use spr_program::{ArrayVec, ClientInputs, Field};

// Each of these would hand its items to the circuit without recording them.
#[derive(ClientInputs)]
pub struct Bad {
    pub nested: [[Utxo; 2]; 2],
    pub pair: (Utxo, u64),
    pub optional: Option<Utxo>,
    pub fields: ArrayVec<Field, 2>,
}

fn main() {}
