use spr_program::{conversion::ProofInput, ZkProgramCircuit};

#[derive(Clone, ProofInput)]
struct Inputs {
    amount: u64,
}

fn require_program<P: ZkProgramCircuit>() {}

fn main() {
    require_program::<Inputs>();
}
