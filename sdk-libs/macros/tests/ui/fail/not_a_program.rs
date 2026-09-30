use zolana_program::{conversion::ProofInput, ZkProgram};

#[derive(Clone, ProofInput)]
struct Inputs {
    amount: u64,
}

fn require_program<P: ZkProgram>() {}

fn main() {
    require_program::<Inputs>();
}
