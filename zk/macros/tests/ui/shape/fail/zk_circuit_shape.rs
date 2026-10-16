extern crate zolana_zk_dsl as zolana_program;

use zolana_program::ZkCircuit;

#[derive(Clone, ZkCircuit)]
struct MissingPublic {
    private: u64,
}

#[derive(Clone, ZkCircuit)]
struct ExtraField {
    private: u64,
    public: u64,
    amount: u64,
}

fn main() {}
