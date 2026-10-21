use zolana_program::ZkProgramCircuit;

#[derive(Clone, ZkProgramCircuit)]
struct MissingPublic {
    private: u64,
}

#[derive(Clone, ZkProgramCircuit)]
struct ExtraField {
    private: u64,
    public: u64,
    amount: u64,
}

fn main() {}
