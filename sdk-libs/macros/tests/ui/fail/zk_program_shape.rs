use zolana_program::ZkProgram;

#[derive(Clone, ZkProgram)]
struct MissingPublic {
    private: u64,
}

#[derive(Clone, ZkProgram)]
struct ExtraField {
    private: u64,
    public: u64,
    amount: u64,
}

fn main() {}
