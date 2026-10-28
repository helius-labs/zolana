#[derive(spr_program::ZkProgram)]
#[zk_program(prepare = "arbitrary()")]
struct Bad {
    private: u64,
    public: u64,
}
fn main() {}
