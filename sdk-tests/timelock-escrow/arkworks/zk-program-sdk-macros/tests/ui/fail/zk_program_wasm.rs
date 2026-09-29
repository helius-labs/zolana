use zk_program_sdk_macros::ZkProgramWasm;

#[derive(ZkProgramWasm)]
struct Generic<T> {
    value: T,
}

#[derive(ZkProgramWasm)]
enum NotAStruct {
    Only,
}

fn main() {}
