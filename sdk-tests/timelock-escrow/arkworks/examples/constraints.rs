#[path = "../tests/programs/mod.rs"]
mod programs;
#[path = "../tests/shared/mod.rs"]
mod shared;

use zk_program_sdk::ZkProgram;

fn main() {
    println!(
        "escrow: {} constraints",
        programs::escrow()
            .check_constraints()
            .expect("escrow constraints")
    );
    println!(
        "withdraw: {} constraints",
        programs::withdraw()
            .check_constraints()
            .expect("withdraw constraints")
    );
}
