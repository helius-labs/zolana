use std::path::PathBuf;

use timelock_escrow_arkworks::{Escrow, Withdraw};
use zk_program_sdk::ZkProgram;

fn main() {
    let dir = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir).expect("output directory");
    for (name, r1cs) in [
        ("escrow.r1cs", Escrow::export_r1cs()),
        ("withdraw.r1cs", Withdraw::export_r1cs()),
    ] {
        let path = dir.join(name);
        std::fs::write(&path, r1cs.expect("r1cs export")).expect("r1cs file");
        println!("{}", path.display());
    }
}
