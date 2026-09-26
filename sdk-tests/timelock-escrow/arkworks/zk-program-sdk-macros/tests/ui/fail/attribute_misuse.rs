use zk_program_sdk::circuit;

#[circuit]
struct NotAnImplBlock;

#[circuit(strict)]
fn with_arguments() {}

fn main() {}
