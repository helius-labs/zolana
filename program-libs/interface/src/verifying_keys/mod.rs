/// Default output directory used by `just xtask-create-verifying-keys`.
///
/// The current monorepo keeps prover-server verifying-key artifacts generated
/// from committed proving-system `.key` files instead of committing Rust VK
/// constants into the interface crate.
pub const DEFAULT_OUTPUT_DIR: &str = "target/verifying-keys";
