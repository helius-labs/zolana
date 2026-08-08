//! Shared shielded-pool workflow backends.

use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_interface::state::tree_account_size;
use zolana_program_test::{ProgramTestError, ZolanaProgramTest};

pub struct LiteSvmPoolBackend {
    pub rpc: ZolanaProgramTest,
    pub authority: Keypair,
    pub tree: Keypair,
}

impl LiteSvmPoolBackend {
    pub fn new() -> Result<Self, ProgramTestError> {
        Self::with_rpc(ZolanaProgramTest::new()?)
    }

    /// Boot the pool state over a caller-prepared runtime, for harnesses
    /// that load a non-default program build or custom syscalls.
    pub fn with_rpc(mut rpc: ZolanaProgramTest) -> Result<Self, ProgramTestError> {
        let authority = Keypair::new();
        rpc.create_protocol_config(&authority)?;
        let tree = rpc.create_tree(tree_account_size() as u64, &authority)?;
        Ok(Self {
            rpc,
            authority,
            tree,
        })
    }

    /// Constructor for test fixtures whose setup failure should abort
    /// immediately with the standard SBF build hint.
    pub fn initialized() -> Self {
        Self::new().expect(
            "boot shielded-pool backend; run `cargo build-sbf -p shielded-pool-program` first",
        )
    }

    pub fn funded_signer(&mut self, lamports: u64) -> Keypair {
        let signer = Keypair::new();
        self.rpc
            .airdrop(&signer.pubkey(), lamports)
            .expect("fund workflow signer");
        signer
    }
}
