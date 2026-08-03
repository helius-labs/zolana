//! Shared shielded-pool workflow backends.
//!
//! Integration tests should build protocol state through this module instead
//! of defining per-binary environment structs. The LiteSVM backend owns the
//! authority and tree lifecycle and exposes the automatically journaled
//! [`ZolanaProgramTest`] transaction history.

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
        let mut rpc = ZolanaProgramTest::new()?;
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
