//! Shared shielded-pool workflow backends.
//!
//! Integration tests should build protocol state through this module instead
//! of defining per-binary environment structs. The LiteSVM backend owns the
//! authority and tree lifecycle and exposes the automatically journaled
//! [`ZolanaProgramTest`] transaction history.

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::state::read_tree_id;
use zolana_program_test::{ProgramTestError, ZolanaProgramTest};

pub struct LiteSvmPoolBackend {
    pub rpc: ZolanaProgramTest,
    pub authority: Keypair,
    pub tree: Pubkey,
    /// The raw id [`Self::tree`] was created with. UTXO commitments are hashed
    /// under the id of the tree they live in, so tests resolve it once here.
    pub tree_id: u16,
}

impl LiteSvmPoolBackend {
    pub fn new() -> Result<Self, ProgramTestError> {
        let mut rpc = ZolanaProgramTest::new()?;
        let authority = Keypair::new();
        rpc.create_protocol_config(&authority)?;
        let tree = rpc.create_tree(&authority)?;
        let tree_id = rpc
            .account_data(&tree)
            .as_deref()
            .and_then(read_tree_id)
            .ok_or_else(|| ProgramTestError::Rpc(format!("read tree id from {tree}")))?;
        Ok(Self {
            rpc,
            authority,
            tree,
            tree_id,
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
