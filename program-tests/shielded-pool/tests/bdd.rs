//! Cucumber/Gherkin BDD suite for the shielded-pool litesvm program tests.
//!
//! Mirrors the SDK BDD harness (`sdk-libs/transaction/tests/bdd.rs`): a single
//! `World` carries the booted litesvm rig and the per-scenario fixtures, step
//! definitions live under `tests/steps`, and the features live under
//! `tests/features`.
//!
//! Requires `cargo build-sbf -p shielded-pool-program` (and, for the zone
//! scenarios, `-p zone-test-program`) to have produced the `.so` binaries.

mod common;
mod steps;

use cucumber::World;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use zolana_interface::event::ProoflessShieldEvent;
use zolana_program_test::{ProgramTestError, ZolanaProgramTest};
use zolana_transaction::Wallet;

#[derive(Default, World)]
pub struct PoolWorld {
    rig: Option<ZolanaProgramTest>,
    authority: Option<Keypair>,
    tree: Option<Keypair>,
    depositor: Option<Keypair>,
    recipient: Option<Wallet>,
    mint: Option<Pubkey>,
    user_token: Option<Pubkey>,
    registry: Option<Pubkey>,
    vault: Option<Pubkey>,
    zone_config: Option<Pubkey>,
    zone_authority: Option<Keypair>,
    last_event: Option<ProoflessShieldEvent>,
    last_error: Option<ProgramTestError>,
    root_before: Option<[u8; 32]>,
    indexed_before: Option<usize>,
    indexed_roots: Vec<[u8; 32]>,
    zone_program_loaded: bool,
}

impl std::fmt::Debug for PoolWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PoolWorld")
    }
}

impl PoolWorld {
    pub fn rig(&mut self) -> &mut ZolanaProgramTest {
        self.rig.as_mut().expect("pool booted")
    }

    pub fn authority(&self) -> &Keypair {
        self.authority.as_ref().expect("protocol authority set")
    }

    pub fn tree(&self) -> &Keypair {
        self.tree.as_ref().expect("tree created")
    }

    pub fn depositor(&self) -> &Keypair {
        self.depositor.as_ref().expect("depositor funded")
    }

    pub fn recipient(&mut self) -> &mut Wallet {
        self.recipient.as_mut().expect("recipient wallet set")
    }

    pub fn mint(&self) -> Pubkey {
        self.mint.expect("mint created")
    }

    pub fn user_token(&self) -> Pubkey {
        self.user_token.expect("user token account created")
    }

    pub fn last_error(&mut self) -> ProgramTestError {
        self.last_error
            .take()
            .expect("an operation must have failed")
    }
}

#[tokio::main]
async fn main() {
    PoolWorld::cucumber()
        .fail_on_skipped()
        .run_and_exit("tests/features")
        .await;
}
