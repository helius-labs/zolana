//! Shielded-pool BDD tests over the LiteSVM program-test harness.

mod common;
mod steps;

use cucumber::World;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use zolana_program_test::{DepositOutput, ProgramTestError, ZolanaProgramTest};
use zolana_transaction::Wallet;

#[derive(Default, World)]
pub struct ShieldedPoolWorld {
    rpc: Option<ZolanaProgramTest>,
    authority: Option<Keypair>,
    tree: Option<Keypair>,
    depositor: Option<Keypair>,
    recipient: Option<Wallet>,
    mint: Option<Pubkey>,
    user_token: Option<Pubkey>,
    protocol_config: Option<Pubkey>,
    prefunded_protocol_config: Option<Pubkey>,
    spl_registry: Option<Pubkey>,
    spl_vault: Option<Pubkey>,
    zone_config: Option<Pubkey>,
    zone_authority: Option<Keypair>,
    previous_zone_authority: Option<Keypair>,
    rotated_authority: Option<Keypair>,
    last_proofless_view: Option<DepositOutput>,
    last_error: Option<ProgramTestError>,
    sol_deposit: Option<SolDepositObservation>,
    indexed_utxo_count_before: Option<usize>,
    state_roots: Vec<[u8; 32]>,
}

struct SolDepositObservation {
    amount: u64,
    vault_before_lamports: u64,
    vault_after_lamports: u64,
    tree_changed: bool,
}

impl std::fmt::Debug for ShieldedPoolWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShieldedPoolWorld")
    }
}

impl ShieldedPoolWorld {
    pub fn rpc(&mut self) -> &mut ZolanaProgramTest {
        self.rpc.as_mut().expect("pool booted")
    }

    pub fn rpc_ref(&self) -> &ZolanaProgramTest {
        self.rpc.as_ref().expect("pool booted")
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
    ShieldedPoolWorld::cucumber()
        .fail_on_skipped()
        .run_and_exit("tests/features")
        .await;
}
