//! Shared proof-backed environment and tree inspection helpers for
//! shielded-pool `transact` tests.

use pinocchio::AccountView;
use solana_account::Account;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_account_checks::account_info::test_account_info::get_account_view;
use zolana_interface::{
    state::{discriminator::RING_CONFIG, RingConfig},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program_test::{ZolanaProgramTest, RING_TEST_PROGRAM_ID};
use zolana_test_utils::prover::spawn_workspace_prover;
use zolana_tree::TreeAccount;

pub use super::fixtures::Pool;

/// Start the workspace prover and return an initialized pool backend.
pub fn proof_env() -> Pool {
    spawn_workspace_prover(zolana_client::IndexerRequirement::Optional);
    Pool::initialized()
}

/// Read the on-chain roots used by a `transact` input.
pub fn tree_roots(rpc: &ZolanaProgramTest, tree: &Pubkey, utxo_index: u16) -> ([u8; 32], [u8; 32]) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.get_utxo_tree_root(utxo_index).expect("utxo root"),
        account.get_nullifier_tree_root(0).expect("nullifier root"),
    )
}

/// Read the latest on-chain UTXO root, its current dense history index, and the
/// current nullifier root used by a `transact` input.
pub fn current_tree_roots(rpc: &ZolanaProgramTest, tree: &Pubkey) -> (u16, [u8; 32], [u8; 32]) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    let utxo_index = account.utxo_tree().current_root_index();
    (
        utxo_index,
        account.get_utxo_tree_root(utxo_index).expect("utxo root"),
        account.get_nullifier_tree_root(0).expect("nullifier root"),
    )
}

/// Read the two counters advanced by a successful `transact`.
pub fn tree_progress(rpc: &ZolanaProgramTest, tree: &Pubkey) -> (u64, u64) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.utxo_tree().next_index(),
        account.nullifier_tree().queue_next_index,
    )
}

/// Write caller-constructed ring-config bytes at an arbitrary address.
///
/// Callers retain control over the payload and owner so malformed-account
/// tests keep their defect visible at the call site.
pub fn write_ring_config_account(
    rpc: &mut ZolanaProgramTest,
    address: Pubkey,
    owner: Pubkey,
    data: Vec<u8>,
) {
    rpc.svm
        .set_account(
            address,
            Account {
                lamports: 1_000_000_000,
                data,
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("write fabricated ring config");
}

/// Materialize a `RingConfig` at a fresh keypair address so tests can
/// produce the signature the ring rails require without the ring program's
/// `invoke_signed`. The operational loader validates owner, size,
/// discriminator, and active state (the `ring_auth` derivation is bound once,
/// at creation), so a signing keypair account stands in for the canonical PDA.
pub fn write_ring_config(
    env: &mut Pool,
    owner: Pubkey,
    discriminator: u8,
    enabled: bool,
    paused: bool,
) -> Keypair {
    let config = RingConfig {
        discriminator,
        ring_authority_transact_is_enabled: u8::from(enabled),
        paused: u8::from(paused),
        ..TEST_RING_CONFIG
    };
    let keypair = Keypair::new();
    write_ring_config_account(
        &mut env.rpc,
        keypair.pubkey(),
        owner,
        bytemuck::bytes_of(&config).to_vec(),
    );
    keypair
}

/// Active, enabled and bound to the test ring program.
pub const TEST_RING_CONFIG: RingConfig = RingConfig {
    discriminator: RING_CONFIG,
    authority: Address::new_from_array([9u8; 32]),
    program_id: Address::new_from_array(RING_TEST_PROGRAM_ID),
    ring_authority_transact_is_enabled: 1,
    paused: 0,
    activated: 1,
    bump: 255,
};

/// [`TEST_RING_CONFIG`] as a signing account for host parser tests.
pub fn ring_config_view(address: [u8; 32]) -> AccountView {
    get_account_view(
        address,
        SHIELDED_POOL_PROGRAM_ID,
        true,
        false,
        false,
        bytemuck::bytes_of(&TEST_RING_CONFIG).to_vec(),
    )
}
