//! F-07: `create_protocol_config` is bound to the deploy upgrade authority.
//!
//! On an upgradeable loader-v3 deployment whose `ProgramData` names an upgrade
//! authority, only that authority may initialize the one-time protocol config
//! (front-run protection, INV-CREATE-PC-10). Non-upgradeable deployments and an
//! unset or zeroed authority skip the check. The accounts are fabricated
//! directly in LiteSVM, mirroring the bytes a real `solana program deploy`
//! writes.

use shielded_pool_tests::support::runtime::program_test;
use solana_account::Account;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    error::ShieldedPoolError, instruction::CreateProtocolConfig, pda,
    BPF_LOADER_UPGRADEABLE_PUBKEY, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program_test::{Rejection, ZolanaProgramTest};

/// Loader-v3 `Program` state: u32 tag 2 || programdata address. Owner is the
/// upgradeable loader, matching a `solana program deploy` deployment.
fn upgradeable_program_account() -> Account {
    let program_data = pda::program_data();
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(program_data.as_ref());
    Account {
        lamports: 1_000_000_000,
        data,
        owner: BPF_LOADER_UPGRADEABLE_PUBKEY,
        executable: true,
        rent_epoch: 0,
    }
}

/// Loader-v3 `ProgramData` state: u32 tag 3 || slot u64 || u8 option tag ||
/// authority (bincode encodes `Option` as a single byte, matching the bytes a
/// real loader writes). `authority = None` models an immutable program or a
/// test harness (LiteSVM loads programs exactly this way).
fn program_data_account(upgrade_authority: Option<&Pubkey>) -> Account {
    let mut data = Vec::with_capacity(48);
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    match upgrade_authority {
        Some(authority) => {
            data.push(1);
            data.extend_from_slice(authority.as_ref());
        }
        None => data.push(0),
    }
    Account {
        lamports: 1_000_000_000,
        data,
        owner: BPF_LOADER_UPGRADEABLE_PUBKEY,
        executable: false,
        rent_epoch: 0,
    }
}

/// Install the shielded-pool program as an upgradeable deployment whose
/// `ProgramData` names `upgrade_authority`.
fn install_upgradeable_deploy(rpc: &mut ZolanaProgramTest, upgrade_authority: Option<&Pubkey>) {
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    rpc.svm
        .set_account(program_id, upgradeable_program_account())
        .expect("write upgradeable program account");
    rpc.svm
        .set_account(pda::program_data(), program_data_account(upgrade_authority))
        .expect("write program data account");
}

fn create_ix_for(authority: &Keypair) -> Instruction {
    CreateProtocolConfig {
        authority: authority.pubkey(),
        protocol_authority: authority.pubkey().to_bytes().into(),
        tree_creation_authority: authority.pubkey().to_bytes().into(),
        tree_creation_is_permissionless: false,
        forester_authority: authority.pubkey().to_bytes().into(),
        ring_creation_authority: authority.pubkey().to_bytes().into(),
        ring_creation_is_permissionless: false,
        spl_interface_creation_is_permissionless: false,
    }
    .instruction()
}

fn boot_with_deploy(upgrade_authority: Option<&Pubkey>, payer: &Keypair) -> ZolanaProgramTest {
    let mut rpc = program_test();
    rpc.airdrop(&payer.pubkey(), 10_000_000_000)
        .expect("airdrop");
    install_upgradeable_deploy(&mut rpc, upgrade_authority);
    rpc
}

/// A fee payer other than the upgrade authority must not initialize the
/// protocol config on an upgradeable deployment (deploy-time front-run).
#[test]
fn create_rejects_a_fee_payer_that_is_not_the_upgrade_authority() {
    let deployer = Keypair::new();
    let attacker = Keypair::new();
    let mut rpc = boot_with_deploy(Some(&deployer.pubkey()), &attacker);

    let error = rpc
        .create_and_send_default_payer_transaction(&[create_ix_for(&attacker)], &[&attacker])
        .expect_err("a non-upgrade-authority payer must be rejected");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(error);
    assert!(
        rpc.account_data(&pda::protocol_config()).is_none(),
        "rejected init must not write the config"
    );
}

/// The deploy upgrade authority itself initializes successfully.
#[test]
fn create_accepts_the_upgrade_authority() {
    let deployer = Keypair::new();
    let mut rpc = boot_with_deploy(Some(&deployer.pubkey()), &deployer);

    rpc.create_and_send_default_payer_transaction(&[create_ix_for(&deployer)], &[&deployer])
        .expect("the upgrade authority initializes");
    assert!(
        rpc.account_data(&pda::protocol_config()).is_some(),
        "config must be written"
    );
}

/// An unset upgrade authority (immutable program, test harness) skips the gate.
#[test]
fn create_skips_the_check_without_an_upgrade_authority() {
    let payer = Keypair::new();
    let mut rpc = boot_with_deploy(None, &payer);

    rpc.create_and_send_default_payer_transaction(&[create_ix_for(&payer)], &[&payer])
        .expect("unset upgrade authority skips the check");
    assert!(
        rpc.account_data(&pda::protocol_config()).is_some(),
        "config must be written"
    );
}

/// A zeroed upgrade authority (the shape solana-test-validator gives
/// `--bpf-program` deployments) skips the gate.
#[test]
fn create_skips_the_check_with_a_zeroed_upgrade_authority() {
    let payer = Keypair::new();
    let zeroed = Pubkey::default();
    let mut rpc = boot_with_deploy(Some(&zeroed), &payer);

    rpc.create_and_send_default_payer_transaction(&[create_ix_for(&payer)], &[&payer])
        .expect("zeroed upgrade authority skips the check");
    assert!(
        rpc.account_data(&pda::protocol_config()).is_some(),
        "config must be written"
    );
}
