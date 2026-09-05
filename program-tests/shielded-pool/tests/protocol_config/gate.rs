//! F-07: `create_protocol_config` is bound to the deploy upgrade authority.
//!
//! Only the real, nonzero loader-v3 upgrade authority may initialize the
//! one-time protocol config (front-run protection, INV-CREATE-PC-10).
//! Non-upgradeable, immutable, and zero-authority deployments fail closed. The
//! accounts are fabricated directly in LiteSVM, mirroring the bytes a real
//! `solana program deploy` writes.

use shielded_pool_tests::support::runtime::program_test;
use solana_account::Account;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::{pubkey, Pubkey};
use solana_signer::Signer;
use zolana_interface::{
    error::ShieldedPoolError, instruction::CreateProtocolConfig, pda, state::ProtocolConfig,
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

fn create_ix(
    fee_payer: &Pubkey,
    initialization_authority: &Pubkey,
    protocol_authority: &Pubkey,
) -> Instruction {
    CreateProtocolConfig {
        fee_payer: *fee_payer,
        initialization_authority: *initialization_authority,
        protocol_authority: protocol_authority.to_bytes().into(),
        tree_creation_authority: protocol_authority.to_bytes().into(),
        tree_creation_is_permissionless: false,
        forester_authority: protocol_authority.to_bytes().into(),
        ring_creation_authority: protocol_authority.to_bytes().into(),
        ring_activation_is_permissionless: false,
        spl_interface_creation_is_permissionless: false,
        fee_authority: protocol_authority.to_bytes().into(),
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

/// A signer other than the upgrade authority must not initialize the protocol
/// config on an upgradeable deployment (deploy-time front-run).
#[test]
fn create_rejects_an_initialization_signer_that_is_not_the_upgrade_authority() {
    let deployer = Keypair::new();
    let attacker = Keypair::new();
    let mut rpc = boot_with_deploy(Some(&deployer.pubkey()), &attacker);

    let error = rpc
        .create_and_send_default_payer_transaction(
            &[create_ix(
                &attacker.pubkey(),
                &attacker.pubkey(),
                &attacker.pubkey(),
            )],
            &[&attacker],
        )
        .expect_err("a non-upgrade-authority initializer must be rejected");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(error);
    assert!(
        rpc.account_data(&pda::protocol_config()).is_none(),
        "rejected init must not write the config"
    );
}

/// The deploy upgrade authority initializes successfully even when the rent
/// payer and final protocol authority are different accounts.
#[test]
fn create_accepts_a_separate_payer_initializer_and_protocol_authority() {
    let payer = Keypair::new();
    let deployer = Keypair::new();
    let protocol_authority = Pubkey::new_unique();
    let mut rpc = boot_with_deploy(Some(&deployer.pubkey()), &payer);

    rpc.create_and_send_default_payer_transaction(
        &[create_ix(
            &payer.pubkey(),
            &deployer.pubkey(),
            &protocol_authority,
        )],
        &[&payer, &deployer],
    )
    .expect("the upgrade authority initializes");
    let config_data = rpc
        .account_data(&pda::protocol_config())
        .expect("config must be written");
    let config = ProtocolConfig::from_account_bytes(&config_data).expect("valid protocol config");
    assert_eq!(
        config.protocol_authority.to_bytes(),
        protocol_authority.to_bytes()
    );
}

#[test]
fn create_rejects_an_unset_upgrade_authority() {
    let payer = Keypair::new();
    let mut rpc = boot_with_deploy(None, &payer);

    let error = rpc
        .create_and_send_default_payer_transaction(
            &[create_ix(&payer.pubkey(), &payer.pubkey(), &payer.pubkey())],
            &[&payer],
        )
        .expect_err("unset upgrade authority must reject initialization");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(error);
    assert!(rpc.account_data(&pda::protocol_config()).is_none());
}

#[test]
fn create_rejects_a_zeroed_upgrade_authority() {
    let payer = Keypair::new();
    let zeroed = Pubkey::default();
    let mut rpc = boot_with_deploy(Some(&zeroed), &payer);

    let error = rpc
        .create_and_send_default_payer_transaction(
            &[create_ix(&payer.pubkey(), &payer.pubkey(), &payer.pubkey())],
            &[&payer],
        )
        .expect_err("zero upgrade authority must reject initialization");
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(error);
    assert!(rpc.account_data(&pda::protocol_config()).is_none());
}

#[test]
fn create_rejects_a_non_loader_v3_deployment() {
    let payer = Keypair::new();
    let mut rpc = program_test();
    rpc.airdrop(&payer.pubkey(), 10_000_000_000)
        .expect("airdrop");
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let program_data = rpc
        .svm
        .get_account(&pda::program_data())
        .expect("shielded-pool ProgramData account");
    let program_bytes = program_data
        .data
        .get(45..)
        .expect("loader-v3 ProgramData header");
    rpc.svm
        .add_program_with_loader(
            program_id,
            program_bytes,
            pubkey!("BPFLoader1111111111111111111111111111111111"),
        )
        .expect("replace program with a loader-v2 deployment");

    rpc.create_and_send_default_payer_transaction(
        &[create_ix(&payer.pubkey(), &payer.pubkey(), &payer.pubkey())],
        &[&payer],
    )
    .expect_err("a non-loader-v3 deployment must reject initialization");
    assert!(rpc.account_data(&pda::protocol_config()).is_none());
}
