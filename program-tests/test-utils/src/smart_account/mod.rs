//! Test helpers for the Squads smart-account program.
//!
//! The client surface (program id, PDA derivations, and the
//! `create_smart_account_ix` / `execute_sync_ix` builders) lives in
//! `zolana-smart-account-client` and is re-exported here so existing test
//! imports keep working. This module adds the localnet `ProgramConfig` fixture
//! and the standard five-role account layout the SPP tests share, built on the
//! role table in [`roles`]: the localnet fixture `ProgramConfig` starts at
//! index 0, so the roles sit at seeds 1..=5 in `Role::ALL` creation order
//! (protocol, tree, ring, merge, forester). `xtask init-protocol` deploys the
//! same roles in the same order without sharing this table -- see [`roles`].

use std::{fs, path::Path};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
pub mod roles;
pub mod settings;

pub use roles::Role;
pub use settings::settings_member_keys;
pub use zolana_smart_account_client::{
    create_smart_account_ix, execute_sync_ix, program_config_pda, settings_pda, smart_account_pda,
    treasury_pda, Permissions, SmartAccountSigner, SMART_ACCOUNT_PROGRAM_ID,
};

// Anchor account discriminator: sha256("account:ProgramConfig")[0..8]
pub const PROGRAM_CONFIG_ACCOUNT_DISCRIMINATOR: [u8; 8] = [196, 210, 90, 231, 144, 149, 140, 63];
const PROGRAM_CONFIG_ACCOUNT_LEN: usize = 160;
const PROGRAM_CONFIG_DISCRIMINATOR_END: usize = 8;
const PROGRAM_CONFIG_TREASURY_START: usize = 64;
const PROGRAM_CONFIG_TREASURY_END: usize = 96;

/// Write the pre-initialized Squads `ProgramConfig` account used by localnet
/// tests that load the smart-account program from a fixture account directory.
pub fn write_program_config_fixture(account_dir: impl AsRef<Path>) {
    let (pda, _) = program_config_pda();

    let mut data = [0u8; PROGRAM_CONFIG_ACCOUNT_LEN];
    data[..PROGRAM_CONFIG_DISCRIMINATOR_END].copy_from_slice(&PROGRAM_CONFIG_ACCOUNT_DISCRIMINATOR);
    data[PROGRAM_CONFIG_TREASURY_START..PROGRAM_CONFIG_TREASURY_END]
        .copy_from_slice(&treasury_pda().to_bytes());
    let encoded = STANDARD.encode(data);

    let json = format!(
        r#"{{"pubkey":"{pda}","account":{{"lamports":1000000,"data":["{encoded}","base64"],"owner":"{SMART_ACCOUNT_PROGRAM_ID}","executable":false,"rentEpoch":18446744073709551615}}}}"#,
    );

    let account_dir = account_dir.as_ref();
    fs::create_dir_all(account_dir).expect("create smart account account dir");
    fs::write(account_dir.join("squads_program_config.json"), json)
        .expect("write squads program config fixture");
}

#[derive(Clone, Copy, Debug)]
pub struct StandardAccounts {
    pub protocol_settings: Pubkey,
    pub protocol_vault: Pubkey,
    pub forester_settings: Pubkey,
    pub forester_vault: Pubkey,
    pub merge_settings: Pubkey,
    pub merge_vault: Pubkey,
    pub tree_settings: Pubkey,
    pub tree_vault: Pubkey,
    pub ring_settings: Pubkey,
    pub ring_vault: Pubkey,
}

#[derive(Clone, Copy, Debug)]
pub struct StandardSigners {
    pub protocol: Pubkey,
    pub forester: Pubkey,
    pub merge: Pubkey,
    pub tree: Pubkey,
    pub ring: Pubkey,
}

/// Derive the five standard role accounts from the shared role table
/// (`zolana_smart_account_client::roles`) above the localnet fixture's base
/// index 0: protocol/tree/ring/merge/forester at seeds 1..=5, the same table
/// `xtask init-protocol` deploys with.
pub fn standard_accounts() -> StandardAccounts {
    let (protocol_settings, _) = Role::Protocol.settings_pda(0);
    let (protocol_vault, _) = smart_account_pda(&protocol_settings, 0);
    let (forester_settings, _) = Role::Forester.settings_pda(0);
    let (forester_vault, _) = smart_account_pda(&forester_settings, 0);
    let (merge_settings, _) = Role::Merge.settings_pda(0);
    let (merge_vault, _) = smart_account_pda(&merge_settings, 0);
    let (tree_settings, _) = Role::Tree.settings_pda(0);
    let (tree_vault, _) = smart_account_pda(&tree_settings, 0);
    let (ring_settings, _) = Role::Ring.settings_pda(0);
    let (ring_vault, _) = smart_account_pda(&ring_settings, 0);

    StandardAccounts {
        protocol_settings,
        protocol_vault,
        forester_settings,
        forester_vault,
        merge_settings,
        merge_vault,
        tree_settings,
        tree_vault,
        ring_settings,
        ring_vault,
    }
}

impl StandardAccounts {
    /// The create instructions for the five role accounts, in `Role::ALL`
    /// creation order: the protocol account is autonomous (`None` settings
    /// authority), the rest are controlled by the protocol vault.
    pub fn create_ixs(&self, creator: &Pubkey, signers: StandardSigners) -> Vec<Instruction> {
        let treasury = treasury_pda();
        [
            (Role::Protocol, None, signers.protocol),
            (Role::Tree, Some(self.protocol_vault), signers.tree),
            (Role::Ring, Some(self.protocol_vault), signers.ring),
            (Role::Merge, Some(self.protocol_vault), signers.merge),
            (Role::Forester, Some(self.protocol_vault), signers.forester),
        ]
        .into_iter()
        .map(|(role, settings_authority, signer)| {
            create_smart_account_ix(
                creator,
                &treasury,
                role.seed(0),
                settings_authority,
                &[SmartAccountSigner {
                    key: signer,
                    permissions: Permissions::all(),
                }],
                1,
                0,
            )
        })
        .collect()
    }
}
