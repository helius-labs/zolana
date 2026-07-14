//! Test helpers for the Squads smart-account program.
//!
//! The client surface (program id, PDA derivations, and the
//! `create_smart_account_ix` / `execute_sync_ix` builders) lives in
//! `zolana-smart-account-client` and is re-exported here so existing test
//! imports keep working. This module adds the localnet `ProgramConfig` fixture
//! and the standard protocol/forester/tree/zone account layout the SPP tests
//! share.

use std::{fs, path::Path};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
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
    pub zone_settings: Pubkey,
    pub zone_vault: Pubkey,
}

#[derive(Clone, Copy, Debug)]
pub struct StandardSigners {
    pub protocol: Pubkey,
    pub forester: Pubkey,
    pub merge: Pubkey,
    pub tree: Pubkey,
    pub zone: Pubkey,
}

pub fn standard_accounts() -> StandardAccounts {
    let (protocol_settings, _) = settings_pda(1);
    let (protocol_vault, _) = smart_account_pda(&protocol_settings, 0);
    let (forester_settings, _) = settings_pda(2);
    let (forester_vault, _) = smart_account_pda(&forester_settings, 0);
    let (merge_settings, _) = settings_pda(3);
    let (merge_vault, _) = smart_account_pda(&merge_settings, 0);
    let (tree_settings, _) = settings_pda(4);
    let (tree_vault, _) = smart_account_pda(&tree_settings, 0);
    let (zone_settings, _) = settings_pda(5);
    let (zone_vault, _) = smart_account_pda(&zone_settings, 0);

    StandardAccounts {
        protocol_settings,
        protocol_vault,
        forester_settings,
        forester_vault,
        merge_settings,
        merge_vault,
        tree_settings,
        tree_vault,
        zone_settings,
        zone_vault,
    }
}

impl StandardAccounts {
    pub fn create_ixs(&self, creator: &Pubkey, signers: StandardSigners) -> Vec<Instruction> {
        let treasury = treasury_pda();
        [
            (1, None, signers.protocol),
            (2, Some(self.protocol_vault), signers.forester),
            (3, Some(self.protocol_vault), signers.merge),
            (4, Some(self.protocol_vault), signers.tree),
            (5, Some(self.protocol_vault), signers.zone),
        ]
        .into_iter()
        .map(|(seed, settings_authority, signer)| {
            create_smart_account_ix(
                creator,
                &treasury,
                seed,
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
