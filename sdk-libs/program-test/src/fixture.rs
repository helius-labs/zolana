//! Accounts a localnet boots with instead of creating them with setup
//! transactions. Everything is built in-process on LiteSVM and written as
//! account JSON files for `--account-dir`, so the validator starts initialized.
//!
//! - [`write_protocol_snapshot`]: the protocol config, the SPL asset counter
//!   and the empty default tree. The release ships this set as its localnet
//!   snapshot.
//! - [`write_test_fixture`]: that set plus an SPL mint registered with the pool
//!   as asset [`SPL_ASSET_ID`], a token account of the [`payer`] holding
//!   [`PAYER_SPL_BALANCE`], and funded [`payer`] and [`actor`] accounts.
//!
//! Every key here comes from a fixed seed, so its secret is public. The
//! protocol config makes tree creation, ring activation and SPL interface
//! creation permissionless, so nothing after boot needs a protocol signer.
//!
//! Deposits stay runtime transactions: Photon builds its tree view from the
//! transactions it indexes after it starts, so a snapshotted tree with leaves
//! would disagree with it.

use std::{fs, path::Path};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{pda, state::SplAssetRegistry};

use crate::{ProgramTestError, ZolanaProgramTest};

/// Lamports the payer and every actor start with.
pub const FUNDED_LAMPORTS: u64 = 100_000_000_000;
/// Tokens of [`spl_mint`] the payer's token account starts with.
pub const PAYER_SPL_BALANCE: u64 = 1_000_000_000;
/// The pool's asset id for [`spl_mint`]: the fixture registers exactly one SPL
/// mint, and the first one follows SOL.
pub const SPL_ASSET_ID: u64 = 2;
/// How many [`actor`] keypairs the fixture funds.
pub const ACTOR_COUNT: u8 = 4;

/// Public on purpose: the localnet protocol authority is nobody's secret.
const PROTOCOL_AUTHORITY_SEED: [u8; 32] = *b"zolana localnet snapshot authori";
const PAYER_SEED: [u8; 32] = *b"zolana localnet fixture payer\0\0\0";
const ACTOR_SEED: [u8; 32] = *b"zolana localnet fixture actor\0\0\0";
const SPL_MINT_SEED: [u8; 32] = *b"zolana localnet fixture mint\0\0\0\0";
const PAYER_TOKEN_ACCOUNT_SEED: [u8; 32] = *b"zolana localnet fixture tokens\0\0";

/// The authority that created the protocol config, the asset counter and the
/// default tree.
pub fn protocol_authority() -> Keypair {
    Keypair::new_from_array(PROTOCOL_AUTHORITY_SEED)
}

/// Funded fee payer and SPL depositor. It owns [`payer_token_account`].
pub fn payer() -> Keypair {
    Keypair::new_from_array(PAYER_SEED)
}

/// A funded actor, `index < ACTOR_COUNT`. Each test boots its own validator,
/// so tests can reuse the same actors.
pub fn actor(index: u8) -> Keypair {
    let mut seed = ACTOR_SEED;
    seed[31] = index;
    Keypair::new_from_array(seed)
}

/// The SPL mint registered with the pool as [`SPL_ASSET_ID`].
pub fn spl_mint() -> Pubkey {
    Keypair::new_from_array(SPL_MINT_SEED).pubkey()
}

/// The payer's token account for [`spl_mint`].
pub fn payer_token_account() -> Pubkey {
    Keypair::new_from_array(PAYER_TOKEN_ACCOUNT_SEED).pubkey()
}

/// Accounts a writer put in its directory, by label.
pub type WrittenAccounts = Vec<(&'static str, Pubkey)>;

/// Write the protocol config, the SPL asset counter and the empty default
/// tree built from `spp_so` into a cleared `dir`.
pub fn write_protocol_snapshot(
    spp_so: &Path,
    dir: &Path,
) -> Result<WrittenAccounts, ProgramTestError> {
    let mut test = boot(spp_so, dir)?;
    let accounts = init_protocol(&mut test)?;
    write_accounts(&test, dir, &accounts)?;
    Ok(accounts)
}

/// Write the protocol snapshot plus the registered SPL mint, the payer's token
/// account and the funded payer and actors into a cleared `dir`.
pub fn write_test_fixture(spp_so: &Path, dir: &Path) -> Result<WrittenAccounts, ProgramTestError> {
    let mut test = boot(spp_so, dir)?;
    let mut accounts = init_protocol(&mut test)?;
    accounts.extend(register_spl_mint(&mut test)?);
    write_accounts(&test, dir, &accounts)?;
    let funded = Account {
        lamports: FUNDED_LAMPORTS,
        data: Vec::new(),
        owner: Pubkey::default(),
        executable: false,
        rent_epoch: 0,
    };
    write_account_json(dir, &payer().pubkey(), &funded)?;
    accounts.push(("payer", payer().pubkey()));
    for index in 0..ACTOR_COUNT {
        write_account_json(dir, &actor(index).pubkey(), &funded)?;
        accounts.push(("actor", actor(index).pubkey()));
    }
    Ok(accounts)
}

fn boot(spp_so: &Path, dir: &Path) -> Result<ZolanaProgramTest, ProgramTestError> {
    if dir.exists() {
        fs::remove_dir_all(dir)?;
    }
    fs::create_dir_all(dir)?;
    ZolanaProgramTest::with_program_path(spp_so)
}

fn init_protocol(test: &mut ZolanaProgramTest) -> Result<WrittenAccounts, ProgramTestError> {
    let authority = protocol_authority();
    test.create_protocol_config_permissionless(&authority)?;
    test.create_asset_counter(&authority)?;
    let tree = test.create_tree(&authority)?;
    if tree != pda::tree(0) {
        return Err(ProgramTestError::Fixture(format!(
            "fresh protocol created tree {tree}, expected {}",
            pda::tree(0)
        )));
    }
    Ok(vec![
        ("protocol_config", pda::protocol_config()),
        ("spl_asset_counter", pda::spl_asset_counter()),
        ("tree", tree),
    ])
}

fn register_spl_mint(test: &mut ZolanaProgramTest) -> Result<WrittenAccounts, ProgramTestError> {
    let token_program = ZolanaProgramTest::token_program_id();
    let mint = test.create_mint_from(&Keypair::new_from_array(SPL_MINT_SEED), token_program)?;
    test.create_spl_interface(&protocol_authority(), &mint)?;
    let token_account = test.create_token_account_from(
        &Keypair::new_from_array(PAYER_TOKEN_ACCOUNT_SEED),
        &mint,
        &payer().pubkey(),
        token_program,
    )?;
    test.mint_to(&mint, &token_account, PAYER_SPL_BALANCE)?;

    let registry = pda::spl_asset_registry(&mint);
    let registry_data = test.account_data(&registry).ok_or_else(|| {
        ProgramTestError::Fixture(format!("spl asset registry {registry} missing after init"))
    })?;
    let asset_id = SplAssetRegistry::from_account_bytes(&registry_data)
        .map_err(|e| ProgramTestError::Fixture(format!("spl asset registry {registry}: {e:?}")))?
        .asset_id;
    if asset_id != SPL_ASSET_ID {
        return Err(ProgramTestError::Fixture(format!(
            "fixture mint registered as asset {asset_id}, expected {SPL_ASSET_ID}"
        )));
    }
    Ok(vec![
        ("spl_mint", mint),
        ("spl_asset_registry", registry),
        ("spl_interface", pda::spl_interface(&mint)),
        ("payer_token_account", token_account),
    ])
}

fn write_accounts(
    test: &ZolanaProgramTest,
    dir: &Path,
    accounts: &[(&'static str, Pubkey)],
) -> Result<(), ProgramTestError> {
    for (label, pubkey) in accounts {
        let account = test.svm.get_account(pubkey).ok_or_else(|| {
            ProgramTestError::Fixture(format!("{label} account {pubkey} missing after init"))
        })?;
        write_account_json(dir, pubkey, &account)?;
    }
    Ok(())
}

/// One account in the `solana account --output json` format surfpool and
/// solana-test-validator load from `--account-dir`. Keys are in sorted order,
/// so the release's snapshot bundle is byte-stable.
pub fn account_json(pubkey: &Pubkey, account: &Account) -> String {
    format!(
        r#"{{"account":{{"data":["{}","base64"],"executable":{},"lamports":{},"owner":"{}","rentEpoch":{}}},"pubkey":"{pubkey}"}}"#,
        STANDARD.encode(&account.data),
        account.executable,
        account.lamports,
        account.owner,
        account.rent_epoch,
    )
}

fn write_account_json(
    dir: &Path,
    pubkey: &Pubkey,
    account: &Account,
) -> Result<(), ProgramTestError> {
    fs::write(
        dir.join(format!("{pubkey}.json")),
        account_json(pubkey, account),
    )?;
    Ok(())
}
