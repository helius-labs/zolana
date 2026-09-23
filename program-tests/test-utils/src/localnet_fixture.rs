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

use std::{env, fs, path::Path};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    AsyncProverClient, AsyncZolanaIndexer, ProverClient, SolanaRpc, ZolanaClient, ZolanaIndexer,
};
use zolana_interface::{pda, state::SplAssetRegistry, SHIELDED_POOL_PROGRAM_ID};
use zolana_program_test::ZolanaProgramTest;

use crate::{
    localnet::{isolated_temp_path, LocalnetValidator, WorkspaceArtifacts},
    prover::spawn_workspace_prover,
};

/// A validator and Photon booted from [`write_test_fixture`], with the
/// workspace prover running. It replaces the setup transactions the sdk-tests
/// localnet suites used to send.
pub struct FixtureLocalnet {
    pub client: ZolanaClient<SolanaRpc>,
    /// The default tree, `pda::tree(0)`.
    pub tree: Pubkey,
    /// Raw id of `tree`, read from its account.
    pub tree_id: u16,
}

impl FixtureLocalnet {
    /// Boot with SPP and `programs`, each a program id and a workspace-relative
    /// `.so` path, loaded. `label` names the per-process account directory.
    pub fn start(label: &str, programs: &[(Pubkey, &str)]) -> Result<Self> {
        let artifacts = WorkspaceArtifacts::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
        let spp = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let spp_so = artifacts.path("target/deploy/shielded_pool_program.so");
        let account_dir = isolated_temp_path(&format!("{label}-accounts"));
        write_test_fixture(Path::new(&spp_so), Path::new(&account_dir))?;

        let mut loaded = vec![(spp.to_string(), spp_so)];
        loaded.extend(
            programs
                .iter()
                .map(|(program_id, so)| (program_id.to_string(), artifacts.path(so))),
        );
        LocalnetValidator {
            cli_bin: env::var("ZOLANA_CLI_BIN")
                .unwrap_or_else(|_| artifacts.path("target/debug/zolana")),
            working_dir: artifacts.root(),
            rpc_port: env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".into()),
            photon_port: env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".into()),
            ledger: isolated_temp_path(&format!("{label}-ledger")),
            account_dir,
            programs: loaded,
        }
        .start();
        spawn_workspace_prover();

        let rpc = SolanaRpc::new(
            env::var("ZOLANA_LOCALNET_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".into()),
        );
        let indexer_url =
            env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| "http://127.0.0.1:8784".into());
        rpc.assert_executable(&spp)?;
        for (program_id, _) in programs {
            rpc.assert_executable(program_id)?;
        }
        let tree = pda::tree(0);
        let tree_id = crate::nullifier_pda::tree_id(&rpc, &tree)?;
        let client = ZolanaClient::new(
            rpc,
            ZolanaIndexer::new(indexer_url.clone()),
            ProverClient::default(),
            AsyncZolanaIndexer::new(indexer_url),
            AsyncProverClient::default(),
        );
        Ok(Self {
            client,
            tree,
            tree_id,
        })
    }
}

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

/// Write the protocol config, the SPL asset counter and the empty default
/// tree built from `spp_so` into a cleared `dir`.
pub fn write_protocol_snapshot(spp_so: &Path, dir: &Path) -> Result<()> {
    let mut test = boot(spp_so, dir)?;
    let accounts = init_protocol(&mut test)?;
    write_accounts(&test, dir, &accounts)
}

/// Write the protocol snapshot plus the registered SPL mint, the payer's token
/// account and the funded payer and actors into a cleared `dir`.
pub fn write_test_fixture(spp_so: &Path, dir: &Path) -> Result<()> {
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
    for index in 0..ACTOR_COUNT {
        write_account_json(dir, &actor(index).pubkey(), &funded)?;
    }
    Ok(())
}

fn boot(spp_so: &Path, dir: &Path) -> Result<ZolanaProgramTest> {
    if !spp_so.is_file() {
        bail!(
            "missing {}: run `just build-programs` first",
            spp_so.display()
        );
    }
    if dir.exists() {
        fs::remove_dir_all(dir).with_context(|| format!("failed to clean {}", dir.display()))?;
    }
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    ZolanaProgramTest::with_program_path(spp_so)
        .map_err(|e| anyhow!("failed to boot litesvm: {e:?}"))
}

fn init_protocol(test: &mut ZolanaProgramTest) -> Result<Vec<(&'static str, Pubkey)>> {
    let authority = protocol_authority();
    test.create_protocol_config_permissionless(&authority)
        .map_err(|e| anyhow!("create_protocol_config failed: {e:?}"))?;
    test.create_asset_counter(&authority)
        .map_err(|e| anyhow!("create_asset_counter failed: {e:?}"))?;
    let tree = test
        .create_tree(&authority)
        .map_err(|e| anyhow!("create_tree failed: {e:?}"))?;
    if tree != pda::tree(0) {
        bail!(
            "fresh protocol created tree {tree}, expected {}",
            pda::tree(0)
        );
    }
    Ok(vec![
        ("protocol_config", pda::protocol_config()),
        ("spl_asset_counter", pda::spl_asset_counter()),
        ("tree", tree),
    ])
}

fn register_spl_mint(test: &mut ZolanaProgramTest) -> Result<Vec<(&'static str, Pubkey)>> {
    let token_program = ZolanaProgramTest::token_program_id();
    let mint = test
        .create_mint_from(&Keypair::new_from_array(SPL_MINT_SEED), token_program)
        .map_err(|e| anyhow!("create_mint failed: {e:?}"))?;
    test.create_spl_interface(&protocol_authority(), &mint)
        .map_err(|e| anyhow!("create_spl_interface failed: {e:?}"))?;
    let token_account = test
        .create_token_account_from(
            &Keypair::new_from_array(PAYER_TOKEN_ACCOUNT_SEED),
            &mint,
            &payer().pubkey(),
            token_program,
        )
        .map_err(|e| anyhow!("create_token_account failed: {e:?}"))?;
    test.mint_to(&mint, &token_account, PAYER_SPL_BALANCE)
        .map_err(|e| anyhow!("mint_to failed: {e:?}"))?;

    let registry = pda::spl_asset_registry(&mint);
    let registry_data = test
        .account_data(&registry)
        .ok_or_else(|| anyhow!("spl asset registry {registry} missing after init"))?;
    let asset_id = SplAssetRegistry::from_account_bytes(&registry_data)
        .map_err(|e| anyhow!("spl asset registry {registry}: {e:?}"))?
        .asset_id;
    if asset_id != SPL_ASSET_ID {
        bail!("fixture mint registered as asset {asset_id}, expected {SPL_ASSET_ID}");
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
) -> Result<()> {
    for (label, pubkey) in accounts {
        let account = test
            .svm
            .get_account(pubkey)
            .ok_or_else(|| anyhow!("{label} account {pubkey} missing after init"))?;
        write_account_json(dir, pubkey, &account)?;
        println!("snapshot {label} {pubkey}");
    }
    Ok(())
}

/// One account in the `solana account --output json` format surfpool and
/// solana-test-validator load from `--account-dir`. Keys are in sorted order,
/// so the release's snapshot bundle is byte-stable.
fn write_account_json(dir: &Path, pubkey: &Pubkey, account: &Account) -> Result<()> {
    let json = format!(
        r#"{{"account":{{"data":["{}","base64"],"executable":{},"lamports":{},"owner":"{}","rentEpoch":{}}},"pubkey":"{pubkey}"}}"#,
        STANDARD.encode(&account.data),
        account.executable,
        account.lamports,
        account.owner,
        account.rent_epoch,
    );
    let path = dir.join(format!("{pubkey}.json"));
    fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))
}
