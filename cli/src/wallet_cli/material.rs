use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_keypair::{ShieldedKeypair, SigningKey, ViewingKey};

use crate::args::{InitOptions, SyncOptions};

use super::registry::register_wallet_locally;
use super::util::parse_hex_array;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct KeypairFile {
    version: u8,
    owner_hash_hex: String,
    signing_key_hex: String,
    viewing_key_hex: String,
    funding_secret_hex: String,
    funding_pubkey: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SolanaKeypairFile {
    version: u8,
    secret_hex: String,
    pubkey: String,
}

pub(super) struct WalletMaterial {
    pub(super) keypair: ShieldedKeypair,
    pub(super) funding: Keypair,
}

pub(super) fn run_init(opts: InitOptions) -> Result<()> {
    let keypair_path = resolve_keypair_path(opts.path.as_deref());
    if keypair_path.exists() {
        let material = load_existing_wallet(&keypair_path)?;
        register_wallet_locally(&keypair_path, &material)?;
        println!(
            "ok keypair {} owner_hash={} funding={}",
            keypair_path.display(),
            hex::encode(material.keypair.owner_hash()?),
            material.funding.pubkey()
        );
        return Ok(());
    }

    let keypair = ShieldedKeypair::new()?;
    let funding = Keypair::new();
    save_wallet(&keypair_path, &keypair, &funding)?;
    register_wallet_locally(
        &keypair_path,
        &WalletMaterial {
            keypair: clone_keypair(&keypair)?,
            funding: funding.insecure_clone(),
        },
    )?;
    println!(
        "ok keypair {} owner_hash={} funding={}",
        keypair_path.display(),
        hex::encode(keypair.owner_hash()?),
        funding.pubkey()
    );
    Ok(())
}

pub(super) fn load_sender_from_sync(opts: &SyncOptions) -> Result<WalletMaterial> {
    let keypair_path = resolve_keypair_path(opts.keypair.keypair.as_deref());
    if !keypair_path.exists() {
        bail!(
            "keypair not found at {}; run `zolana wallet init` first",
            keypair_path.display()
        );
    }
    load_existing_wallet(&keypair_path)
}

pub(super) fn load_recipient_wallet(path: &str) -> Result<WalletMaterial> {
    let path = PathBuf::from(path);
    if !path.exists() {
        bail!(
            "recipient must be a wallet file path for now; `{}` does not exist",
            path.display()
        );
    }
    load_existing_wallet(&path)
}

pub(super) fn load_existing_wallet(path: &Path) -> Result<WalletMaterial> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read wallet {}", path.display()))?;
    let file: KeypairFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse wallet {}", path.display()))?;
    let signing_bytes = parse_hex_array::<32>(&file.signing_key_hex)?;
    let viewing_bytes = parse_hex_array::<32>(&file.viewing_key_hex)?;
    let funding_bytes = parse_hex_array::<32>(&file.funding_secret_hex)?;
    let signing = SigningKey::from_bytes(&signing_bytes)?;
    let viewing = ViewingKey::from_bytes(&viewing_bytes)?;
    let keypair = ShieldedKeypair::from_keys(signing, viewing)?;
    let expected_owner_hash = keypair.owner_hash()?;
    let stored_owner_hash = parse_hex_array::<32>(&file.owner_hash_hex)?;
    if stored_owner_hash != expected_owner_hash {
        bail!("wallet {} owner_hash does not match keys", path.display());
    }
    let funding = Keypair::new_from_array(funding_bytes);
    if funding.pubkey().to_string() != file.funding_pubkey {
        bail!(
            "wallet {} funding pubkey does not match secret",
            path.display()
        );
    }
    Ok(WalletMaterial { keypair, funding })
}

fn save_wallet(path: &Path, keypair: &ShieldedKeypair, funding: &Keypair) -> Result<()> {
    let file = KeypairFile {
        version: 2,
        owner_hash_hex: hex::encode(keypair.owner_hash()?),
        signing_key_hex: hex::encode(keypair.signing_key.secret_bytes().as_slice()),
        viewing_key_hex: hex::encode(keypair.viewing_key.secret_bytes().as_slice()),
        funding_secret_hex: hex::encode(funding.secret_bytes()),
        funding_pubkey: funding.pubkey().to_string(),
    };
    write_json_secret(path, &file)
}

pub(super) fn load_or_create_solana_keypair(path: &Path) -> Result<Keypair> {
    if path.exists() {
        let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let file: SolanaKeypairFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let secret = parse_hex_array::<32>(&file.secret_hex)?;
        let keypair = Keypair::new_from_array(secret);
        if keypair.pubkey().to_string() != file.pubkey {
            bail!("keypair {} pubkey does not match secret", path.display());
        }
        return Ok(keypair);
    }

    let keypair = Keypair::new();
    let file = SolanaKeypairFile {
        version: 1,
        secret_hex: hex::encode(keypair.secret_bytes()),
        pubkey: keypair.pubkey().to_string(),
    };
    write_json_secret(path, &file)?;
    Ok(keypair)
}

pub(super) fn write_json_secret<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }
    Ok(())
}

pub(super) fn clone_keypair(keypair: &ShieldedKeypair) -> Result<ShieldedKeypair> {
    let mut signing = [0u8; 32];
    signing.copy_from_slice(keypair.signing_key.secret_bytes().as_slice());
    let mut viewing = [0u8; 32];
    viewing.copy_from_slice(keypair.viewing_key.secret_bytes().as_slice());
    Ok(ShieldedKeypair::from_keys(
        SigningKey::from_bytes(&signing)?,
        ViewingKey::from_bytes(&viewing)?,
    )?)
}

pub(super) fn resolve_keypair_path(value: Option<&str>) -> PathBuf {
    match value {
        Some(path) => PathBuf::from(path),
        None => default_config_dir().join("pid.json"),
    }
}

pub(super) fn default_config_dir() -> PathBuf {
    if let Some(home) = env::var_os("HOME") {
        PathBuf::from(home).join(".config").join("zolana")
    } else {
        PathBuf::from(".zolana")
    }
}

#[allow(dead_code)]
fn _assert_pubkey_public(pubkey: Pubkey) -> Pubkey {
    pubkey
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::args::{SyncOptions, WalletKeypairOptions};
    use crate::wallet_cli::registry::{
        local_user_registry_path, read_local_user_registry, resolve_transfer_recipient,
    };

    fn temp_root(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        env::temp_dir().join(format!("{prefix}-{}-{stamp}", std::process::id()))
    }

    #[test]
    fn wallet_init_round_trips_real_keys() {
        let root = temp_root("zolana-cli-wallet-real");
        let wallet = root.join("alice.pid.json");
        run_init(InitOptions {
            path: Some(wallet.display().to_string()),
        })
        .expect("init wallet");

        let loaded = load_existing_wallet(&wallet).expect("load wallet");
        assert_eq!(
            loaded.keypair.owner_hash().unwrap(),
            parse_hex_array::<32>(
                &serde_json::from_slice::<KeypairFile>(&fs::read(&wallet).unwrap())
                    .unwrap()
                    .owner_hash_hex
            )
            .unwrap()
        );
        assert_ne!(loaded.funding.pubkey(), Pubkey::default());

        let registry_path = local_user_registry_path(&wallet);
        let registry = read_local_user_registry(&registry_path).expect("read registry");
        assert_eq!(registry.records.len(), 1);
        assert!(registry
            .records
            .contains_key(&loaded.funding.pubkey().to_string()));
        let recipient = resolve_transfer_recipient(
            &loaded.funding.pubkey().to_string(),
            &SyncOptions {
                keypair: WalletKeypairOptions {
                    keypair: Some(wallet.display().to_string()),
                },
                rpc_url: "http://127.0.0.1:8899".to_string(),
                indexer_url: "http://127.0.0.1:8784".to_string(),
            },
        )
        .expect("lookup recipient");
        assert_eq!(recipient.owner, loaded.funding.pubkey());
        assert_eq!(
            recipient.address.owner_hash().unwrap(),
            loaded
                .keypair
                .shielded_address()
                .unwrap()
                .owner_hash()
                .unwrap()
        );
    }

    #[test]
    fn missing_recipient_path_is_rejected() {
        let missing = temp_root("zolana-cli-missing").join("missing.pid.json");
        let err = match load_recipient_wallet(&missing.display().to_string()) {
            Ok(_) => panic!("missing recipient should fail"),
            Err(err) => err,
        };
        assert!(err
            .to_string()
            .contains("recipient must be a wallet file path"));
    }
}
