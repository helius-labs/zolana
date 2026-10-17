use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::SolanaRpc;
use zolana_keypair::ShieldedKeypair;
use zolana_secret_file::{create_new, Visibility};

use super::{resolve::ResolvedSyncOptions, util::parse_hex_array};
use crate::{
    args::{AddressOptions, NewWalletOptions},
    cli_config::{resolve_keypair_path as config_keypair_path, resolve_rpc_url, CliConfigFile},
};

const WALLET_FORMAT_VERSION: u8 = 3;

/// One Ed25519 owner seed derives the signing, viewing and nullifier keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeypairFile {
    version: u8,
    owner_hash_hex: String,
    signing_key_hex: String,
}

/// Development format accepted only to preserve the existing owner during conversion.
#[derive(Deserialize)]
struct DevelopmentWalletFile {
    mode: String,
    owner_hash_hex: String,
    signing_key_hex: Option<String>,
    funding_secret_hex: String,
    funding_pubkey: String,
}

pub(super) struct WalletMaterial {
    pub(super) keypair: ShieldedKeypair,
    pub(super) fee_payer: Keypair,
}

impl WalletMaterial {
    pub(super) fn owner_pubkey(&self) -> Pubkey {
        self.keypair.pubkey()
    }

    /// Select a transaction sponsor without changing the wallet identity.
    pub(super) fn with_fee_payer(mut self, path: Option<&str>) -> Result<Self> {
        if let Some(path) = path {
            self.fee_payer = load_owner_keypair(Path::new(path))?;
        }
        Ok(self)
    }
}

pub(super) fn run_new(opts: NewWalletOptions) -> Result<()> {
    let config = CliConfigFile::load()?;
    let path = config_keypair_path(opts.outfile.as_deref(), &config);
    if path.exists() {
        bail!(
            "wallet already exists at {}; delete it or choose another --outfile",
            path.display()
        );
    }

    let (owner, owner_source) = match opts.owner_keypair.as_deref() {
        Some(path) => (load_owner_keypair(Path::new(path))?, "imported"),
        None => (Keypair::new(), "generated"),
    };
    let keypair = ShieldedKeypair::from_keypair(&owner)?;
    save_wallet(&path, &keypair)?;

    // Creation and conversion stay offline unless an airdrop is requested.
    if let Some(lamports) = opts.airdrop_lamports {
        let mut rpc = SolanaRpc::new(resolve_rpc_url(opts.rpc_url.as_deref(), &config));
        let signature = rpc.airdrop(&owner.pubkey(), lamports)?;
        println!("ok airdrop signature={signature}");
    }

    println!(
        "ok wallet {} address={} owner={} owner_source={owner_source}",
        path.display(),
        hex::encode(keypair.owner_hash()?),
        owner.pubkey()
    );
    println!("next: zolana wallet register --keypair {}", path.display());
    Ok(())
}

pub(super) fn run_address(opts: AddressOptions) -> Result<()> {
    let path = config_keypair_path(opts.keypair.keypair.as_deref(), &CliConfigFile::load()?);
    if !path.exists() {
        bail!(
            "wallet not found at {}; create it with `zolana wallet new --outfile {}`",
            path.display(),
            path.display()
        );
    }
    let material = load_existing_wallet(&path)?;
    if opts.public_key {
        println!("{}", material.owner_pubkey());
    } else {
        println!("{}", hex::encode(material.keypair.owner_hash()?));
    }
    Ok(())
}

pub(super) fn load_sender_from_resolved_sync(sync: &ResolvedSyncOptions) -> Result<WalletMaterial> {
    if !sync.keypair_path.exists() {
        bail!(
            "wallet not found at {}; create it with `zolana wallet new --outfile {}`",
            sync.keypair_path.display(),
            sync.keypair_path.display()
        );
    }
    load_existing_wallet(&sync.keypair_path)?.with_fee_payer(sync.fee_payer.as_deref())
}

pub(super) fn load_existing_wallet(path: &Path) -> Result<WalletMaterial> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read wallet {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse wallet {}", path.display()))?;
    let (signing_secret, owner_hash) = match value["version"].as_u64() {
        Some(3) => {
            let file: KeypairFile = serde_json::from_value(value)?;
            (file.signing_key_hex, file.owner_hash_hex)
        }
        Some(2) => {
            let file: DevelopmentWalletFile = serde_json::from_value(value)?;
            let funding = Keypair::new_from_array(parse_hex_array::<32>(&file.funding_secret_hex)?);
            if funding.pubkey().to_string() != file.funding_pubkey {
                bail!(
                    "wallet {} funding pubkey does not match secret",
                    path.display()
                );
            }
            let secret = match file.mode.as_str() {
                "ed25519" => file.funding_secret_hex,
                "independent-ed25519" => file
                    .signing_key_hex
                    .context("development wallet is missing signing_key_hex")?,
                _ => bail!("unsupported development wallet owner mode {}", file.mode),
            };
            (secret, file.owner_hash_hex)
        }
        version => bail!(
            "wallet {} has unsupported wallet format version {}",
            path.display(),
            version.map_or_else(|| "missing".to_string(), |v| v.to_string())
        ),
    };
    let owner = Keypair::new_from_array(parse_hex_array::<32>(&signing_secret)?);
    let keypair = ShieldedKeypair::from_keypair(&owner)?;
    if parse_hex_array::<32>(&owner_hash)? != keypair.owner_hash()? {
        bail!("wallet {} owner_hash does not match keys", path.display());
    }
    Ok(WalletMaterial {
        keypair,
        fee_payer: owner,
    })
}

/// Import an owner without rewriting its source or retaining a development sponsor.
pub(super) fn load_owner_keypair(path: &Path) -> Result<Keypair> {
    let value: serde_json::Value = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("failed to read keypair {}", path.display()))?,
    )?;
    if value.is_array() {
        let values: Vec<u8> = serde_json::from_value(value)?;
        keypair_from_solana_bytes(&values, path)
    } else {
        let material = load_existing_wallet(path)?;
        Ok(Keypair::new_from_array(
            *material.keypair.signing_key.secret_bytes(),
        ))
    }
}

fn keypair_from_solana_bytes(values: &[u8], path: &Path) -> Result<Keypair> {
    let mut secret = [0u8; 32];
    match values.len() {
        32 | 64 => secret.copy_from_slice(values.get(..32).expect("length checked above")),
        length => bail!(
            "unexpected Solana keypair length {length} in {} (expected 32 or 64 bytes)",
            path.display()
        ),
    }
    let keypair = Keypair::new_from_array(secret);
    if values.len() == 64 && Some(keypair.pubkey().to_bytes().as_slice()) != values.get(32..) {
        bail!(
            "keypair {} secret does not match its public key",
            path.display()
        );
    }
    Ok(keypair)
}

fn save_wallet(path: &Path, keypair: &ShieldedKeypair) -> Result<()> {
    let file = KeypairFile {
        version: WALLET_FORMAT_VERSION,
        owner_hash_hex: hex::encode(keypair.owner_hash()?),
        signing_key_hex: hex::encode(keypair.signing_key.secret_bytes()),
    };
    // A wallet key never exists on disk with looser permissions, even briefly.
    create_new(path, &serde_json::to_vec_pretty(&file)?, Visibility::Secret)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    fn temp_root(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        env::temp_dir().join(format!("{prefix}-{}-{stamp}", std::process::id()))
    }

    fn assert_identity(actual: &ShieldedKeypair, expected: &ShieldedKeypair) {
        assert_eq!(actual.pubkey(), expected.pubkey());
        assert_eq!(actual.owner_hash().unwrap(), expected.owner_hash().unwrap());
        assert_eq!(
            actual.shielded_address().unwrap(),
            expected.shielded_address().unwrap()
        );
        let mut utxo_hash = [0; 32];
        utxo_hash[31] = 1;
        let mut blinding = [0; 32];
        blinding[31] = 2;
        assert_eq!(
            actual
                .nullifier_key
                .nullifier(&utxo_hash, &blinding)
                .unwrap(),
            expected
                .nullifier_key
                .nullifier(&utxo_hash, &blinding)
                .unwrap()
        );
    }

    #[test]
    fn wallet_stores_one_owner_secret_and_defaults_fees_to_owner() {
        let wallet = temp_root("zolana-cli-wallet-owner").join("owner.json");
        let owner = ShieldedKeypair::new_ed25519().unwrap();
        save_wallet(&wallet, &owner).unwrap();
        let file: serde_json::Value = serde_json::from_slice(&fs::read(&wallet).unwrap()).unwrap();
        assert_eq!(file.as_object().unwrap().len(), 3);
        assert_eq!(file["version"], WALLET_FORMAT_VERSION);
        assert_eq!(
            file["signing_key_hex"],
            hex::encode(owner.signing_key.secret_bytes())
        );
        let loaded = load_existing_wallet(&wallet).unwrap();
        assert_identity(&loaded.keypair, &owner);
        assert_eq!(loaded.fee_payer.pubkey(), owner.pubkey());
    }

    #[test]
    fn development_wallet_conversion_and_fee_payers_preserve_identity() {
        for independent in [false, true] {
            let root = temp_root("zolana-cli-wallet-conversion");
            let old = root.join("old.json");
            let new = root.join("new.json");
            let funding = Keypair::new();
            let owner = if independent {
                ShieldedKeypair::new_ed25519().unwrap()
            } else {
                ShieldedKeypair::from_keypair(&funding).unwrap()
            };
            let legacy = serde_json::json!({
                "version": 2,
                "mode": if independent { "independent-ed25519" } else { "ed25519" },
                "owner_hash_hex": hex::encode(owner.owner_hash().unwrap()),
                "signing_key_hex": independent.then(|| hex::encode(owner.signing_key.secret_bytes())),
                "funding_secret_hex": hex::encode(funding.secret_bytes()),
                "funding_pubkey": funding.pubkey().to_string(),
            });
            create_new(
                &old,
                &serde_json::to_vec_pretty(&legacy).unwrap(),
                Visibility::Secret,
            )
            .unwrap();
            let original_bytes = fs::read(&old).unwrap();
            let imported =
                ShieldedKeypair::from_keypair(&load_owner_keypair(&old).unwrap()).unwrap();
            assert_identity(&imported, &owner);
            save_wallet(&new, &imported).unwrap();
            assert_eq!(fs::read(&old).unwrap(), original_bytes);
            let converted: serde_json::Value =
                serde_json::from_slice(&fs::read(&new).unwrap()).unwrap();
            for removed in ["mode", "funding_secret_hex", "funding_pubkey"] {
                assert!(converted.get(removed).is_none());
            }
            for i in 0..2 {
                let payer = Keypair::new();
                let payer_path = root.join(format!("payer-{i}.json"));
                create_new(
                    &payer_path,
                    &serde_json::to_vec_pretty(&payer.to_bytes().to_vec()).unwrap(),
                    Visibility::Secret,
                )
                .unwrap();
                let material = load_existing_wallet(&new)
                    .unwrap()
                    .with_fee_payer(payer_path.to_str())
                    .unwrap();
                assert_identity(&material.keypair, &owner);
                assert_eq!(material.fee_payer.pubkey(), payer.pubkey());
                assert_ne!(material.fee_payer.pubkey(), owner.pubkey());
            }
            let mut unsupported = legacy;
            unsupported["mode"] = "p256".into();
            fs::write(&old, serde_json::to_vec(&unsupported).unwrap()).unwrap();
            assert!(load_owner_keypair(&old).is_err());
        }
    }

    #[test]
    fn legacy_wallet_requires_explicit_viewing_key_migration() {
        let wallet = temp_root("zolana-cli-wallet-legacy").join("legacy.json");
        let keypair = ShieldedKeypair::new_ed25519().unwrap();
        save_wallet(&wallet, &keypair).unwrap();
        let mut file: KeypairFile = serde_json::from_slice(&fs::read(&wallet).unwrap()).unwrap();
        file.version = 1;
        fs::write(&wallet, serde_json::to_vec(&file).unwrap()).unwrap();
        let err = load_existing_wallet(&wallet)
            .err()
            .expect("legacy wallet rejected");
        assert!(err
            .to_string()
            .contains("unsupported wallet format version 1"));
    }

    #[test]
    fn wallet_file_creation_never_overwrites() {
        let root = temp_root("zolana-cli-wallet-exclusive");
        let wallet = root.join("id.json");
        let first = ShieldedKeypair::new_ed25519().expect("first shielded keypair");
        save_wallet(&wallet, &first).expect("create wallet");
        let before = fs::read(&wallet).expect("read first wallet");

        assert!(save_wallet(&wallet, &ShieldedKeypair::new_ed25519().unwrap()).is_err());
        assert_eq!(fs::read(&wallet).expect("read unchanged wallet"), before);
    }

    #[cfg(unix)]
    #[test]
    fn wallet_file_is_private_when_created() {
        use std::os::unix::fs::PermissionsExt as _;

        let wallet = temp_root("zolana-cli-wallet-mode").join("id.json");
        save_wallet(
            &wallet,
            &ShieldedKeypair::new_ed25519().expect("shielded keypair"),
        )
        .expect("create wallet");

        assert_eq!(
            fs::metadata(wallet)
                .expect("wallet metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn load_owner_keypair_reads_standard_and_bare_forms() {
        let root = temp_root("zolana-cli-solana-key");
        fs::create_dir_all(&root).unwrap();
        let keypair = Keypair::new();

        let full = root.join("id.json");
        fs::write(
            &full,
            serde_json::to_vec(&keypair.to_bytes().to_vec()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            load_owner_keypair(&full).expect("64-byte").pubkey(),
            keypair.pubkey()
        );

        let bare = root.join("id32.json");
        fs::write(
            &bare,
            serde_json::to_vec(&keypair.secret_bytes().to_vec()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            load_owner_keypair(&bare).expect("32-byte").pubkey(),
            keypair.pubkey()
        );

        let mut bad = keypair.to_bytes().to_vec();
        if let Some(byte) = bad.get_mut(63) {
            *byte ^= 0xff;
        }
        let bad_path = root.join("bad.json");
        fs::write(&bad_path, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(load_owner_keypair(&bad_path).is_err());

        let short = root.join("short.json");
        fs::write(&short, serde_json::to_vec(&vec![0u8; 16]).unwrap()).unwrap();
        assert!(load_owner_keypair(&short).is_err());

        let invalid = root.join("invalid.json");
        fs::write(&invalid, b"not json").unwrap();
        assert!(load_owner_keypair(&invalid).is_err());
    }
}
