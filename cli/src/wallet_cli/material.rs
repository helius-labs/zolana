#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    AnonymousRecipientSlot, ApprovalRequest, ClientError, ConfidentialRecipientSlot,
    EncryptedSplit, EncryptedTransfer, P256Signature, Rpc, SolanaRpc, SyncWalletAuthority,
};
use zolana_keypair::{
    shielded::ShieldedAddress, viewing_key::ViewTag, NullifierKey, ShieldedKeypair, SigningKey,
    ViewingKey,
};
use zolana_transaction::{
    serialization::{
        anonymous::AnonymousTransferSenderPlaintext, confidential::TransferSenderPlaintext,
        split::SplitBundlePlaintext,
    },
    Address,
};

use super::{
    registry::register_wallet_on_chain,
    resolve::ResolvedSyncOptions,
    util::{parse_hex_array, parse_sol_amount, system_transfer_ix},
};
use crate::{
    args::{InitOptions, NewWalletOptions, WalletKeypairOptions},
    cli_config::{
        resolve_keypair_path as config_keypair_path, resolve_rpc_url, resolve_wallet_path,
        wallet_file, wallets_dir, CliConfigFile,
    },
};

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

impl WalletMaterial {
    pub(super) fn owner_pubkey(&self) -> Pubkey {
        self.funding.pubkey()
    }

    fn check_owner_pubkey(&self, owner_pubkey: Pubkey) -> std::result::Result<(), ClientError> {
        if owner_pubkey == self.owner_pubkey() {
            Ok(())
        } else {
            Err(ClientError::AddressResolution(format!(
                "wallet file belongs to owner_pubkey {}, got {owner_pubkey}",
                self.owner_pubkey()
            )))
        }
    }
}

impl SyncWalletAuthority for WalletMaterial {
    fn shielded_address(
        &self,
        owner_pubkey: Pubkey,
    ) -> std::result::Result<ShieldedAddress, ClientError> {
        self.check_owner_pubkey(owner_pubkey)?;
        Ok(self.keypair.shielded_address()?)
    }

    fn encrypt_confidential_transfer(
        &self,
        owner_pubkey: Pubkey,
        first_nullifier: &[u8; 32],
        sender_tag: ViewTag,
        sender: &TransferSenderPlaintext,
        recipients: &[ConfidentialRecipientSlot],
    ) -> std::result::Result<EncryptedTransfer, ClientError> {
        self.check_owner_pubkey(owner_pubkey)?;
        SyncWalletAuthority::encrypt_confidential_transfer(
            &self.keypair,
            owner_pubkey,
            first_nullifier,
            sender_tag,
            sender,
            recipients,
        )
    }

    fn encrypt_anonymous_transfer(
        &self,
        owner_pubkey: Pubkey,
        first_nullifier: &[u8; 32],
        sender_view_tag: ViewTag,
        sender: &AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> std::result::Result<EncryptedTransfer, ClientError> {
        self.check_owner_pubkey(owner_pubkey)?;
        SyncWalletAuthority::encrypt_anonymous_transfer(
            &self.keypair,
            owner_pubkey,
            first_nullifier,
            sender_view_tag,
            sender,
            recipients,
        )
    }

    fn encrypt_split(
        &self,
        owner_pubkey: Pubkey,
        first_nullifier: &[u8; 32],
        view_tag: ViewTag,
        bundle: &SplitBundlePlaintext,
    ) -> std::result::Result<EncryptedSplit, ClientError> {
        self.check_owner_pubkey(owner_pubkey)?;
        SyncWalletAuthority::encrypt_split(
            &self.keypair,
            owner_pubkey,
            first_nullifier,
            view_tag,
            bundle,
        )
    }

    fn request_user_approval(
        &self,
        request: ApprovalRequest,
    ) -> std::result::Result<(), ClientError> {
        self.check_owner_pubkey(request.owner_pubkey)
    }

    fn sign_p256(
        &self,
        owner_pubkey: Pubkey,
        message_hash: &[u8; 32],
    ) -> std::result::Result<P256Signature, ClientError> {
        self.check_owner_pubkey(owner_pubkey)?;
        SyncWalletAuthority::sign_p256(&self.keypair, owner_pubkey, message_hash)
    }

    fn spend_nullifier_key(
        &self,
        owner_pubkey: Pubkey,
    ) -> std::result::Result<NullifierKey, ClientError> {
        self.check_owner_pubkey(owner_pubkey)?;
        Ok(self.keypair.nullifier_key.clone())
    }
}

pub(super) fn run_init(opts: InitOptions) -> Result<()> {
    let config = CliConfigFile::load()?;
    let keypair_path = config_keypair_path(opts.path.as_deref(), &config);
    let material = if keypair_path.exists() {
        if opts.funding_keypair.is_some() {
            bail!(
                "wallet already exists at {}; remove it or pass --path to create a new wallet with --funding-keypair",
                keypair_path.display()
            );
        }
        load_existing_wallet(&keypair_path)?
    } else {
        let keypair = ShieldedKeypair::new()?;
        let funding = match opts.funding_keypair.as_deref() {
            Some(path) => load_solana_cli_keypair(Path::new(path))?,
            None => Keypair::new(),
        };
        save_wallet(&keypair_path, &keypair, &funding)?;
        WalletMaterial { keypair, funding }
    };

    let mut rpc = SolanaRpc::new(resolve_rpc_url(opts.rpc_url.as_deref(), &config));
    if let Some(lamports) = opts.airdrop_lamports {
        let signature = rpc.airdrop(&material.funding.pubkey(), lamports)?;
        println!("ok airdrop signature={signature}");
    }
    if opts.skip_register {
        println!("skipped user-registry registration (--skip-register)");
    } else if let Some(signature) = register_wallet_on_chain(&rpc, &material)? {
        println!("ok user_registry signature={signature}");
    }
    println!(
        "ok keypair {} owner_hash={} funding={}",
        keypair_path.display(),
        hex::encode(material.keypair.owner_hash()?),
        material.funding.pubkey()
    );
    Ok(())
}

pub(super) fn run_new(opts: NewWalletOptions) -> Result<()> {
    let path = wallet_file(&opts.name);
    if path.exists() {
        bail!(
            "wallet `{}` already exists at {}",
            opts.name,
            path.display()
        );
    }

    let keypair = ShieldedKeypair::new()?;
    let funding = match opts.funding_keypair.as_deref() {
        Some(funding_path) => load_solana_cli_keypair(Path::new(funding_path))?,
        None => Keypair::new(),
    };
    save_wallet(&path, &keypair, &funding)?;
    let material = WalletMaterial { keypair, funding };
    let owner = material.funding.pubkey();

    // `--fund-from` and `--register` both need a live RPC; only build one when a
    // network step is actually requested.
    let needs_rpc = opts.fund_from.is_some() || opts.register;
    if needs_rpc {
        let config = CliConfigFile::load()?;
        let rpc = SolanaRpc::new(resolve_rpc_url(opts.rpc_url.as_deref(), &config));

        if let Some(fund_from) = opts.fund_from.as_deref() {
            let sol = opts.fund_sol.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "--fund-from requires --fund-sol <SOL> to know how much to transfer"
                )
            })?;
            let lamports = parse_sol_amount(sol)?;
            let payer = load_solana_cli_keypair(Path::new(fund_from))?;
            let ix = system_transfer_ix(&payer.pubkey(), &owner, lamports);
            let signature = rpc.create_and_send_transaction(
                &[ix],
                Address::new_from_array(payer.pubkey().to_bytes()),
                &[&payer],
            )?;
            println!(
                "ok fund from={} amount={sol} signature={signature}",
                payer.pubkey()
            );
        } else if opts.fund_sol.is_some() {
            bail!("--fund-sol requires --fund-from <PATH> to name the source keypair");
        }

        if opts.register {
            if let Some(signature) = register_wallet_on_chain(&rpc, &material)? {
                println!("ok user_registry signature={signature}");
            } else {
                println!("ok user_registry already registered");
            }
        }
    } else if opts.fund_sol.is_some() {
        bail!("--fund-sol requires --fund-from <PATH> to name the source keypair");
    }

    println!(
        "ok wallet `{}` {} owner={} funding={}",
        opts.name,
        path.display(),
        owner,
        material.funding.pubkey()
    );
    Ok(())
}

pub(super) fn run_address(opts: WalletKeypairOptions) -> Result<()> {
    let config = CliConfigFile::load()?;
    let path = resolve_wallet_path(opts.wallet.as_deref(), opts.keypair.as_deref(), &config);
    if !path.exists() {
        bail!(
            "wallet not found at {}; run `zolana wallet new <name>` first",
            path.display()
        );
    }
    let material = load_existing_wallet(&path)?;
    println!("{}", material.owner_pubkey());
    Ok(())
}

pub(super) fn run_list() -> Result<()> {
    let dir = wallets_dir();
    let config = CliConfigFile::load()?;
    let default = config.wallet.as_deref();
    if !dir.exists() {
        println!("no wallets in {}", dir.display());
        return Ok(());
    }
    let mut names: Vec<String> = fs::read_dir(&dir)
        .with_context(|| format!("failed to read {}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                return None;
            }
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_string)
        })
        .collect();
    names.sort();
    if names.is_empty() {
        println!("no wallets in {}", dir.display());
        return Ok(());
    }
    for name in names {
        let marker = if Some(name.as_str()) == default {
            "*"
        } else {
            " "
        };
        match load_existing_wallet(&wallet_file(&name)) {
            Ok(material) => println!("{marker} {name}\t{}", material.owner_pubkey()),
            Err(err) => println!("{marker} {name}\t(unreadable: {err})"),
        }
    }
    Ok(())
}

pub(super) fn load_sender_from_resolved_sync(sync: &ResolvedSyncOptions) -> Result<WalletMaterial> {
    if !sync.keypair_path.exists() {
        bail!(
            "keypair not found at {}; run `zolana wallet init` first",
            sync.keypair_path.display()
        );
    }
    load_existing_wallet(&sync.keypair_path)
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

/// Load a standard Solana CLI keypair file (the JSON byte array written by
/// `solana-keygen`, e.g. ~/.config/solana/id.json). Accepts the 64-byte
/// `[secret||pubkey]` form or a bare 32-byte secret. Used to reuse an existing
/// funded key as the wallet's funding/fee-payer key.
pub(super) fn load_solana_cli_keypair(path: &Path) -> Result<Keypair> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read keypair {}", path.display()))?;
    let arr: Vec<u8> = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "{} is not a Solana keypair file (expected a JSON byte array)",
            path.display()
        )
    })?;
    let seed: [u8; 32] = match arr.len() {
        32 | 64 => arr[..32].try_into().expect("checked length"),
        n => bail!(
            "unexpected Solana keypair length {n} in {} (expected 32 or 64 bytes)",
            path.display()
        ),
    };
    let keypair = Keypair::new_from_array(seed);
    if arr.len() == 64 {
        let expected: [u8; 32] = arr[32..].try_into().expect("checked length");
        if keypair.pubkey().to_bytes() != expected {
            bail!(
                "keypair {} secret does not match its public key",
                path.display()
            );
        }
    }
    Ok(keypair)
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

    #[test]
    fn wallet_file_round_trips_real_keys() {
        let root = temp_root("zolana-cli-wallet-real");
        let wallet = root.join("alice.pid.json");
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
        let funding = Keypair::new();
        save_wallet(&wallet, &keypair, &funding).expect("save wallet");

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
        assert_eq!(loaded.funding.pubkey(), funding.pubkey());
    }

    #[test]
    fn load_solana_cli_keypair_reads_standard_and_bare_forms() {
        let root = temp_root("zolana-cli-solana-key");
        fs::create_dir_all(&root).unwrap();
        let keypair = Keypair::new();

        // Standard solana-keygen format: JSON array of the 64-byte [secret||pubkey].
        let full = root.join("id.json");
        fs::write(
            &full,
            serde_json::to_vec(&keypair.to_bytes().to_vec()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            load_solana_cli_keypair(&full).expect("64-byte").pubkey(),
            keypair.pubkey()
        );

        // A bare 32-byte secret seed is also accepted.
        let bare = root.join("id32.json");
        fs::write(
            &bare,
            serde_json::to_vec(&keypair.secret_bytes().to_vec()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            load_solana_cli_keypair(&bare).expect("32-byte").pubkey(),
            keypair.pubkey()
        );

        // A corrupted public-key tail is rejected.
        let mut bad = keypair.to_bytes().to_vec();
        bad[63] ^= 0xff;
        let bad_path = root.join("bad.json");
        fs::write(&bad_path, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(load_solana_cli_keypair(&bad_path).is_err());

        // A wrong-length array is rejected.
        let short = root.join("short.json");
        fs::write(&short, serde_json::to_vec(&vec![0u8; 16]).unwrap()).unwrap();
        assert!(load_solana_cli_keypair(&short).is_err());
    }

    #[test]
    fn wrong_owner_pubkey_is_rejected() {
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
        let funding = Keypair::new();
        let material = WalletMaterial { keypair, funding };
        let owner_pubkey = material.owner_pubkey();
        let wrong = Pubkey::new_unique();

        let err = match material.shielded_address(wrong) {
            Ok(_) => panic!("wrong owner_pubkey should fail"),
            Err(err) => err,
        };
        assert!(matches!(err, ClientError::AddressResolution(_)));
        assert!(err.to_string().contains(&owner_pubkey.to_string()));

        material
            .shielded_address(owner_pubkey)
            .expect("correct owner_pubkey should succeed");
    }

    #[test]
    fn wrong_owner_pubkey_rejected_for_spend_nullifier_key() {
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
        let funding = Keypair::new();
        let material = WalletMaterial { keypair, funding };
        let wrong = Pubkey::new_unique();

        let err = match material.spend_nullifier_key(wrong) {
            Ok(_) => panic!("wrong owner_pubkey should fail"),
            Err(err) => err,
        };
        assert!(matches!(err, ClientError::AddressResolution(_)));

        material
            .spend_nullifier_key(material.owner_pubkey())
            .expect("correct owner_pubkey should succeed");
    }

    #[test]
    fn wrong_owner_pubkey_rejected_for_sign_p256() {
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
        let funding = Keypair::new();
        let material = WalletMaterial { keypair, funding };
        let wrong = Pubkey::new_unique();
        let message_hash = [7u8; 32];

        let err = match material.sign_p256(wrong, &message_hash) {
            Ok(_) => panic!("wrong owner_pubkey should fail"),
            Err(err) => err,
        };
        assert!(matches!(err, ClientError::AddressResolution(_)));

        material
            .sign_p256(material.owner_pubkey(), &message_hash)
            .expect("correct owner_pubkey should succeed");
    }
}
