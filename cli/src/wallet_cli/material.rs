#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    AnonymousRecipientSlot, ApprovalRequest, EncryptedSplit, EncryptedTransfer,
    LocalWalletAuthority, P256Signature, SolanaRpc, SyncWalletAuthority,
};
use zolana_keypair::{
    shielded::ShieldedAddress, viewing_key::ViewTag, NullifierKey, ShieldedKeypair, SigningKey,
    ViewingKey,
};
use zolana_transaction::{
    serialization::{anonymous::AnonymousTransferSenderPlaintext, split::SplitBundlePlaintext},
    Address, AssetRegistry, SppProofOutputUtxo, TransactionError,
};

use super::{resolve::ResolvedSyncOptions, util::parse_hex_array};
use crate::{
    args::{AddressOptions, NewWalletOptions},
    cli_config::{resolve_keypair_path as config_keypair_path, resolve_rpc_url, CliConfigFile},
};

/// The only wallet file format this build reads or writes. There is no
/// migration path: a file carrying any other version is rejected outright.
const WALLET_FORMAT_VERSION: u8 = 1;

/// On-disk wallet identity. `mode` picks the rail and decides what the file
/// holds:
///
/// - `ed25519`: the Solana funding key IS the shielded identity. Its secret is
///   the signing key and the nullifier and viewing keys re-derive from it (flat
///   HKDF), so the file only caches the funding secret and stores no scalars.
/// - `p256`: an independent random shielded identity. Its signing and viewing
///   scalars derive from nothing else, so both are stored raw.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct KeypairFile {
    version: u8,
    mode: WalletMode,
    owner_hash_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_key_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    viewing_key_hex: Option<String>,
    funding_secret_hex: String,
    funding_pubkey: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum WalletMode {
    Ed25519,
    P256,
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
}

impl SyncWalletAuthority for WalletMaterial {
    fn solana_pubkey(&self) -> Address {
        Address::new_from_array(self.owner_pubkey().to_bytes())
    }

    fn shielded_address(&self) -> std::result::Result<ShieldedAddress, TransactionError> {
        Ok(self.keypair.shielded_address()?)
    }

    fn viewing_keys(&self) -> std::result::Result<Vec<ViewingKey>, TransactionError> {
        Ok(vec![self.keypair.viewing_key.clone()])
    }

    fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        outputs: &[SppProofOutputUtxo],
        assets: &AssetRegistry,
    ) -> std::result::Result<EncryptedTransfer, TransactionError> {
        SyncWalletAuthority::encrypt_confidential_transfer(
            &LocalWalletAuthority::new(self.solana_pubkey(), &self.keypair),
            first_nullifier,
            outputs,
            assets,
        )
    }

    fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: ViewTag,
        sender: &AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> std::result::Result<EncryptedTransfer, TransactionError> {
        SyncWalletAuthority::encrypt_anonymous_transfer(
            &LocalWalletAuthority::new(self.solana_pubkey(), &self.keypair),
            first_nullifier,
            sender_view_tag,
            sender,
            recipients,
        )
    }

    fn encrypt_split(
        &self,
        first_nullifier: &[u8; 32],
        view_tag: ViewTag,
        bundle: &SplitBundlePlaintext,
    ) -> std::result::Result<EncryptedSplit, TransactionError> {
        SyncWalletAuthority::encrypt_split(
            &LocalWalletAuthority::new(self.solana_pubkey(), &self.keypair),
            first_nullifier,
            view_tag,
            bundle,
        )
    }

    fn request_user_approval(
        &self,
        request: ApprovalRequest,
    ) -> std::result::Result<(), TransactionError> {
        debug_assert_eq!(request.solana_pubkey, self.solana_pubkey());
        Ok(())
    }

    fn sign_p256(
        &self,
        message_hash: &[u8; 32],
    ) -> std::result::Result<P256Signature, TransactionError> {
        SyncWalletAuthority::sign_p256(
            &LocalWalletAuthority::new(self.solana_pubkey(), &self.keypair),
            message_hash,
        )
    }

    fn spend_nullifier_key(&self) -> std::result::Result<NullifierKey, TransactionError> {
        Ok(self.keypair.nullifier_key.clone())
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

    // Both rails need a Solana funding key to pay fees. Importing an existing
    // keypair keeps the identity people already fund; a generated one is fully
    // recoverable from its own keypair file.
    let (funding, funding_source) = match opts.funding_keypair.as_deref() {
        Some(keypair) => (load_solana_cli_keypair(Path::new(keypair))?, "imported"),
        None => (Keypair::new(), "generated"),
    };

    // ed25519 (default): the funding key IS the shielded identity -- its secret
    // is the signing key and the nullifier and viewing keys derive from it, so
    // the file is a cache. p256 (`--p256`): an independent random shielded
    // identity whose scalars derive from nothing else and are stored on disk.
    let (keypair, mode) = if opts.p256 {
        (ShieldedKeypair::new()?, "p256")
    } else {
        (ShieldedKeypair::from_solana_keypair(&funding)?, "ed25519")
    };
    save_wallet(&path, &keypair, &funding)?;
    let material = WalletMaterial { keypair, funding };

    // `wallet new` is offline: it only writes the wallet file. Publishing the
    // shielded keys on chain is the explicit `wallet register` command, and
    // funding is left to the operator; `--airdrop-lamports` is a localnet
    // convenience that reaches the RPC only when explicitly requested.
    if let Some(lamports) = opts.airdrop_lamports {
        let mut rpc = SolanaRpc::new(resolve_rpc_url(opts.rpc_url.as_deref(), &config));
        let signature = rpc.airdrop(&material.funding.pubkey(), lamports)?;
        println!("ok airdrop signature={signature}");
    }

    println!(
        "ok wallet {} mode={mode} address={} funding={} funding_source={funding_source}",
        path.display(),
        hex::encode(material.keypair.owner_hash()?),
        material.funding.pubkey()
    );
    // `wallet new` only writes the file; point the operator at the explicit
    // on-chain step so the offline behavior is not mistaken for registration.
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
    if opts.funding {
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
    load_existing_wallet(&sync.keypair_path)
}

pub(super) fn load_existing_wallet(path: &Path) -> Result<WalletMaterial> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read wallet {}", path.display()))?;
    let file: KeypairFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse wallet {}", path.display()))?;
    if file.version != WALLET_FORMAT_VERSION {
        bail!(
            "wallet {} has unsupported wallet format version {}",
            path.display(),
            file.version
        );
    }
    let funding_bytes = parse_hex_array::<32>(&file.funding_secret_hex)?;
    let funding = Keypair::new_from_array(funding_bytes);
    let keypair = match file.mode {
        // The funding key is the identity: re-derive the shielded keypair (flat
        // HKDF) instead of trusting any cached scalars.
        WalletMode::Ed25519 => ShieldedKeypair::from_solana_keypair(&funding)?,
        // A P256 identity is random, so its scalars are stored and reloaded.
        WalletMode::P256 => p256_keypair_from_file(path, &file)?,
    };
    let expected_owner_hash = keypair.owner_hash()?;
    let stored_owner_hash = parse_hex_array::<32>(&file.owner_hash_hex)?;
    if stored_owner_hash != expected_owner_hash {
        bail!("wallet {} owner_hash does not match keys", path.display());
    }
    if funding.pubkey().to_string() != file.funding_pubkey {
        bail!(
            "wallet {} funding pubkey does not match secret",
            path.display()
        );
    }
    Ok(WalletMaterial { keypair, funding })
}

/// Reconstruct a P256 wallet from its stored signing and viewing scalars. Both
/// fields are required: a P256 identity is random, so its keys cannot be
/// derived from the funding secret the way the ed25519 rail derives them.
fn p256_keypair_from_file(path: &Path, file: &KeypairFile) -> Result<ShieldedKeypair> {
    let signing_hex = file
        .signing_key_hex
        .as_deref()
        .with_context(|| format!("wallet {} is missing signing_key_hex", path.display()))?;
    let viewing_hex = file
        .viewing_key_hex
        .as_deref()
        .with_context(|| format!("wallet {} is missing viewing_key_hex", path.display()))?;
    let signing = SigningKey::from_bytes(&parse_hex_array::<32>(signing_hex)?)?;
    let viewing = ViewingKey::from_bytes(&parse_hex_array::<32>(viewing_hex)?)?;
    Ok(ShieldedKeypair::from_keys(signing, viewing)?)
}

/// Load the JSON byte array written by `solana-keygen`. Both the standard
/// 64-byte `[secret || pubkey]` form and a bare 32-byte secret are accepted.
pub(super) fn load_solana_cli_keypair(path: &Path) -> Result<Keypair> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read keypair {}", path.display()))?;
    let values: Vec<u8> = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "{} is not a Solana keypair file (expected a JSON byte array)",
            path.display()
        )
    })?;
    keypair_from_solana_bytes(&values, path)
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

fn save_wallet(path: &Path, keypair: &ShieldedKeypair, funding: &Keypair) -> Result<()> {
    let file = if keypair.signing_key.is_ed25519() {
        // An ed25519 wallet's signing key must be the funding secret: that is
        // the whole point of the rail, and it is what the load path re-derives.
        if keypair.signing_key.secret_bytes().as_slice() != funding.secret_bytes().as_slice() {
            bail!("ed25519 wallet signing key must be the funding keypair");
        }
        KeypairFile {
            version: WALLET_FORMAT_VERSION,
            mode: WalletMode::Ed25519,
            owner_hash_hex: hex::encode(keypair.owner_hash()?),
            signing_key_hex: None,
            viewing_key_hex: None,
            funding_secret_hex: hex::encode(funding.secret_bytes()),
            funding_pubkey: funding.pubkey().to_string(),
        }
    } else {
        KeypairFile {
            version: WALLET_FORMAT_VERSION,
            mode: WalletMode::P256,
            owner_hash_hex: hex::encode(keypair.owner_hash()?),
            signing_key_hex: Some(hex::encode(keypair.signing_key.secret_bytes().as_slice())),
            viewing_key_hex: Some(hex::encode(keypair.viewing_key.secret_bytes().as_slice())),
            funding_secret_hex: hex::encode(funding.secret_bytes()),
            funding_pubkey: funding.pubkey().to_string(),
        }
    };
    write_json_secret_exclusive(path, &file)
}

/// Write a secret file without ever overwriting an existing one. The file is
/// created `0o600` up front (exclusive `create_new`), so a wallet key never
/// exists on disk with looser permissions, even briefly.
fn write_json_secret_exclusive<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    harden_secret_permissions(&file, path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn harden_secret_permissions(file: &File, path: &Path) -> Result<()> {
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    #[cfg(not(unix))]
    let _ = (file, path);
    Ok(())
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
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    // Create the file 0600 up front so a secret is never briefly world-readable
    // between open and chmod. `mode` applies only on creation, so still enforce
    // 0600 afterwards for the overwrite-an-existing-file case.
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
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
    fn p256_wallet_round_trips_and_stores_scalars() {
        let root = temp_root("zolana-cli-wallet-p256");
        let wallet = root.join("alice.pid.json");
        let keypair = ShieldedKeypair::new().expect("p256 keypair");
        let funding = Keypair::new();
        save_wallet(&wallet, &keypair, &funding).expect("save wallet");

        let file: KeypairFile =
            serde_json::from_slice(&fs::read(&wallet).unwrap()).expect("parse wallet");
        assert_eq!(file.version, WALLET_FORMAT_VERSION);
        assert_eq!(file.mode, WalletMode::P256);
        let expected_signing = hex::encode(keypair.signing_key.secret_bytes().as_slice());
        let expected_viewing = hex::encode(keypair.viewing_key.secret_bytes().as_slice());
        assert_eq!(
            file.signing_key_hex.as_deref(),
            Some(expected_signing.as_str())
        );
        assert_eq!(
            file.viewing_key_hex.as_deref(),
            Some(expected_viewing.as_str())
        );

        let loaded = load_existing_wallet(&wallet).expect("load wallet");
        assert_eq!(
            loaded.keypair.owner_hash().unwrap(),
            keypair.owner_hash().unwrap()
        );
        assert_ne!(loaded.funding.pubkey(), Pubkey::default());
        assert_eq!(loaded.funding.pubkey(), funding.pubkey());
    }

    #[test]
    fn ed25519_wallet_round_trips_and_stores_no_scalars() {
        let root = temp_root("zolana-cli-wallet-ed25519");
        let wallet = root.join("alice.pid.json");
        let funding = Keypair::new();
        let keypair = ShieldedKeypair::from_solana_keypair(&funding).expect("keypair");
        save_wallet(&wallet, &keypair, &funding).expect("save wallet");

        let file: KeypairFile =
            serde_json::from_slice(&fs::read(&wallet).unwrap()).expect("parse wallet");
        assert_eq!(file.version, WALLET_FORMAT_VERSION);
        assert_eq!(file.mode, WalletMode::Ed25519);
        assert_eq!(file.signing_key_hex, None);
        assert_eq!(file.viewing_key_hex, None);

        let loaded = load_existing_wallet(&wallet).expect("load wallet");
        assert_eq!(
            loaded.keypair.shielded_address().unwrap(),
            keypair.shielded_address().unwrap()
        );
        assert_eq!(loaded.funding.pubkey(), funding.pubkey());
    }

    #[test]
    fn ed25519_wallet_rejects_foreign_funding_key() {
        let root = temp_root("zolana-cli-wallet-ed25519-mismatch");
        let wallet = root.join("mismatch.pid.json");
        let keypair = ShieldedKeypair::from_solana_keypair(&Keypair::new()).unwrap();

        assert!(save_wallet(&wallet, &keypair, &Keypair::new()).is_err());
    }

    #[test]
    fn wallet_file_creation_never_overwrites() {
        let root = temp_root("zolana-cli-wallet-exclusive");
        let wallet = root.join("id.json");
        let first = ShieldedKeypair::new().expect("first shielded keypair");
        let first_funding = Keypair::new();
        save_wallet(&wallet, &first, &first_funding).expect("create wallet");
        let before = fs::read(&wallet).expect("read first wallet");

        assert!(save_wallet(&wallet, &ShieldedKeypair::new().unwrap(), &Keypair::new()).is_err());
        assert_eq!(fs::read(&wallet).expect("read unchanged wallet"), before);
    }

    #[cfg(unix)]
    #[test]
    fn wallet_file_is_private_when_created() {
        use std::os::unix::fs::PermissionsExt as _;

        let wallet = temp_root("zolana-cli-wallet-mode").join("id.json");
        save_wallet(
            &wallet,
            &ShieldedKeypair::new().expect("shielded keypair"),
            &Keypair::new(),
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
    fn load_solana_cli_keypair_reads_standard_and_bare_forms() {
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
            load_solana_cli_keypair(&full).expect("64-byte").pubkey(),
            keypair.pubkey()
        );

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

        let mut bad = keypair.to_bytes().to_vec();
        if let Some(byte) = bad.get_mut(63) {
            *byte ^= 0xff;
        }
        let bad_path = root.join("bad.json");
        fs::write(&bad_path, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(load_solana_cli_keypair(&bad_path).is_err());

        let short = root.join("short.json");
        fs::write(&short, serde_json::to_vec(&vec![0u8; 16]).unwrap()).unwrap();
        assert!(load_solana_cli_keypair(&short).is_err());

        let invalid = root.join("invalid.json");
        fs::write(&invalid, b"not json").unwrap();
        assert!(load_solana_cli_keypair(&invalid).is_err());
    }

    #[test]
    fn wallet_authority_is_bound_to_funding_owner() {
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
        let funding = Keypair::new();
        let material = WalletMaterial { keypair, funding };
        let message_hash = [7u8; 32];

        assert_eq!(material.solana_pubkey(), material.funding.pubkey());
        material.shielded_address().expect("shielded address");
        material.spend_nullifier_key().expect("nullifier key");
        material.sign_p256(&message_hash).expect("P256 signature");
    }
}
