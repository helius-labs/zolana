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
    ApprovalRequest, ClientError, P256Signature, ScopedSpendWitness, SolanaRpc,
    SpendWitnessRequest, WalletAuthority,
};
use zolana_keypair::shielded::ShieldedAddress;
use zolana_keypair::viewing_key::ViewTag;
use zolana_keypair::{ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::transfer::{
    RecipientOutput, TransferEncryptedUtxos, TransferSenderPlaintext,
};
use zolana_transaction::TransactionEncryption;

use super::{
    registry::register_wallet_on_chain, resolve::ResolvedSyncOptions, util::parse_hex_array,
};
use crate::{
    args::InitOptions,
    cli_config::{resolve_keypair_path as config_keypair_path, resolve_rpc_url, CliConfigFile},
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

impl WalletAuthority for WalletMaterial {
    fn shielded_address(
        &self,
        owner_pubkey: Pubkey,
    ) -> std::result::Result<ShieldedAddress, ClientError> {
        self.check_owner_pubkey(owner_pubkey)?;
        Ok(self.keypair.shielded_address()?)
    }

    fn derive_sender_view_tag(
        &self,
        owner_pubkey: Pubkey,
        tx_count: u64,
    ) -> std::result::Result<ViewTag, ClientError> {
        self.check_owner_pubkey(owner_pubkey)?;
        Ok(self.keypair.get_sender_view_tag(tx_count)?)
    }

    fn encrypt_transfer(
        &self,
        owner_pubkey: Pubkey,
        first_nullifier: &[u8; 32],
        sender: &TransferSenderPlaintext,
        recipients: &[RecipientOutput],
    ) -> std::result::Result<TransferEncryptedUtxos, ClientError> {
        self.check_owner_pubkey(owner_pubkey)?;
        Ok(self
            .keypair
            .viewing_key
            .encrypt_transfer(first_nullifier, sender, recipients)?)
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
        WalletAuthority::sign_p256(&self.keypair, owner_pubkey, message_hash)
    }

    fn create_spend_witness(
        &self,
        owner_pubkey: Pubkey,
        request: SpendWitnessRequest,
    ) -> std::result::Result<ScopedSpendWitness, ClientError> {
        self.check_owner_pubkey(owner_pubkey)?;
        ScopedSpendWitness::from_nullifier_key(&request, &self.keypair.nullifier_key)
    }
}

pub(super) fn run_init(opts: InitOptions) -> Result<()> {
    let config = CliConfigFile::load()?;
    let keypair_path = config_keypair_path(opts.path.as_deref(), &config);
    let material = if keypair_path.exists() {
        load_existing_wallet(&keypair_path)?
    } else {
        let keypair = ShieldedKeypair::new()?;
        let funding = Keypair::new();
        save_wallet(&keypair_path, &keypair, &funding)?;
        WalletMaterial { keypair, funding }
    };

    let mut rpc = SolanaRpc::new(resolve_rpc_url(opts.rpc_url.as_deref(), &config));
    if let Some(lamports) = opts.airdrop_lamports {
        let signature = rpc.airdrop(&material.funding.pubkey(), lamports)?;
        println!("ok airdrop signature={signature}");
    }
    if let Some(signature) = register_wallet_on_chain(&rpc, &material)? {
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

    use zolana_keypair::constants::BLINDING_LEN;

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
    fn wrong_owner_pubkey_rejected_for_spend_witness() {
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
        let funding = Keypair::new();
        let material = WalletMaterial { keypair, funding };
        let wrong = Pubkey::new_unique();
        let request = SpendWitnessRequest::new(zolana_transaction::Utxo {
            owner: material.keypair.signing_pubkey(),
            asset: zolana_transaction::SOL_MINT,
            amount: 1,
            blinding: [1u8; BLINDING_LEN],
            zone_program_id: None,
            data: zolana_transaction::Data::default(),
        });

        let err = match material.create_spend_witness(wrong, request.clone()) {
            Ok(_) => panic!("wrong owner_pubkey should fail"),
            Err(err) => err,
        };
        assert!(matches!(err, ClientError::AddressResolution(_)));

        material
            .create_spend_witness(material.owner_pubkey(), request)
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
