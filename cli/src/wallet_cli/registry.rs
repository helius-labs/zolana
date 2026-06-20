use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_keypair::{P256Pubkey, PublicKey, ShieldedAddress};

use crate::args::SyncOptions;

use super::material::{
    load_recipient_wallet, resolve_keypair_path, write_json_secret, WalletMaterial,
};
use super::util::parse_hex_array;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(super) struct LocalUserRegistryFile {
    pub(super) version: u8,
    pub(super) records: HashMap<String, LocalUserRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct LocalUserRecord {
    owner_p256_hex: Option<String>,
    nullifier_pubkey_hex: String,
    viewing_pubkey_hex: String,
}

pub(super) struct RecipientLookup {
    pub(super) owner: Pubkey,
    pub(super) address: ShieldedAddress,
    pub(super) view_tag: [u8; 32],
}

pub(super) fn resolve_transfer_recipient(
    value: &str,
    opts: &SyncOptions,
) -> Result<RecipientLookup> {
    if let Ok(owner) = value.parse::<Pubkey>() {
        let keypair_path = resolve_keypair_path(opts.keypair.keypair.as_deref());
        return lookup_registered_recipient(&local_user_registry_path(&keypair_path), &owner);
    }

    let material = load_recipient_wallet(value)?;
    Ok(RecipientLookup {
        owner: material.funding.pubkey(),
        address: material.keypair.shielded_address()?,
        view_tag: material.keypair.recipient_bootstrap_view_tag(),
    })
}

pub(super) fn register_wallet_locally(
    keypair_path: &Path,
    material: &WalletMaterial,
) -> Result<()> {
    let path = local_user_registry_path(keypair_path);
    let mut registry = read_local_user_registry(&path)?;
    let owner = material.funding.pubkey().to_string();
    let owner_p256 = material.keypair.signing_pubkey().as_p256()?;
    let record = LocalUserRecord {
        owner_p256_hex: Some(hex::encode(owner_p256.as_bytes())),
        nullifier_pubkey_hex: hex::encode(material.keypair.nullifier_key.pubkey()?),
        viewing_pubkey_hex: hex::encode(material.keypair.viewing_pubkey().as_bytes()),
    };

    registry.records.insert(owner, record);
    registry.version = 1;
    // TODO(user-registry): replace this JSON write with the user_registry register instruction.
    // For now we stub with a local lookup.
    write_json_secret(&path, &registry)
}

fn lookup_registered_recipient(path: &Path, owner: &Pubkey) -> Result<RecipientLookup> {
    // TODO(user-registry): replace this JSON read with an RPC read of the user_registry PDA.
    let registry = read_local_user_registry(path)?;
    let record = registry.records.get(&owner.to_string()).ok_or_else(|| {
        anyhow::anyhow!(
            "recipient {owner} not found in {}; run `zolana wallet init` for that user first",
            path.display()
        )
    })?;
    let signing_pubkey = if let Some(owner_p256_hex) = &record.owner_p256_hex {
        PublicKey::from_p256(&P256Pubkey::from_bytes(parse_hex_array::<33>(
            owner_p256_hex,
        )?)?)
    } else {
        PublicKey::from_ed25519(&owner.to_bytes())
    };
    let viewing_pubkey =
        P256Pubkey::from_bytes(parse_hex_array::<33>(&record.viewing_pubkey_hex)?)?;
    let address = ShieldedAddress {
        signing_pubkey,
        nullifier_pubkey: parse_hex_array::<32>(&record.nullifier_pubkey_hex)?,
        viewing_pubkey,
    };
    Ok(RecipientLookup {
        owner: *owner,
        address,
        view_tag: viewing_pubkey.x(),
    })
}

pub(super) fn read_local_user_registry(path: &Path) -> Result<LocalUserRegistryFile> {
    if !path.exists() {
        return Ok(LocalUserRegistryFile {
            version: 1,
            records: HashMap::new(),
        });
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

pub(super) fn local_user_registry_path(keypair_path: &Path) -> PathBuf {
    keypair_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(super::material::default_config_dir)
        .join("user-registry.json")
}
