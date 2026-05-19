use std::{collections::HashMap, fs, path::PathBuf};

use light_client::rpc::RpcError;
use serde::{Deserialize, Serialize};
use solana_sdk::{account::Account, pubkey::Pubkey};

#[derive(Debug, Serialize, Deserialize)]
struct AccountData {
    pubkey: String,
    account: AccountInfo,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccountInfo {
    lamports: u64,
    data: (String, String), // (data, encoding) where encoding is typically "base64"
    owner: String,
    executable: bool,
    #[serde(rename = "rentEpoch")]
    rent_epoch: u64,
}

pub fn find_accounts_dir() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("LIGHT_PROTOCOL_ACCOUNTS_DIR") {
        let path = PathBuf::from(path);
        if path.is_dir() {
            return Some(path);
        }
    }

    let cache = fixtures_cache_dir()?.join("accounts");
    cache.is_dir().then_some(cache)
}

fn fixtures_cache_dir() -> Option<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let root = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_string());
    let tag = fs::read_to_string(root.join(".fixtures-version"))
        .ok()?
        .trim()
        .to_string();
    if tag.is_empty() {
        return None;
    }
    let cache_root = std::env::var_os("ZOLANA_CACHE_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache/zolana")))?;
    Some(cache_root.join("fixtures").join(tag))
}

/// Load all accounts from the accounts directory
/// Returns a HashMap of Pubkey -> Account
pub fn load_all_accounts_from_dir() -> Result<HashMap<Pubkey, Account>, RpcError> {
    let accounts_dir = find_accounts_dir().ok_or_else(|| {
        RpcError::CustomError(
            "Failed to find account fixtures. Run `just fetch-fixtures` or set LIGHT_PROTOCOL_ACCOUNTS_DIR.".to_string(),
        )
    })?;

    let mut accounts = HashMap::new();

    let entries = fs::read_dir(&accounts_dir).map_err(|e| {
        RpcError::CustomError(format!(
            "Failed to read accounts directory at {:?}: {}",
            accounts_dir, e
        ))
    })?;

    for entry in entries {
        let entry = entry
            .map_err(|e| RpcError::CustomError(format!("Failed to read directory entry: {}", e)))?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            let contents = fs::read_to_string(&path).map_err(|e| {
                RpcError::CustomError(format!("Failed to read file {:?}: {}", path, e))
            })?;

            let account_data: AccountData = serde_json::from_str(&contents).map_err(|e| {
                RpcError::CustomError(format!(
                    "Failed to parse account JSON from {:?}: {}",
                    path, e
                ))
            })?;

            let pubkey = account_data
                .pubkey
                .parse::<Pubkey>()
                .map_err(|e| RpcError::CustomError(format!("Invalid pubkey: {}", e)))?;

            let owner = account_data
                .account
                .owner
                .parse::<Pubkey>()
                .map_err(|e| RpcError::CustomError(format!("Invalid owner pubkey: {}", e)))?;

            // Decode base64 data
            let data = if account_data.account.data.1 == "base64" {
                base64::decode(&account_data.account.data.0).map_err(|e| {
                    RpcError::CustomError(format!("Failed to decode base64 data: {}", e))
                })?
            } else {
                return Err(RpcError::CustomError(format!(
                    "Unsupported encoding: {}",
                    account_data.account.data.1
                )));
            };

            let account = Account {
                lamports: account_data.account.lamports,
                data,
                owner,
                executable: account_data.account.executable,
                rent_epoch: account_data.account.rent_epoch,
            };

            accounts.insert(pubkey, account);
        }
    }

    Ok(accounts)
}

/// Load a specific account by pubkey from the accounts directory
/// Optionally provide a prefix for the filename (e.g. "address_merkle_tree")
pub fn load_account_from_dir(pubkey: &Pubkey, prefix: Option<&str>) -> Result<Account, RpcError> {
    let accounts_dir = find_accounts_dir().ok_or_else(|| {
        RpcError::CustomError(
            "Failed to find account fixtures. Run `just fetch-fixtures` or set LIGHT_PROTOCOL_ACCOUNTS_DIR.".to_string(),
        )
    })?;

    let filename = if let Some(prefix) = prefix {
        format!("{}_{}.json", prefix, pubkey)
    } else {
        format!("{}.json", pubkey)
    };
    let path = accounts_dir.join(&filename);

    let contents = fs::read_to_string(&path).map_err(|e| {
        RpcError::CustomError(format!("Failed to read account file {:?}: {}", path, e))
    })?;

    let account_data: AccountData = serde_json::from_str(&contents).map_err(|e| {
        RpcError::CustomError(format!(
            "Failed to parse account JSON from {:?}: {}",
            path, e
        ))
    })?;

    let owner = account_data
        .account
        .owner
        .parse::<Pubkey>()
        .map_err(|e| RpcError::CustomError(format!("Invalid owner pubkey: {}", e)))?;

    // Decode base64 data
    let data = if account_data.account.data.1 == "base64" {
        base64::decode(&account_data.account.data.0)
            .map_err(|e| RpcError::CustomError(format!("Failed to decode base64 data: {}", e)))?
    } else {
        return Err(RpcError::CustomError(format!(
            "Unsupported encoding: {}",
            account_data.account.data.1
        )));
    };

    Ok(Account {
        lamports: account_data.account.lamports,
        data,
        owner,
        executable: account_data.account.executable,
        rent_epoch: account_data.account.rent_epoch,
    })
}
