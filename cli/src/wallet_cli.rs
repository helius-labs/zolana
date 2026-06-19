use std::env;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use zolana_client::testing::{InMemoryPrivacyProvider, MockHost, ProviderParts};
use zolana_client::{
    CreatePrivateWalletInput, DecryptionMode, PrivacyClient, PrivateWalletId,
    SendPrivateTransferInput,
};
use zolana_interface::event::DepositView;
use zolana_keypair::{ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::wallet::SyncTransaction;
use zolana_transaction::{Address, AssetRegistry, SOL_ASSET_ID, SOL_MINT};

use crate::args::{BalanceOptions, DepositOptions, TransferOptions, WithdrawOptions};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletFile {
    version: u8,
    owner: String,
    signing_key_hex: String,
    viewing_key_hex: String,
}

struct WalletMaterial {
    owner: Address,
    keypair: ShieldedKeypair,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct LedgerFile {
    next_wallet_id: u64,
    next_asset_id: u64,
    next_counter: u64,
    next_signature: u64,
    assets: Vec<AssetEntry>,
    transactions: Vec<StoredSyncTransaction>,
    proofless_deposits: Vec<StoredDepositView>,
    withdrawals: Vec<WithdrawalRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AssetEntry {
    asset_id: u64,
    mint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredSyncTransaction {
    encrypted_utxos_hex: String,
    sender_view_tag_hex: String,
    nullifiers_hex: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredDepositView {
    view_tag_hex: String,
    utxo_hash_hex: String,
    asset: String,
    amount: u64,
    owner_utxo_hash_hex: String,
    salt_hex: String,
    output_tree_hex: String,
    leaf_index: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WithdrawalRecord {
    signature: String,
    to: String,
    mint: String,
    amount: u64,
}

impl LedgerFile {
    fn initialize(mut self) -> Self {
        if self.next_asset_id < 2 {
            self.next_asset_id = 2;
        }
        self
    }

    fn asset_registry(&self) -> Result<AssetRegistry> {
        let mut assets = AssetRegistry::default();
        for entry in &self.assets {
            assets.insert(entry.asset_id, parse_address(&entry.mint)?)?;
        }
        Ok(assets)
    }

    fn sync_transactions(&self) -> Result<Vec<SyncTransaction>> {
        self.transactions
            .iter()
            .map(stored_sync_to_runtime)
            .collect()
    }

    fn deposit_views(&self) -> Result<Vec<DepositView>> {
        self.proofless_deposits
            .iter()
            .map(stored_deposit_to_runtime)
            .collect()
    }
}

pub(crate) fn run_deposit(opts: DepositOptions) -> Result<()> {
    if opts.amount == 0 {
        bail!("amount must be greater than zero");
    }
    let wallet_path = resolve_wallet_path(opts.paths.wallet.as_deref());
    let state_path = resolve_state_path(opts.paths.state_file.as_deref());
    let mint = parse_address(&opts.mint)?;

    let sender = load_or_create_wallet(&wallet_path)?;
    let mut ledger = load_or_create_ledger(&state_path)?;
    let provider = provider_from_ledger(&ledger)?;

    let signature = run_async(async {
        let (mut client, wallet_id) = ready_client(sender, provider.clone()).await?;
        client.deposit_proofless(wallet_id, mint, opts.amount).await
    })?;

    update_ledger_from_provider(&mut ledger, &provider)?;
    save_ledger(&state_path, &ledger)?;
    println!(
        "deposited {} {} ({signature})",
        opts.amount,
        format_address(mint)
    );
    Ok(())
}

pub(crate) fn run_transfer(opts: TransferOptions) -> Result<()> {
    if opts.amount == 0 {
        bail!("amount must be greater than zero");
    }
    let wallet_path = resolve_wallet_path(opts.paths.wallet.as_deref());
    let state_path = resolve_state_path(opts.paths.state_file.as_deref());
    let recipient_wallet_path = PathBuf::from(&opts.to_wallet);
    let mint = parse_address(&opts.mint)?;

    let sender = load_or_create_wallet(&wallet_path)?;
    let recipient = load_existing_wallet(&recipient_wallet_path)?;
    let recipient_owner = recipient.owner;
    let mut ledger = load_or_create_ledger(&state_path)?;
    let provider = provider_from_ledger(&ledger)?;

    let signature = run_async(async {
        let _ = ready_client(recipient, provider.clone()).await?;
        let (mut sender_client, sender_wallet_id) = ready_client(sender, provider.clone()).await?;
        sender_client.sync_private_wallet(sender_wallet_id).await?;
        let result = sender_client
            .send_private_transfer(SendPrivateTransferInput {
                private_wallet_id: sender_wallet_id,
                recipient: recipient_owner,
                mint,
                amount: opts.amount,
            })
            .await?;
        Ok::<String, anyhow::Error>(
            result
                .signatures
                .first()
                .cloned()
                .unwrap_or_else(|| "transfer-no-signature".to_string()),
        )
    })?;

    update_ledger_from_provider(&mut ledger, &provider)?;
    save_ledger(&state_path, &ledger)?;
    println!(
        "transferred {} {} ({signature})",
        opts.amount,
        format_address(mint)
    );
    Ok(())
}

pub(crate) fn run_withdraw(opts: WithdrawOptions) -> Result<()> {
    if opts.amount == 0 {
        bail!("amount must be greater than zero");
    }
    let wallet_path = resolve_wallet_path(opts.paths.wallet.as_deref());
    let state_path = resolve_state_path(opts.paths.state_file.as_deref());
    let mint = parse_address(&opts.mint)?;
    let _destination = parse_address(&opts.to)?;

    let sender = load_or_create_wallet(&wallet_path)?;
    let sink_owner = Address::new_from_array(Pubkey::new_unique().to_bytes());
    let sink = WalletMaterial {
        owner: sink_owner,
        keypair: ShieldedKeypair::new()?,
    };
    let mut ledger = load_or_create_ledger(&state_path)?;
    let provider = provider_from_ledger(&ledger)?;

    let signature = run_async(async {
        let _ = ready_client(sink, provider.clone()).await?;
        let (mut sender_client, sender_wallet_id) = ready_client(sender, provider.clone()).await?;
        sender_client.sync_private_wallet(sender_wallet_id).await?;
        let result = sender_client
            .send_private_transfer(SendPrivateTransferInput {
                private_wallet_id: sender_wallet_id,
                recipient: sink_owner,
                mint,
                amount: opts.amount,
            })
            .await?;
        Ok::<String, anyhow::Error>(
            result
                .signatures
                .first()
                .cloned()
                .unwrap_or_else(|| "withdraw-no-signature".to_string()),
        )
    })?;

    update_ledger_from_provider(&mut ledger, &provider)?;
    ledger.withdrawals.push(WithdrawalRecord {
        signature: signature.clone(),
        to: opts.to.clone(),
        mint: format_address(mint),
        amount: opts.amount,
    });
    save_ledger(&state_path, &ledger)?;
    println!(
        "withdrew {} {} to {} ({signature})",
        opts.amount,
        format_address(mint),
        opts.to
    );
    Ok(())
}

pub(crate) fn run_balance(opts: BalanceOptions) -> Result<()> {
    let wallet_path = resolve_wallet_path(opts.paths.wallet.as_deref());
    let state_path = resolve_state_path(opts.paths.state_file.as_deref());
    let wallet = load_or_create_wallet(&wallet_path)?;
    let ledger = load_or_create_ledger(&state_path)?;
    let provider = provider_from_ledger(&ledger)?;

    let balances = run_async(async {
        let (mut client, wallet_id) = ready_client(wallet, provider).await?;
        client.sync_private_wallet(wallet_id).await?;
        let private_balances = client.get_private_token_balances(wallet_id).await?;
        Ok::<_, anyhow::Error>(private_balances.balances)
    })?;

    if let Some(mint) = opts.mint {
        let mint = parse_address(&mint)?;
        let amount = balances
            .iter()
            .find_map(|balance| (balance.mint == mint).then_some(balance.amount))
            .unwrap_or(0);
        println!("{amount}");
        return Ok(());
    }

    if balances.is_empty() {
        println!("SOL: 0");
        return Ok(());
    }

    for balance in balances {
        println!("{}: {}", format_address(balance.mint), balance.amount);
    }
    Ok(())
}

async fn ready_client(
    wallet: WalletMaterial,
    provider: InMemoryPrivacyProvider,
) -> zolana_client::Result<(PrivacyClient, PrivateWalletId)> {
    let host = MockHost::new(wallet.keypair)?;
    let mut client = PrivacyClient::new_with_provider(wallet.owner, host, provider);
    let private_wallet = client
        .create_private_wallet(CreatePrivateWalletInput {
            inbox: wallet.owner,
            label: None,
            decryption_mode: DecryptionMode::Local,
        })
        .await?;
    Ok((client, private_wallet.id))
}

fn provider_from_ledger(ledger: &LedgerFile) -> Result<InMemoryPrivacyProvider> {
    Ok(InMemoryPrivacyProvider::from_parts(ProviderParts {
        next_wallet_id: ledger.next_wallet_id,
        next_asset_id: ledger.next_asset_id,
        next_counter: ledger.next_counter,
        next_signature: ledger.next_signature,
        transactions: ledger.sync_transactions()?,
        proofless_deposits: ledger.deposit_views()?,
        assets: ledger.asset_registry()?,
    }))
}

fn update_ledger_from_provider(
    ledger: &mut LedgerFile,
    provider: &InMemoryPrivacyProvider,
) -> Result<()> {
    let parts = provider.export_parts()?;
    ledger.next_wallet_id = parts.next_wallet_id;
    ledger.next_asset_id = parts.next_asset_id.max(2);
    ledger.next_counter = parts.next_counter;
    ledger.next_signature = parts.next_signature;
    ledger.transactions = parts
        .transactions
        .iter()
        .map(runtime_sync_to_stored)
        .collect();
    ledger.proofless_deposits = parts
        .proofless_deposits
        .iter()
        .map(runtime_deposit_to_stored)
        .collect();
    ledger.assets = parts
        .assets
        .entries()
        .into_iter()
        .filter(|(asset_id, _)| *asset_id != SOL_ASSET_ID)
        .map(|(asset_id, mint)| AssetEntry {
            asset_id,
            mint: format_address(mint),
        })
        .collect();
    Ok(())
}

fn run_async<T, E>(future: impl Future<Output = std::result::Result<T, E>>) -> Result<T>
where
    E: Into<anyhow::Error>,
{
    futures::executor::block_on(future).map_err(Into::into)
}

fn load_or_create_wallet(path: &Path) -> Result<WalletMaterial> {
    if path.exists() {
        return load_existing_wallet(path);
    }
    let keypair = ShieldedKeypair::new()?;
    let mut owner_bytes = [0u8; 32];
    owner_bytes.copy_from_slice(keypair.signing_key.secret_bytes().as_slice());
    let owner = Address::new_from_array(owner_bytes);
    save_wallet(path, owner, &keypair)?;
    println!("created wallet at {}", path.display());
    Ok(WalletMaterial { owner, keypair })
}

fn load_existing_wallet(path: &Path) -> Result<WalletMaterial> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read wallet {}", path.display()))?;
    let file: WalletFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse wallet {}", path.display()))?;
    let signing_bytes = parse_hex_array::<32>(&file.signing_key_hex)?;
    let viewing_bytes = parse_hex_array::<32>(&file.viewing_key_hex)?;
    let owner = parse_address(&file.owner)?;
    let signing = SigningKey::from_bytes(&signing_bytes)?;
    let viewing = ViewingKey::from_bytes(&viewing_bytes)?;
    let keypair = ShieldedKeypair::from_keys(signing, viewing)?;
    Ok(WalletMaterial { owner, keypair })
}

fn save_wallet(path: &Path, owner: Address, keypair: &ShieldedKeypair) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let file = WalletFile {
        version: 1,
        owner: format_address(owner),
        signing_key_hex: hex::encode(keypair.signing_key.secret_bytes().as_slice()),
        viewing_key_hex: hex::encode(keypair.viewing_key.secret_bytes().as_slice()),
    };
    fs::write(path, serde_json::to_vec_pretty(&file)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn load_or_create_ledger(path: &Path) -> Result<LedgerFile> {
    if !path.exists() {
        return Ok(LedgerFile::default().initialize());
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let ledger: LedgerFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(ledger.initialize())
}

fn save_ledger(path: &Path, ledger: &LedgerFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_vec_pretty(ledger)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn resolve_wallet_path(value: Option<&str>) -> PathBuf {
    match value {
        Some(path) => PathBuf::from(path),
        None => default_config_dir().join("wallet.json"),
    }
}

fn resolve_state_path(value: Option<&str>) -> PathBuf {
    match value {
        Some(path) => PathBuf::from(path),
        None => default_config_dir().join("state.json"),
    }
}

fn default_config_dir() -> PathBuf {
    if let Some(home) = env::var_os("HOME") {
        PathBuf::from(home).join(".config").join("zolana")
    } else {
        PathBuf::from(".zolana")
    }
}

fn runtime_sync_to_stored(tx: &SyncTransaction) -> StoredSyncTransaction {
    StoredSyncTransaction {
        encrypted_utxos_hex: hex::encode(&tx.encrypted_utxos),
        sender_view_tag_hex: hex::encode(tx.sender_view_tag),
        nullifiers_hex: tx.nullifiers.iter().map(hex::encode).collect(),
    }
}

fn stored_sync_to_runtime(tx: &StoredSyncTransaction) -> Result<SyncTransaction> {
    Ok(SyncTransaction {
        encrypted_utxos: hex::decode(&tx.encrypted_utxos_hex)
            .with_context(|| "invalid transaction encrypted_utxos hex")?,
        sender_view_tag: parse_hex_array::<32>(&tx.sender_view_tag_hex)?,
        nullifiers: tx
            .nullifiers_hex
            .iter()
            .map(|value| parse_hex_array::<32>(value))
            .collect::<Result<Vec<_>>>()?,
    })
}

fn runtime_deposit_to_stored(value: &DepositView) -> StoredDepositView {
    StoredDepositView {
        view_tag_hex: hex::encode(value.view_tag),
        utxo_hash_hex: hex::encode(value.utxo_hash),
        asset: format_address(Address::new_from_array(value.asset)),
        amount: value.amount,
        owner_utxo_hash_hex: hex::encode(value.owner_utxo_hash),
        salt_hex: hex::encode(value.salt),
        output_tree_hex: hex::encode(value.output_tree),
        leaf_index: value.leaf_index,
    }
}

fn stored_deposit_to_runtime(value: &StoredDepositView) -> Result<DepositView> {
    Ok(DepositView {
        view_tag: parse_hex_array::<32>(&value.view_tag_hex)?,
        utxo_hash: parse_hex_array::<32>(&value.utxo_hash_hex)?,
        asset: parse_address(&value.asset)?.to_bytes(),
        amount: value.amount,
        zone_program_id: None,
        policy_data_hash: None,
        owner_utxo_hash: parse_hex_array::<32>(&value.owner_utxo_hash_hex)?,
        salt: parse_hex_array::<16>(&value.salt_hex)?,
        program_data_hash: None,
        program_data: None,
        zone_data: None,
        output_tree: parse_hex_array::<32>(&value.output_tree_hex)?,
        leaf_index: value.leaf_index,
    })
}

fn parse_address(value: &str) -> Result<Address> {
    if value.eq_ignore_ascii_case("SOL") {
        return Ok(SOL_MINT);
    }
    if let Ok(pubkey) = value.parse::<Pubkey>() {
        return Ok(Address::new_from_array(pubkey.to_bytes()));
    }
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(trimmed).with_context(|| {
        format!("invalid address `{value}` (expected base58 pubkey or 32-byte hex)")
    })?;
    if bytes.len() != 32 {
        bail!("invalid address `{value}`: expected 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Address::new_from_array(out))
}

fn format_address(address: Address) -> String {
    if address == SOL_MINT {
        return "SOL".to_string();
    }
    Pubkey::new_from_array(address.to_bytes()).to_string()
}

fn parse_hex_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value).with_context(|| "invalid hex string")?;
    if bytes.len() != N {
        bail!(
            "invalid hex length: expected {N} bytes, got {}",
            bytes.len()
        );
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::args::WalletPathOptions;

    fn temp_root(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        env::temp_dir().join(format!("{prefix}-{}-{stamp}", std::process::id()))
    }

    fn balance_for(wallet: &Path, state: &Path, mint: Address) -> Result<u64> {
        let wallet = load_existing_wallet(wallet)?;
        let ledger = load_or_create_ledger(state)?;
        let provider = provider_from_ledger(&ledger)?;
        run_async(async {
            let (mut client, wallet_id) = ready_client(wallet, provider).await?;
            client.sync_private_wallet(wallet_id).await?;
            let balances = client.get_private_token_balances(wallet_id).await?;
            Ok::<_, anyhow::Error>(
                balances
                    .balances
                    .into_iter()
                    .find_map(|balance| (balance.mint == mint).then_some(balance.amount))
                    .unwrap_or(0),
            )
        })
    }

    #[test]
    fn deposit_transfer_withdraw_end_to_end() {
        let root = temp_root("zolana-cli-wallet");
        let alice_wallet = root.join("alice.json");
        let bob_wallet = root.join("bob.json");
        let state = root.join("state.json");

        run_balance(BalanceOptions {
            paths: WalletPathOptions {
                wallet: Some(bob_wallet.display().to_string()),
                state_file: Some(state.display().to_string()),
            },
            mint: None,
        })
        .expect("init bob");
        run_deposit(DepositOptions {
            paths: WalletPathOptions {
                wallet: Some(alice_wallet.display().to_string()),
                state_file: Some(state.display().to_string()),
            },
            mint: "SOL".to_string(),
            amount: 100,
        })
        .expect("deposit");
        run_transfer(TransferOptions {
            paths: WalletPathOptions {
                wallet: Some(alice_wallet.display().to_string()),
                state_file: Some(state.display().to_string()),
            },
            to_wallet: bob_wallet.display().to_string(),
            mint: "SOL".to_string(),
            amount: 30,
        })
        .expect("transfer");
        run_withdraw(WithdrawOptions {
            paths: WalletPathOptions {
                wallet: Some(alice_wallet.display().to_string()),
                state_file: Some(state.display().to_string()),
            },
            mint: "SOL".to_string(),
            amount: 20,
            to: Pubkey::new_unique().to_string(),
        })
        .expect("withdraw");

        assert_eq!(balance_for(&alice_wallet, &state, SOL_MINT).unwrap(), 50);
        assert_eq!(balance_for(&bob_wallet, &state, SOL_MINT).unwrap(), 30);
    }
}
