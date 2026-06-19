use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use zolana_interface::event::DepositView;
use zolana_keypair::constants::{BLINDING_LEN, SALT_LEN};
use zolana_keypair::{random_salt, ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::transfer::{
    RecipientSlot, TransferEncryptedUtxos, TransferSenderPlaintext,
};
use zolana_transaction::wallet::{SyncTransaction, Wallet, DEFAULT_TAG_WINDOW};
use zolana_transaction::{
    owner_utxo_hash, utxo_hash, Address, AssetRegistry, Data, Utxo, SOL_MINT, TRANSFER,
};

use crate::args::{BalanceOptions, DepositOptions, TransferOptions, WithdrawOptions};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletFile {
    version: u8,
    signing_key_hex: String,
    viewing_key_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct LedgerFile {
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

    fn ensure_asset_id(&mut self, mint: Address) -> u64 {
        if mint == SOL_MINT {
            return 1;
        }
        if let Some(entry) = self
            .assets
            .iter()
            .find(|entry| parse_address(&entry.mint).ok() == Some(mint))
        {
            return entry.asset_id;
        }
        let asset_id = self.next_asset_id.max(2);
        self.next_asset_id = asset_id.saturating_add(1);
        self.assets.push(AssetEntry {
            asset_id,
            mint: format_address(mint),
        });
        asset_id
    }

    fn asset_registry(&self) -> Result<AssetRegistry> {
        let mut assets = AssetRegistry::default();
        for entry in &self.assets {
            let mint = parse_address(&entry.mint)?;
            assets.insert(entry.asset_id, mint)?;
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

    fn unique_blinding(&mut self) -> [u8; BLINDING_LEN] {
        self.next_counter = self.next_counter.saturating_add(1);
        let mut out = [0u8; BLINDING_LEN];
        out[0] = 0x42;
        out[1..9].copy_from_slice(&self.next_counter.to_be_bytes());
        out
    }

    fn next_signature(&mut self, prefix: &str) -> String {
        self.next_signature = self.next_signature.saturating_add(1);
        format!("{prefix}-{}", self.next_signature)
    }
}

pub(crate) fn run_deposit(opts: DepositOptions) -> Result<()> {
    if opts.amount == 0 {
        bail!("amount must be greater than zero");
    }
    let wallet_path = resolve_wallet_path(opts.paths.wallet.as_deref());
    let state_path = resolve_state_path(opts.paths.state_file.as_deref());
    let mint = parse_address(&opts.mint)?;

    let keypair = load_or_create_wallet(&wallet_path)?;
    let mut ledger = load_or_create_ledger(&state_path)?;
    ledger.ensure_asset_id(mint);

    let salt = random_salt();
    let blinding = keypair.viewing_key.derive_proofless_blinding(&salt)?;
    let owner_hash = keypair.owner_hash()?;
    let owner_utxo = owner_utxo_hash(&owner_hash, &blinding)?;
    let hash = utxo_hash(mint, opts.amount, &[0u8; 32], &[0u8; 32], None, &owner_utxo)?;

    ledger.proofless_deposits.push(StoredDepositView {
        view_tag_hex: hex::encode(keypair.recipient_bootstrap_view_tag()),
        utxo_hash_hex: hex::encode(hash),
        asset: format_address(mint),
        amount: opts.amount,
        owner_utxo_hash_hex: hex::encode(owner_utxo),
        salt_hex: hex::encode(salt),
        output_tree_hex: hex::encode([0u8; 32]),
        leaf_index: ledger.proofless_deposits.len() as u64,
    });
    let signature = ledger.next_signature("deposit");
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

    let sender_keypair = load_or_create_wallet(&wallet_path)?;
    let recipient_keypair = load_existing_wallet(&recipient_wallet_path)?;
    let mut ledger = load_or_create_ledger(&state_path)?;
    ledger.ensure_asset_id(mint);
    let assets = ledger.asset_registry()?;

    let sender_wallet = synced_wallet(&sender_keypair, &ledger)?;
    let tx = create_transfer_transaction(
        &sender_keypair,
        &sender_wallet,
        &recipient_keypair,
        &assets,
        mint,
        opts.amount,
        &mut || ledger.unique_blinding(),
    )?;
    ledger.transactions.push(runtime_sync_to_stored(&tx));
    let signature = ledger.next_signature("transfer");
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

    let sender_keypair = load_or_create_wallet(&wallet_path)?;
    let sink_keypair = ShieldedKeypair::new()?;
    let mut ledger = load_or_create_ledger(&state_path)?;
    ledger.ensure_asset_id(mint);
    let assets = ledger.asset_registry()?;

    let sender_wallet = synced_wallet(&sender_keypair, &ledger)?;
    let tx = create_transfer_transaction(
        &sender_keypair,
        &sender_wallet,
        &sink_keypair,
        &assets,
        mint,
        opts.amount,
        &mut || ledger.unique_blinding(),
    )?;
    ledger.transactions.push(runtime_sync_to_stored(&tx));
    let signature = ledger.next_signature("withdraw");
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
    let keypair = load_or_create_wallet(&wallet_path)?;
    let ledger = load_or_create_ledger(&state_path)?;
    let assets = ledger.asset_registry()?;
    let wallet = synced_wallet(&keypair, &ledger)?;
    let balances = wallet.balances(&assets, true)?;

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

fn create_transfer_transaction(
    sender_keypair: &ShieldedKeypair,
    sender_wallet: &Wallet,
    recipient_keypair: &ShieldedKeypair,
    assets: &AssetRegistry,
    mint: Address,
    amount: u64,
    unique_blinding: &mut impl FnMut() -> [u8; BLINDING_LEN],
) -> Result<SyncTransaction> {
    let mut nullifiers = Vec::new();
    let mut selected_amount = 0u64;
    for entry in &sender_wallet.utxos {
        if entry.spent || entry.utxo.asset != mint {
            continue;
        }
        nullifiers.push(entry.nullifier);
        selected_amount = selected_amount.saturating_add(entry.utxo.amount);
        if selected_amount >= amount {
            break;
        }
    }
    if selected_amount < amount {
        bail!("insufficient private balance");
    }

    let first_nullifier = nullifiers[0];
    let change_amount = selected_amount - amount;
    let recipient_viewing = recipient_keypair.viewing_pubkey();
    let output_blinding = unique_blinding();
    let change_blinding_seed = unique_blinding();
    let recipient_utxo = Utxo {
        owner: recipient_keypair.signing_pubkey(),
        asset: mint,
        amount,
        blinding: output_blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let recipient_plaintext =
        recipient_utxo.to_recipient_plaintext(sender_keypair.viewing_pubkey(), assets)?;
    let viewing_entry = sender_wallet
        .viewing_key_history
        .last()
        .ok_or_else(|| anyhow!("missing viewing key history"))?;
    let view_tag = match viewing_entry.known_recipients.get(&recipient_viewing) {
        Some(index) => sender_keypair.get_send_shared_view_tag(&recipient_viewing, *index)?,
        None => recipient_viewing.x(),
    };
    let sender_view_tag = sender_keypair.get_sender_view_tag(viewing_entry.tx_count)?;
    let asset_id = assets.asset_id(&mint)?;
    let sender_plaintext = if mint == SOL_MINT {
        TransferSenderPlaintext {
            owner_pubkey: sender_keypair.signing_pubkey(),
            spl_asset_id: asset_id,
            spl_amount: 0,
            sol_amount: change_amount,
            blinding_seed: change_blinding_seed,
            recipient_viewing_pks: vec![recipient_viewing],
            spl_data: Data::default(),
            sol_data: Data::default(),
        }
    } else {
        TransferSenderPlaintext {
            owner_pubkey: sender_keypair.signing_pubkey(),
            spl_asset_id: asset_id,
            spl_amount: change_amount,
            sol_amount: 0,
            blinding_seed: change_blinding_seed,
            recipient_viewing_pks: vec![recipient_viewing],
            spl_data: Data::default(),
            sol_data: Data::default(),
        }
    };
    let salt = random_salt();
    let tx_viewing_key = sender_keypair.get_transaction_viewing_key(&first_nullifier)?;
    let tx_viewing_pk = tx_viewing_key.pubkey();
    let sender_ciphertext = tx_viewing_key.encrypt_slot(
        &sender_keypair.viewing_pubkey(),
        &sender_plaintext.serialize()?,
        salt,
        0,
    )?;
    let recipient_ciphertext = tx_viewing_key.encrypt_slot(
        &recipient_viewing,
        &recipient_plaintext.serialize()?,
        salt,
        1,
    )?;
    let encrypted = TransferEncryptedUtxos {
        type_prefix: TRANSFER,
        tx_viewing_pk,
        salt,
        sender_ciphertext,
        recipient_slots: vec![RecipientSlot {
            view_tag,
            ciphertext: recipient_ciphertext,
        }],
    };

    Ok(SyncTransaction {
        encrypted_utxos: encrypted.serialize()?,
        sender_view_tag,
        nullifiers,
    })
}

fn synced_wallet(keypair: &ShieldedKeypair, ledger: &LedgerFile) -> Result<Wallet> {
    let mut wallet = Wallet::new_from_keypair(keypair)?;
    let transactions = ledger.sync_transactions()?;
    let proofless = ledger.deposit_views()?;
    wallet.sync_keypair(
        keypair,
        &transactions,
        &proofless,
        &ledger.asset_registry()?,
        unix_timestamp_now(),
        DEFAULT_TAG_WINDOW,
    )?;
    Ok(wallet)
}

fn load_or_create_wallet(path: &Path) -> Result<ShieldedKeypair> {
    if path.exists() {
        return load_existing_wallet(path);
    }
    let keypair = ShieldedKeypair::new()?;
    save_wallet(path, &keypair)?;
    println!("created wallet at {}", path.display());
    Ok(keypair)
}

fn load_existing_wallet(path: &Path) -> Result<ShieldedKeypair> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read wallet {}", path.display()))?;
    let file: WalletFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse wallet {}", path.display()))?;
    let signing_bytes = parse_hex_array::<32>(&file.signing_key_hex)?;
    let viewing_bytes = parse_hex_array::<32>(&file.viewing_key_hex)?;
    let signing = SigningKey::from_bytes(&signing_bytes)?;
    let viewing = ViewingKey::from_bytes(&viewing_bytes)?;
    ShieldedKeypair::from_keys(signing, viewing).map_err(Into::into)
}

fn save_wallet(path: &Path, keypair: &ShieldedKeypair) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let file = WalletFile {
        version: 1,
        signing_key_hex: hex::encode(keypair.signing_key.secret_bytes().as_slice()),
        viewing_key_hex: hex::encode(keypair.viewing_key.secret_bytes().as_slice()),
    };
    let serialized = serde_json::to_vec_pretty(&file)?;
    fs::write(path, serialized).with_context(|| format!("failed to write {}", path.display()))
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
    let serialized = serde_json::to_vec_pretty(ledger)?;
    fs::write(path, serialized).with_context(|| format!("failed to write {}", path.display()))
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
    let encrypted = hex::decode(&tx.encrypted_utxos_hex)
        .with_context(|| "invalid transaction encrypted_utxos hex")?;
    let sender_view_tag = parse_hex_array::<32>(&tx.sender_view_tag_hex)?;
    let mut nullifiers = Vec::with_capacity(tx.nullifiers_hex.len());
    for value in &tx.nullifiers_hex {
        nullifiers.push(parse_hex_array::<32>(value)?);
    }
    Ok(SyncTransaction {
        encrypted_utxos: encrypted,
        sender_view_tag,
        nullifiers,
    })
}

fn stored_deposit_to_runtime(value: &StoredDepositView) -> Result<DepositView> {
    let salt = parse_hex_array::<SALT_LEN>(&value.salt_hex)?;
    let asset = parse_address(&value.asset)?;
    Ok(DepositView {
        view_tag: parse_hex_array::<32>(&value.view_tag_hex)?,
        utxo_hash: parse_hex_array::<32>(&value.utxo_hash_hex)?,
        asset: asset.to_bytes(),
        amount: value.amount,
        zone_program_id: None,
        policy_data_hash: None,
        owner_utxo_hash: parse_hex_array::<32>(&value.owner_utxo_hash_hex)?,
        salt,
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

fn unix_timestamp_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::WalletPathOptions;

    fn temp_root(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        env::temp_dir().join(format!("{prefix}-{}-{stamp}", std::process::id()))
    }

    fn balance_for(wallet: &Path, state: &Path, mint: Address) -> Result<u64> {
        let keypair = load_existing_wallet(wallet)?;
        let ledger = load_or_create_ledger(state)?;
        let assets = ledger.asset_registry()?;
        let wallet = synced_wallet(&keypair, &ledger)?;
        Ok(wallet
            .balances(&assets, true)?
            .into_iter()
            .find_map(|balance| (balance.mint == mint).then_some(balance.amount))
            .unwrap_or(0))
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
        .expect("init bob wallet");
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
