use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use zolana_interface::event::DepositView;
use zolana_keypair::random_salt;
use zolana_keypair::{ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::transfer::{
    OutputCiphertext, RecipientSlot, TransferEncryptedUtxos, TransferSenderPlaintext,
    SENDER_SLOT_COUNT,
};
use zolana_transaction::wallet::SyncTransaction;
use zolana_transaction::{
    owner_utxo_hash, utxo_hash, Address, AssetRegistry, Data, Wallet, Utxo, DEFAULT_TAG_WINDOW,
    SOL_ASSET_ID, SOL_MINT, TRANSFER,
};

use crate::args::{
    BalanceOptions, DepositOptions, InitOptions, SyncOptions, TransferOptions, WalletCommand,
    WithdrawOptions,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct KeypairFile {
    version: u8,
    owner: String,
    signing_key_hex: String,
    viewing_key_hex: String,
}

struct WalletMaterial {
    owner: Address,
    keypair: ShieldedKeypair,
}

enum RecipientTarget {
    Address(Address),
    KeypairPath(PathBuf),
}

const MOCK_LOOKUP_PRIVATE_ADDRESS: &str = "11111111111111111111111111111111";

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
    scheme: u8,
    tx_viewing_pk_hex: String,
    salt_hex: String,
    output_slots: Vec<StoredOutputSlot>,
    nullifiers_hex: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredOutputSlot {
    view_tag_hex: String,
    payload_hex: String,
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

struct SyncContext {
    material: WalletMaterial,
    ledger: LedgerFile,
    wallet: Wallet,
    assets: AssetRegistry,
    report: zolana_transaction::SyncReport,
    state_path: PathBuf,
}

pub(crate) fn run_wallet(command: WalletCommand) -> Result<()> {
    match command {
        WalletCommand::Init(opts) => run_init(opts),
        WalletCommand::Sync(opts) => run_sync(opts),
        WalletCommand::Balance(opts) => run_balance(opts),
        WalletCommand::Deposit(opts) => run_deposit(opts),
        WalletCommand::Transfer(opts) => run_transfer(opts),
        WalletCommand::Withdraw(opts) => run_withdraw(opts),
    }
}

fn run_init(opts: InitOptions) -> Result<()> {
    let keypair_path = resolve_keypair_path(opts.path.as_deref());
    if keypair_path.exists() {
        let _ = load_existing_wallet(&keypair_path)?;
        println!("ok keypair {}", keypair_path.display());
        return Ok(());
    }
    let keypair = ShieldedKeypair::new()?;
    let owner = owner_from_keypair(&keypair);
    save_wallet(&keypair_path, owner, &keypair)?;
    println!("ok keypair {}", keypair_path.display());
    Ok(())
}

fn run_sync(opts: SyncOptions) -> Result<()> {
    let ctx = sync_context(&opts)?;
    println!(
        "ok sync stored={} unparsed={} undecryptable={}",
        ctx.report.stored_utxos, ctx.report.unparsed_transactions, ctx.report.undecryptable_candidates
    );
    Ok(())
}

fn run_deposit(opts: DepositOptions) -> Result<()> {
    if opts.amount == 0 {
        bail!("amount must be greater than zero");
    }
    let to = parse_pubkey_address(&opts.to)?;
    let mint = parse_address(&opts.mint)?;
    let mut ctx = sync_context(&opts.sync)?;
    let recipient = if to == ctx.material.owner {
        WalletMaterial {
            owner: ctx.material.owner,
            keypair: clone_keypair(&ctx.material.keypair)?,
        }
    } else {
        mock_lookup_wallet(to)?.ok_or_else(|| {
            anyhow::anyhow!(
                "recipient not found in mock lookup; use {} or your own keypair owner",
                MOCK_LOOKUP_PRIVATE_ADDRESS
            )
        })?
    };

    let _ = ensure_asset(&mut ctx.ledger, &mut ctx.assets, mint)?;
    let signature = next_signature(&mut ctx.ledger);
    let salt = random_salt();
    let blinding = recipient.keypair.viewing_key.derive_proofless_blinding(&salt)?;
    let recipient_owner_hash = recipient.keypair.owner_hash()?;
    let recipient_owner_utxo_hash = owner_utxo_hash(&recipient_owner_hash, &blinding)?;
    let hash = utxo_hash(
        mint,
        opts.amount,
        &[0u8; 32],
        &[0u8; 32],
        None,
        &recipient_owner_utxo_hash,
    )?;
    let deposit = DepositView {
        view_tag: recipient.keypair.recipient_bootstrap_view_tag(),
        utxo_hash: hash,
        asset: mint.to_bytes(),
        amount: opts.amount,
        zone_program_id: None,
        policy_data_hash: None,
        owner_utxo_hash: recipient_owner_utxo_hash,
        salt,
        program_data_hash: None,
        program_data: None,
        zone_data: None,
        output_tree: [0u8; 32],
        leaf_index: ctx.ledger.proofless_deposits.len() as u64,
    };
    ctx.ledger
        .proofless_deposits
        .push(runtime_deposit_to_stored(&deposit));
    save_ledger(&ctx.state_path, &ctx.ledger)?;
    println!(
        "ok deposit amount={} mint={} to={} signature={}",
        opts.amount,
        format_address(mint),
        Pubkey::new_from_array(to.to_bytes()),
        signature
    );
    Ok(())
}

fn run_transfer(opts: TransferOptions) -> Result<()> {
    if opts.amount == 0 {
        bail!("amount must be greater than zero");
    }
    let mint = parse_address(&opts.mint)?;
    let recipient_target = parse_recipient_target(&opts.to)?;
    let mut ctx = sync_context(&opts.sync)?;
    let sender_owner = ctx.material.owner;
    let sender_keypair = clone_keypair(&ctx.material.keypair)?;
    let recipient = match recipient_target {
        RecipientTarget::Address(address) => {
            if address == sender_owner {
                WalletMaterial {
                    owner: sender_owner,
                    keypair: clone_keypair(&ctx.material.keypair)?,
                }
            } else {
                mock_lookup_wallet(address)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "recipient not found in mock lookup; use {} or pass a local keypair path",
                        MOCK_LOOKUP_PRIVATE_ADDRESS
                    )
                })?
            }
        }
        RecipientTarget::KeypairPath(path) => load_existing_wallet(&path)?,
    };

    let signature = next_signature(&mut ctx.ledger);
    let tx = build_private_transfer(
        &mut ctx.ledger,
        &mut ctx.assets,
        &ctx.wallet,
        &sender_keypair,
        &recipient.keypair,
        mint,
        opts.amount,
    )?;
    ctx.ledger.transactions.push(runtime_sync_to_stored(&tx));
    save_ledger(&ctx.state_path, &ctx.ledger)?;
    println!(
        "ok transfer amount={} mint={} to={} signature={}",
        opts.amount,
        format_address(mint),
        Pubkey::new_from_array(recipient.owner.to_bytes()),
        signature
    );
    Ok(())
}

fn run_withdraw(opts: WithdrawOptions) -> Result<()> {
    if opts.amount == 0 {
        bail!("amount must be greater than zero");
    }
    let mint = parse_address(&opts.mint)?;
    let destination = parse_pubkey_address(&opts.to)?;
    let mut ctx = sync_context(&opts.sync)?;
    let sender = clone_keypair(&ctx.material.keypair)?;
    let sink = WalletMaterial {
        owner: Address::new_from_array(Pubkey::new_unique().to_bytes()),
        keypair: ShieldedKeypair::new()?,
    };

    let signature = next_signature(&mut ctx.ledger);
    let tx = build_private_transfer(
        &mut ctx.ledger,
        &mut ctx.assets,
        &ctx.wallet,
        &sender,
        &sink.keypair,
        mint,
        opts.amount,
    )?;
    ctx.ledger.transactions.push(runtime_sync_to_stored(&tx));
    ctx.ledger.withdrawals.push(WithdrawalRecord {
        signature: signature.clone(),
        to: format_address(destination),
        mint: format_address(mint),
        amount: opts.amount,
    });
    save_ledger(&ctx.state_path, &ctx.ledger)?;
    println!(
        "ok withdraw amount={} mint={} to={} signature={}",
        opts.amount,
        format_address(mint),
        Pubkey::new_from_array(destination.to_bytes()),
        signature
    );
    Ok(())
}

fn run_balance(opts: BalanceOptions) -> Result<()> {
    let ctx = sync_context(&opts.sync)?;
    let balances = ctx.wallet.balances(&ctx.assets, true)?;

    if let Some(mint) = &opts.mint {
        let mint = parse_address(mint)?;
        let amount = balances
            .iter()
            .find_map(|balance| (balance.mint == mint).then_some(balance.amount))
            .unwrap_or(0);
        println!("ok balance mint={} amount={}", format_address(mint), amount);
        return Ok(());
    }

    if balances.is_empty() {
        println!("ok balance mint=SOL amount=0");
        return Ok(());
    }

    for balance in balances {
        println!(
            "ok balance mint={} amount={}",
            format_address(balance.mint),
            balance.amount
        );
    }
    Ok(())
}

fn load_sender_from_sync(opts: &SyncOptions) -> Result<WalletMaterial> {
    let _ = (&opts.rpc_url, &opts.indexer_url);
    let keypair_path = resolve_keypair_path(opts.keypair.keypair.as_deref());
    if !keypair_path.exists() {
        bail!(
            "keypair not found at {}; run `zolana wallet init` first",
            keypair_path.display()
        );
    }
    load_existing_wallet(&keypair_path)
}

fn sync_context(opts: &SyncOptions) -> Result<SyncContext> {
    let material = load_sender_from_sync(opts)?;
    let state_path = resolve_state_path();
    let ledger = load_or_create_ledger(&state_path)?;
    let assets = ledger.asset_registry()?;
    let mut wallet = Wallet::new(clone_keypair(&material.keypair)?)?;
    let report = wallet.sync(
        &ledger.sync_transactions()?,
        &ledger.deposit_views()?,
        &assets,
        now_unix_ts(),
        DEFAULT_TAG_WINDOW,
    )?;
    Ok(SyncContext {
        material,
        ledger,
        wallet,
        assets,
        report,
        state_path,
    })
}

fn load_existing_wallet(path: &Path) -> Result<WalletMaterial> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read wallet {}", path.display()))?;
    let file: KeypairFile = serde_json::from_slice(&bytes)
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
    let file = KeypairFile {
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

fn resolve_keypair_path(value: Option<&str>) -> PathBuf {
    match value {
        Some(path) => PathBuf::from(path),
        None => default_config_dir().join("pid.json"),
    }
}

fn resolve_state_path() -> PathBuf {
    if let Some(path) = env::var_os("ZOLANA_INTERNAL_STATE_FILE") {
        return PathBuf::from(path);
    }
    default_config_dir().join("state.json")
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
        scheme: tx.scheme,
        tx_viewing_pk_hex: hex::encode(tx.tx_viewing_pk.as_bytes()),
        salt_hex: hex::encode(tx.salt),
        output_slots: tx
            .output_slots
            .iter()
            .map(|slot| StoredOutputSlot {
                view_tag_hex: hex::encode(slot.view_tag),
                payload_hex: hex::encode(&slot.data),
            })
            .collect(),
        nullifiers_hex: tx.nullifiers.iter().map(hex::encode).collect(),
    }
}

fn stored_sync_to_runtime(tx: &StoredSyncTransaction) -> Result<SyncTransaction> {
    let tx_viewing_pk_bytes = parse_hex_array::<33>(&tx.tx_viewing_pk_hex)?;
    Ok(SyncTransaction {
        scheme: tx.scheme,
        tx_viewing_pk: zolana_keypair::P256Pubkey::from_bytes(tx_viewing_pk_bytes)?,
        salt: parse_hex_array::<16>(&tx.salt_hex)?,
        output_slots: tx
            .output_slots
            .iter()
            .map(|slot| {
                Ok(OutputCiphertext {
                    view_tag: parse_hex_array::<32>(&slot.view_tag_hex)?,
                    data: hex::decode(&slot.payload_hex)
                        .with_context(|| "invalid transaction output slot payload hex")?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
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

fn parse_pubkey_address(value: &str) -> Result<Address> {
    let pubkey = value
        .parse::<Pubkey>()
        .with_context(|| format!("invalid pubkey `{value}`"))?;
    Ok(Address::new_from_array(pubkey.to_bytes()))
}

fn parse_recipient_target(value: &str) -> Result<RecipientTarget> {
    let path = PathBuf::from(value);
    if path.exists() {
        Ok(RecipientTarget::KeypairPath(path))
    } else {
        Ok(RecipientTarget::Address(parse_pubkey_address(value)?))
    }
}

fn owner_from_keypair(keypair: &ShieldedKeypair) -> Address {
    let mut owner_bytes = [0u8; 32];
    owner_bytes.copy_from_slice(keypair.signing_key.secret_bytes().as_slice());
    Address::new_from_array(owner_bytes)
}

fn mock_lookup_wallet(owner: Address) -> Result<Option<WalletMaterial>> {
    let mock = parse_pubkey_address(MOCK_LOOKUP_PRIVATE_ADDRESS)?;
    if owner != mock {
        return Ok(None);
    }
    let mut signing_bytes = [0u8; 32];
    signing_bytes[31] = 1;
    let mut viewing_bytes = [0u8; 32];
    viewing_bytes[31] = 2;
    let signing = SigningKey::from_bytes(&signing_bytes)?;
    let viewing = ViewingKey::from_bytes(&viewing_bytes)?;
    let keypair = ShieldedKeypair::from_keys(signing, viewing)?;
    Ok(Some(WalletMaterial { owner, keypair }))
}

fn clone_keypair(keypair: &ShieldedKeypair) -> Result<ShieldedKeypair> {
    let mut signing = [0u8; 32];
    signing.copy_from_slice(keypair.signing_key.secret_bytes().as_slice());
    let mut viewing = [0u8; 32];
    viewing.copy_from_slice(keypair.viewing_key.secret_bytes().as_slice());
    ShieldedKeypair::from_keys(
        SigningKey::from_bytes(&signing)?,
        ViewingKey::from_bytes(&viewing)?,
    )
    .map_err(Into::into)
}

fn next_signature(ledger: &mut LedgerFile) -> String {
    ledger.next_signature = ledger.next_signature.saturating_add(1);
    format!("sig-{}", ledger.next_signature)
}

fn next_blinding_seed(ledger: &mut LedgerFile) -> [u8; 31] {
    ledger.next_counter = ledger.next_counter.saturating_add(1);
    let bytes = ledger.next_counter.to_be_bytes();
    let mut out = [0u8; 31];
    for (i, b) in out.iter_mut().enumerate() {
        *b = bytes[i % bytes.len()] ^ ((i as u8).wrapping_mul(17));
    }
    out
}

fn ensure_asset(ledger: &mut LedgerFile, assets: &mut AssetRegistry, mint: Address) -> Result<u64> {
    if mint == SOL_MINT {
        return Ok(SOL_ASSET_ID);
    }
    if let Ok(asset_id) = assets.asset_id(&mint) {
        return Ok(asset_id);
    }
    let asset_id = ledger.next_asset_id.max(2);
    ledger.next_asset_id = asset_id.saturating_add(1);
    assets.insert(asset_id, mint)?;
    ledger.assets.push(AssetEntry {
        asset_id,
        mint: format_address(mint),
    });
    Ok(asset_id)
}

fn build_private_transfer(
    ledger: &mut LedgerFile,
    assets: &mut AssetRegistry,
    wallet: &Wallet,
    sender: &ShieldedKeypair,
    recipient: &ShieldedKeypair,
    mint: Address,
    amount: u64,
) -> Result<SyncTransaction> {
    let mut selected_nullifiers = Vec::new();
    let mut selected_amount = 0u64;
    for entry in &wallet.utxos {
        if entry.spent || entry.utxo.asset != mint {
            continue;
        }
        selected_nullifiers.push(entry.nullifier);
        selected_amount = selected_amount.saturating_add(entry.utxo.amount);
        if selected_amount >= amount {
            break;
        }
    }
    if selected_amount < amount {
        bail!("insufficient private balance");
    }
    let first_nullifier = *selected_nullifiers
        .first()
        .ok_or_else(|| anyhow::anyhow!("no spendable utxo found"))?;
    let change_amount = selected_amount - amount;
    let asset_id = ensure_asset(ledger, assets, mint)?;
    let recipient_utxo = Utxo {
        owner: recipient.signing_pubkey(),
        asset: mint,
        amount,
        blinding: next_blinding_seed(ledger),
        zone_program_id: None,
        data: Data::default(),
    };
    let recipient_plaintext =
        recipient_utxo.to_recipient_plaintext(sender.viewing_pubkey(), assets)?;

    let viewing_entry = wallet
        .viewing_key_history
        .last()
        .ok_or_else(|| anyhow::anyhow!("wallet viewing history missing"))?;
    let recipient_viewing = recipient.viewing_pubkey();
    let view_tag = match viewing_entry.known_recipients.get(&recipient_viewing) {
        Some(index) => sender
            .viewing_key
            .get_send_shared_view_tag(&recipient_viewing, *index)?,
        None => recipient_viewing.x(),
    };
    let sender_view_tag = sender.viewing_key.get_sender_view_tag(viewing_entry.tx_count)?;

    let sender_plaintext = if mint == SOL_MINT {
        TransferSenderPlaintext {
            owner_pubkey: sender.signing_pubkey(),
            spl_asset_id: asset_id,
            spl_amount: 0,
            sol_amount: change_amount,
            blinding_seed: next_blinding_seed(ledger),
            recipient_viewing_pks: vec![recipient_viewing],
            spl_data: Data::default(),
            sol_data: Data::default(),
        }
    } else {
        TransferSenderPlaintext {
            owner_pubkey: sender.signing_pubkey(),
            spl_asset_id: asset_id,
            spl_amount: change_amount,
            sol_amount: 0,
            blinding_seed: next_blinding_seed(ledger),
            recipient_viewing_pks: vec![recipient_viewing],
            spl_data: Data::default(),
            sol_data: Data::default(),
        }
    };

    let tx_viewing = sender.get_transaction_viewing_key(&first_nullifier)?;
    let salt = random_salt();
    let sender_ciphertext = tx_viewing.encrypt_slot(
        &sender.viewing_pubkey(),
        &sender_plaintext.serialize()?,
        salt,
        0,
    )?;
    let recipient_ciphertext = tx_viewing.encrypt_slot(
        &recipient_viewing,
        &recipient_plaintext.serialize()?,
        salt,
        1,
    )?;
    let encrypted = TransferEncryptedUtxos {
        type_prefix: TRANSFER,
        tx_viewing_pk: tx_viewing.pubkey(),
        salt,
        sender_ciphertext,
        recipient_slots: vec![RecipientSlot {
            view_tag,
            ciphertext: recipient_ciphertext,
        }],
    };
    let output_slots =
        encrypted.to_output_ciphertexts(sender_view_tag, SENDER_SLOT_COUNT, SENDER_SLOT_COUNT + 1)?;
    Ok(SyncTransaction {
        scheme: TRANSFER,
        tx_viewing_pk: encrypted.tx_viewing_pk,
        salt,
        output_slots,
        nullifiers: selected_nullifiers,
    })
}

fn now_unix_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
    use crate::args::{
        BalanceOptions, DepositOptions, InitOptions, SyncOptions, TransferOptions, WalletCommand,
        WalletKeypairOptions, WithdrawOptions,
    };

    fn temp_root(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        env::temp_dir().join(format!("{prefix}-{}-{stamp}", std::process::id()))
    }

    fn balance_for(wallet: &Path, state: &Path, mint: Address) -> Result<u64> {
        std::env::set_var("ZOLANA_INTERNAL_STATE_FILE", state.display().to_string());
        let material = load_existing_wallet(wallet)?;
        let mut wallet_state = Wallet::new(clone_keypair(&material.keypair)?)?;
        let ledger = load_or_create_ledger(state)?;
        let assets = ledger.asset_registry()?;
        wallet_state.sync(
            &ledger.sync_transactions()?,
            &ledger.deposit_views()?,
            &assets,
            now_unix_ts(),
            DEFAULT_TAG_WINDOW,
        )?;
        let amount = wallet_state
            .balances(&assets, true)?
            .into_iter()
            .find_map(|balance| (balance.mint == mint).then_some(balance.amount))
            .unwrap_or(0);
        std::env::remove_var("ZOLANA_INTERNAL_STATE_FILE");
        Ok(amount)
    }

    #[test]
    fn wallet_commands_end_to_end() {
        let root = temp_root("zolana-cli-wallet");
        let alice_wallet = root.join("alice.pid.json");
        let bob_wallet = root.join("bob.pid.json");
        let state = root.join("state.json");
        std::env::set_var("ZOLANA_INTERNAL_STATE_FILE", state.display().to_string());

        run_wallet(WalletCommand::Init(InitOptions {
            path: Some(alice_wallet.display().to_string()),
        }))
        .expect("init alice");
        run_wallet(WalletCommand::Init(InitOptions {
            path: Some(bob_wallet.display().to_string()),
        }))
        .expect("init bob");
        run_wallet(WalletCommand::Deposit(DepositOptions {
            sync: SyncOptions {
                keypair: WalletKeypairOptions {
                    keypair: Some(alice_wallet.display().to_string()),
                },
                rpc_url: "http://127.0.0.1:8899".to_string(),
                indexer_url: "http://127.0.0.1:8784".to_string(),
            },
            to: Pubkey::new_from_array(load_existing_wallet(&alice_wallet).unwrap().owner.to_bytes())
                .to_string(),
            mint: "SOL".to_string(),
            amount: 100,
        }))
        .expect("deposit");
        run_wallet(WalletCommand::Transfer(TransferOptions {
            sync: SyncOptions {
                keypair: WalletKeypairOptions {
                    keypair: Some(alice_wallet.display().to_string()),
                },
                rpc_url: "http://127.0.0.1:8899".to_string(),
                indexer_url: "http://127.0.0.1:8784".to_string(),
            },
            to: bob_wallet.display().to_string(),
            mint: "SOL".to_string(),
            amount: 30,
        }))
        .expect("transfer");
        run_wallet(WalletCommand::Withdraw(WithdrawOptions {
            sync: SyncOptions {
                keypair: WalletKeypairOptions {
                    keypair: Some(alice_wallet.display().to_string()),
                },
                rpc_url: "http://127.0.0.1:8899".to_string(),
                indexer_url: "http://127.0.0.1:8784".to_string(),
            },
            to: Pubkey::new_unique().to_string(),
            mint: "SOL".to_string(),
            amount: 20,
        }))
        .expect("withdraw");
        run_wallet(WalletCommand::Balance(BalanceOptions {
            sync: SyncOptions {
                keypair: WalletKeypairOptions {
                    keypair: Some(alice_wallet.display().to_string()),
                },
                rpc_url: "http://127.0.0.1:8899".to_string(),
                indexer_url: "http://127.0.0.1:8784".to_string(),
            },
            mint: None,
        }))
        .expect("balance");

        assert_eq!(balance_for(&alice_wallet, &state, SOL_MINT).unwrap(), 50);
        assert_eq!(balance_for(&bob_wallet, &state, SOL_MINT).unwrap(), 30);
        std::env::remove_var("ZOLANA_INTERNAL_STATE_FILE");
    }
}
