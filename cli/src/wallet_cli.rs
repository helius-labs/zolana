use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    CircuitType, InputCommitment, InputTreeIndices, ProofCompressed, ProverClient, Rpc,
    ShieldedTransaction, SolanaRpc, SpendProof, SpendUtxo, StateInclusionProof, Transaction,
    WithdrawalTarget, ZolanaIndexer, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_interface::event::{
    indexed_events_from_instruction_groups, proofless_output, DepositView,
};
use zolana_interface::instruction::{
    CreateProtocolConfig, CreateTree, Deposit, Transact, TransactSolWithdrawal, TransactWithdrawal,
};
use zolana_interface::{pda, state::tree_account_size, PROGRAM_ID_PUBKEY};
use zolana_keypair::random_salt;
use zolana_keypair::{
    P256Pubkey, PublicKey, ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey,
};
use zolana_transaction::transfer::OutputCiphertext;
use zolana_transaction::{
    owner_utxo_hash, utxo_hash, Address, AssetRegistry, SyncTransaction, Wallet,
    DEFAULT_TAG_WINDOW, SOL_MINT, TRANSFER,
};

use crate::args::{
    BalanceOptions, CreateTreeOptions, DepositOptions, InitOptions, SyncOptions, TransferOptions,
    WalletCommand, WithdrawOptions,
};

const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const INDEXER_POLL: Duration = Duration::from_millis(500);
const TAG_QUERY_CHUNK: usize = 64;
const QUERY_LIMIT: u32 = 1_000;
const SYNC_ROUNDS: usize = 6;

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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct LocalUserRegistryFile {
    version: u8,
    records: HashMap<String, LocalUserRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LocalUserRecord {
    owner_p256_hex: Option<String>,
    nullifier_pubkey_hex: String,
    viewing_pubkey_hex: String,
}

struct WalletMaterial {
    keypair: ShieldedKeypair,
    funding: Keypair,
}

struct RecipientLookup {
    owner: Pubkey,
    address: ShieldedAddress,
    view_tag: [u8; 32],
}

struct SyncContext {
    material: WalletMaterial,
    wallet: Wallet,
    assets: AssetRegistry,
    report: zolana_transaction::SyncReport,
}

pub(crate) fn run_wallet(command: WalletCommand) -> Result<()> {
    match command {
        WalletCommand::Init(opts) => run_init(opts),
        WalletCommand::CreateTree(opts) => run_create_tree(opts),
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

fn run_create_tree(opts: CreateTreeOptions) -> Result<()> {
    let material = load_sender_from_sync(&opts.sync)?;
    let mut rpc = SolanaRpc::new(opts.sync.rpc_url);
    if opts.airdrop_lamports > 0 {
        let signature = rpc.airdrop(&material.funding.pubkey(), opts.airdrop_lamports)?;
        println!("ok airdrop signature={signature}");
    }

    let authority = material.funding.pubkey();
    let authority_address = Address::new_from_array(authority.to_bytes());
    let protocol_config = pda::protocol_config();
    if rpc
        .get_account(Address::new_from_array(protocol_config.to_bytes()))?
        .is_none()
    {
        let ix = CreateProtocolConfig {
            authority,
            protocol_authority: authority_address,
            tree_creation_authority: authority_address,
            tree_creation_is_permissionless: false,
            forester_authority: authority_address,
            zone_creation_authority: authority_address,
            zone_creation_is_permissionless: false,
            merge_authority: authority_address,
        }
        .instruction();
        let signature =
            rpc.create_and_send_transaction(&[ix], authority_address, &[&material.funding])?;
        println!("ok create_protocol_config signature={signature}");
    }

    let tree_keypair = load_or_create_solana_keypair(Path::new(&opts.tree_keypair))?;
    let tree_pubkey = tree_keypair.pubkey();
    if rpc
        .get_account(Address::new_from_array(tree_pubkey.to_bytes()))?
        .is_none()
    {
        let rent = rpc.get_minimum_balance_for_rent_exemption(tree_account_size())?;
        let ixs = vec![
            system_create_account_ix(
                &authority,
                &tree_pubkey,
                rent,
                tree_account_size() as u64,
                &PROGRAM_ID_PUBKEY,
            ),
            CreateTree {
                authority,
                tree: tree_pubkey,
                owner: authority,
            }
            .instruction(),
        ];
        let signature = rpc.create_and_send_transaction(
            &ixs,
            authority_address,
            &[&material.funding, &tree_keypair],
        )?;
        println!("ok create_tree signature={signature}");
    }

    println!("ok tree {}", tree_pubkey);
    Ok(())
}

fn run_sync(opts: SyncOptions) -> Result<()> {
    let ctx = sync_context(&opts)?;
    println!(
        "ok sync stored={} unparsed={} undecryptable={}",
        ctx.report.stored_utxos,
        ctx.report.unparsed_transactions,
        ctx.report.undecryptable_candidates
    );
    Ok(())
}

fn run_deposit(opts: DepositOptions) -> Result<()> {
    ensure_sol(&opts.mint)?;
    ensure_positive(opts.amount)?;
    let mut rpc = SolanaRpc::new(opts.network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(opts.network.sync.indexer_url.clone());
    let material = load_sender_from_sync(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &material, opts.network.airdrop_lamports)?;
    let recipient = load_recipient_wallet(&opts.to)?;
    let tree = parse_pubkey(&opts.network.tree)?;

    let salt = random_salt();
    let blinding = recipient
        .keypair
        .viewing_key
        .derive_proofless_blinding(&salt)?;
    let owner_hash = recipient.keypair.owner_hash()?;
    let owner_utxo_hash = owner_utxo_hash(&owner_hash, &blinding)?;
    let view_tag = recipient.keypair.recipient_bootstrap_view_tag();
    let deposit_hash = utxo_hash(
        SOL_MINT,
        opts.amount,
        &[0u8; 32],
        &[0u8; 32],
        None,
        &owner_utxo_hash,
    )?;
    let ix = Deposit {
        tree,
        depositor: material.funding.pubkey(),
        spl: None,
        view_tag,
        owner_utxo_hash,
        salt,
        public_amount: Some(opts.amount),
        program_data_hash: None,
        program_data: None,
        cpi_signer: None,
    }
    .instruction();
    let signature = rpc.create_and_send_transaction(
        &[ix],
        Address::new_from_array(material.funding.pubkey().to_bytes()),
        &[&material.funding],
    )?;
    wait_for_indexed_utxo(&indexer, view_tag, signature)?;
    println!(
        "ok deposit amount={} mint=SOL to={} utxo_hash={} signature={}",
        opts.amount,
        recipient.funding.pubkey(),
        hex::encode(deposit_hash),
        signature
    );
    Ok(())
}

fn run_transfer(opts: TransferOptions) -> Result<()> {
    ensure_sol(&opts.mint)?;
    ensure_positive(opts.amount)?;
    let mut rpc = SolanaRpc::new(opts.network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(opts.network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, opts.network.airdrop_lamports)?;
    let recipient = resolve_transfer_recipient(&opts.to, &opts.network.sync)?;
    let tree = parse_pubkey(&opts.network.tree)?;

    let sender_view_tag = next_sender_view_tag(&ctx)?;
    let inputs = select_inputs(&ctx, SOL_MINT, opts.amount)?;
    let mut tx = Transaction::new(
        ctx.material.keypair.shielded_address()?,
        inputs,
        Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
    );
    tx.send(
        &recipient.address,
        SOL_MINT,
        opts.amount,
        recipient.view_tag,
    )?;
    let signed = tx.sign(&ctx.material.keypair, &ctx.assets, sender_view_tag)?;
    let signature = submit_private_transaction(
        SubmitPrivateTx {
            rpc: &rpc,
            indexer: &indexer,
            material: &ctx.material,
            tree,
            prover_url: &opts.network.prover_url,
            withdrawal: None,
            wait_tag: sender_view_tag,
        },
        signed,
    )?;
    println!(
        "ok transfer amount={} mint=SOL to={} signature={}",
        opts.amount, recipient.owner, signature
    );
    Ok(())
}

fn run_withdraw(opts: WithdrawOptions) -> Result<()> {
    ensure_sol(&opts.mint)?;
    ensure_positive(opts.amount)?;
    let mut rpc = SolanaRpc::new(opts.network.sync.rpc_url.clone());
    let indexer = ZolanaIndexer::new(opts.network.sync.indexer_url.clone());
    let ctx = sync_context(&opts.network.sync)?;
    maybe_airdrop(&mut rpc, &ctx.material, opts.network.airdrop_lamports)?;
    let tree = parse_pubkey(&opts.network.tree)?;
    let destination = parse_pubkey(&opts.to)?;

    let sender_view_tag = next_sender_view_tag(&ctx)?;
    let inputs = select_inputs(&ctx, SOL_MINT, opts.amount)?;
    let mut tx = Transaction::new(
        ctx.material.keypair.shielded_address()?,
        inputs,
        Address::new_from_array(ctx.material.funding.pubkey().to_bytes()),
    );
    tx.withdraw(
        SOL_MINT,
        opts.amount,
        WithdrawalTarget::Sol {
            user_sol_account: Address::new_from_array(destination.to_bytes()),
        },
    )?;
    let signed = tx.sign(&ctx.material.keypair, &ctx.assets, sender_view_tag)?;
    let signature = submit_private_transaction(
        SubmitPrivateTx {
            rpc: &rpc,
            indexer: &indexer,
            material: &ctx.material,
            tree,
            prover_url: &opts.network.prover_url,
            withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal {
                recipient: destination,
            })),
            wait_tag: sender_view_tag,
        },
        signed,
    )?;
    println!(
        "ok withdraw amount={} mint=SOL to={} signature={}",
        opts.amount, destination, signature
    );
    Ok(())
}

fn run_balance(opts: BalanceOptions) -> Result<()> {
    let ctx = sync_context(&opts.sync)?;
    let balances = ctx.wallet.balances(&ctx.assets, true)?;

    if let Some(mint) = &opts.mint {
        ensure_sol(mint)?;
        let amount = balances
            .iter()
            .find_map(|balance| (balance.mint == SOL_MINT).then_some(balance.amount))
            .unwrap_or(0);
        println!("ok balance mint=SOL amount={amount}");
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

fn sync_context(opts: &SyncOptions) -> Result<SyncContext> {
    let material = load_sender_from_sync(opts)?;
    let rpc = SolanaRpc::new(opts.rpc_url.clone());
    let indexer = ZolanaIndexer::new(opts.indexer_url.clone());
    let assets = AssetRegistry::default();
    let (wallet, report) = sync_wallet(&material, &rpc, &indexer, &assets)?;
    Ok(SyncContext {
        material,
        wallet,
        assets,
        report,
    })
}

fn sync_wallet(
    material: &WalletMaterial,
    rpc: &SolanaRpc,
    indexer: &ZolanaIndexer,
    assets: &AssetRegistry,
) -> Result<(Wallet, zolana_transaction::SyncReport)> {
    let mut wallet = Wallet::new(clone_keypair(&material.keypair)?)?;
    let mut transactions: HashMap<String, SyncTransaction> = HashMap::new();
    let mut proofless_deposits: HashMap<String, DepositView> = HashMap::new();
    let mut report = zolana_transaction::SyncReport::default();

    for _ in 0..SYNC_ROUNDS {
        let before = (transactions.len(), proofless_deposits.len());
        let tags = wallet_query_tags(&wallet)?;
        fetch_shielded_transactions(indexer, &tags, &mut transactions)?;
        fetch_proofless_deposits(rpc, indexer, &tags, &mut proofless_deposits)?;

        let mut txs = transactions.values().cloned().collect::<Vec<_>>();
        txs.sort_by_key(|tx| tx.nullifiers.first().copied().unwrap_or_default());
        let mut deposits = proofless_deposits.values().cloned().collect::<Vec<_>>();
        deposits.sort_by_key(|deposit| (deposit.output_tree, deposit.leaf_index));
        report = wallet.sync(&txs, &deposits, assets, now_unix_ts(), DEFAULT_TAG_WINDOW)?;

        if before == (transactions.len(), proofless_deposits.len()) {
            break;
        }
    }

    Ok((wallet, report))
}

fn wallet_query_tags(wallet: &Wallet) -> Result<Vec<[u8; 32]>> {
    let mut tags = HashSet::new();
    for entry in &wallet.viewing_key_history {
        tags.insert(entry.key.recipient_bootstrap_view_tag());
        for n in 0..entry.tx_count.saturating_add(DEFAULT_TAG_WINDOW) {
            tags.insert(entry.key.get_sender_view_tag(n)?);
        }
        for n in 0..entry.request_count.saturating_add(DEFAULT_TAG_WINDOW) {
            tags.insert(entry.key.get_recipient_request_view_tag(n)?);
        }
        for (sender, count) in &entry.known_senders {
            for n in 0..count.saturating_add(DEFAULT_TAG_WINDOW) {
                tags.insert(entry.key.get_recipient_shared_view_tag(sender, n)?);
            }
        }
        for (recipient, count) in &entry.known_recipients {
            for n in 0..count.saturating_add(DEFAULT_TAG_WINDOW) {
                tags.insert(entry.key.get_send_shared_view_tag(recipient, n)?);
            }
        }
    }
    Ok(tags.into_iter().collect())
}

fn fetch_shielded_transactions(
    indexer: &ZolanaIndexer,
    tags: &[[u8; 32]],
    out: &mut HashMap<String, SyncTransaction>,
) -> Result<()> {
    for chunk in tags.chunks(TAG_QUERY_CHUNK) {
        let mut cursor = None;
        loop {
            let response = indexer.get_shielded_transactions_by_tags(
                chunk.to_vec(),
                cursor,
                Some(QUERY_LIMIT),
            )?;
            for tx in response.transactions {
                if tx.proofless {
                    continue;
                }
                let key = tx.tx_signature.to_string();
                out.entry(key).or_insert(convert_sync_transaction(tx)?);
            }
            cursor = response.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
    }
    Ok(())
}

fn fetch_proofless_deposits(
    rpc: &SolanaRpc,
    indexer: &ZolanaIndexer,
    tags: &[[u8; 32]],
    out: &mut HashMap<String, DepositView>,
) -> Result<()> {
    for chunk in tags.chunks(TAG_QUERY_CHUNK) {
        let mut cursor = None;
        loop {
            let response =
                indexer.get_encrypted_utxos_by_tags(chunk.to_vec(), cursor, Some(QUERY_LIMIT))?;
            for item in response.matches {
                if item.tx_viewing_pk.is_some() {
                    continue;
                }
                let key = item.tx_signature.to_string();
                if out.contains_key(&key) {
                    continue;
                }
                if let Some(view) =
                    proofless_deposit_from_signature(rpc, item.tx_signature, item.view_tag)?
                {
                    out.insert(key, view);
                }
            }
            cursor = response.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
    }
    Ok(())
}

fn convert_sync_transaction(tx: ShieldedTransaction) -> Result<SyncTransaction> {
    let tx_viewing_pk = tx
        .tx_viewing_pk
        .ok_or_else(|| anyhow::anyhow!("indexed transaction missing tx_viewing_pk"))?;
    let salt = tx
        .salt
        .ok_or_else(|| anyhow::anyhow!("indexed transaction missing salt"))?;
    Ok(SyncTransaction {
        scheme: TRANSFER,
        tx_viewing_pk,
        salt,
        output_slots: tx
            .output_slots
            .into_iter()
            .map(|slot| OutputCiphertext {
                view_tag: slot.view_tag,
                data: slot.payload,
            })
            .collect(),
        nullifiers: tx.nullifiers,
    })
}

fn proofless_deposit_from_signature(
    rpc: &SolanaRpc,
    signature: Signature,
    view_tag: [u8; 32],
) -> Result<Option<DepositView>> {
    let groups = rpc.fetch_confirmed_instruction_groups(&signature)?.groups;
    let events = indexed_events_from_instruction_groups(PROGRAM_ID_PUBKEY, &groups);
    for event in events {
        let Ok(general) = event.decoded else {
            continue;
        };
        let Ok(view) = proofless_output(&general) else {
            continue;
        };
        if view.view_tag == view_tag {
            return Ok(Some(view));
        }
    }
    Ok(None)
}

struct SubmitPrivateTx<'a> {
    rpc: &'a SolanaRpc,
    indexer: &'a ZolanaIndexer,
    material: &'a WalletMaterial,
    tree: Pubkey,
    prover_url: &'a str,
    withdrawal: Option<TransactWithdrawal>,
    wait_tag: [u8; 32],
}

fn submit_private_transaction(
    request: SubmitPrivateTx<'_>,
    signed: zolana_client::SignedTransaction,
) -> Result<Signature> {
    let commitments = signed.input_commitments()?;
    let (proofs, indices) = spend_proofs(request.indexer, request.tree, &commitments)?;
    let prover = ProverClient::new(request.prover_url.to_string());
    let proof = match signed.clone().into_prover(&proofs)? {
        CircuitType::P256(prover_inputs) => {
            let built = prover_inputs.build()?;
            prover.prove_transfer_p256(&built.inputs)?
        }
        CircuitType::Eddsa(prover_inputs) => {
            let built = prover_inputs.build()?;
            prover.prove_transfer(&built.inputs)?
        }
    };
    let proof_bytes = ProofCompressed::try_from(proof)?.to_transact_proof_bytes();
    let data = signed.into_transact_ix_data(proof_bytes, &indices)?;
    let ix = Transact {
        payer: request.material.funding.pubkey(),
        tree: request.tree,
        cpi_signer: None,
        withdrawal: request.withdrawal,
        data,
    }
    .instruction();
    let instructions = [
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        ix,
    ];
    let signature = request.rpc.create_and_send_transaction(
        &instructions,
        Address::new_from_array(request.material.funding.pubkey().to_bytes()),
        &[&request.material.funding],
    )?;
    wait_for_indexed_transaction(request.indexer, request.wait_tag, signature)?;
    Ok(signature)
}

fn spend_proofs(
    indexer: &ZolanaIndexer,
    tree: Pubkey,
    commitments: &[InputCommitment],
) -> Result<(Vec<SpendProof>, Vec<InputTreeIndices>)> {
    let tree_address = Address::new_from_array(tree.to_bytes());
    let leaves = commitments
        .iter()
        .map(|commitment| commitment.utxo_hash)
        .collect::<Vec<_>>();
    let nullifiers = commitments
        .iter()
        .map(|commitment| commitment.nullifier)
        .collect::<Vec<_>>();
    let state_proofs = indexer.get_merkle_proofs(tree_address, leaves)?.proofs;
    let nullifier_proofs = indexer
        .get_non_inclusion_proofs(tree_address, nullifiers)?
        .proofs;
    if state_proofs.len() != commitments.len() || nullifier_proofs.len() != commitments.len() {
        bail!("indexer returned incomplete input proofs");
    }

    let mut proofs = Vec::with_capacity(commitments.len());
    let mut indices = Vec::with_capacity(commitments.len());
    for (state, nullifier) in state_proofs.into_iter().zip(nullifier_proofs) {
        indices.push(InputTreeIndices {
            utxo_tree_root_index: state.root_index,
            nullifier_tree_root_index: nullifier.root_index,
            tree_index: 0,
            eddsa_signer_index: 0,
        });
        proofs.push(SpendProof {
            state: StateInclusionProof {
                path_elements: fixed_path::<STATE_TREE_HEIGHT>(state.path, "state path")?,
                leaf_index: state.leaf_index,
                root: state.root,
            },
            nullifier: zolana_client::NullifierNonInclusionProof {
                low_value: nullifier.low_element,
                next_value: nullifier.high_element,
                low_path_elements: fixed_path::<NULLIFIER_TREE_HEIGHT>(
                    nullifier.path,
                    "nullifier path",
                )?,
                low_leaf_index: nullifier.low_element_index,
                root: nullifier.root,
            },
        });
    }
    Ok((proofs, indices))
}

fn fixed_path<const N: usize>(path: Vec<[u8; 32]>, name: &str) -> Result<[[u8; 32]; N]> {
    let actual = path.len();
    path.try_into()
        .map_err(|_| anyhow::anyhow!("{name} length mismatch: expected {N}, got {actual}"))
}

fn select_inputs(ctx: &SyncContext, mint: Address, amount: u64) -> Result<Vec<SpendUtxo>> {
    let mut selected = Vec::new();
    let mut total = 0u64;
    for entry in &ctx.wallet.utxos {
        if entry.spent || entry.utxo.asset != mint {
            continue;
        }
        selected.push(SpendUtxo::from((entry.utxo.clone(), &ctx.material.keypair)));
        total = total
            .checked_add(entry.utxo.amount)
            .ok_or_else(|| anyhow::anyhow!("selected balance overflow"))?;
        if total >= amount {
            break;
        }
    }
    if total < amount {
        bail!("insufficient private balance: requested {amount}, available {total}");
    }
    Ok(selected)
}

fn next_sender_view_tag(ctx: &SyncContext) -> Result<[u8; 32]> {
    let entry = ctx
        .wallet
        .viewing_key_history
        .last()
        .ok_or_else(|| anyhow::anyhow!("wallet viewing history missing"))?;
    Ok(ctx.material.keypair.get_sender_view_tag(entry.tx_count)?)
}

fn wait_for_indexed_utxo(
    indexer: &ZolanaIndexer,
    tag: [u8; 32],
    signature: Signature,
) -> Result<()> {
    let started = SystemTime::now();
    loop {
        let response = indexer.get_encrypted_utxos_by_tags(vec![tag], None, Some(50))?;
        if response
            .matches
            .iter()
            .any(|item| item.tx_signature == signature)
        {
            return Ok(());
        }
        if started.elapsed().unwrap_or_default() >= INDEXER_TIMEOUT {
            bail!("timed out waiting for Photon to index {signature}");
        }
        sleep(INDEXER_POLL);
    }
}

fn wait_for_indexed_transaction(
    indexer: &ZolanaIndexer,
    tag: [u8; 32],
    signature: Signature,
) -> Result<()> {
    let started = SystemTime::now();
    loop {
        let response = indexer.get_shielded_transactions_by_tags(vec![tag], None, Some(50))?;
        if response
            .transactions
            .iter()
            .any(|item| item.tx_signature == signature)
        {
            return Ok(());
        }
        if started.elapsed().unwrap_or_default() >= INDEXER_TIMEOUT {
            bail!("timed out waiting for Photon to index {signature}");
        }
        sleep(INDEXER_POLL);
    }
}

fn maybe_airdrop(
    rpc: &mut SolanaRpc,
    material: &WalletMaterial,
    lamports: Option<u64>,
) -> Result<()> {
    let Some(lamports) = lamports else {
        return Ok(());
    };
    let signature = rpc.airdrop(&material.funding.pubkey(), lamports)?;
    println!("ok airdrop signature={signature}");
    Ok(())
}

fn load_sender_from_sync(opts: &SyncOptions) -> Result<WalletMaterial> {
    let keypair_path = resolve_keypair_path(opts.keypair.keypair.as_deref());
    if !keypair_path.exists() {
        bail!(
            "keypair not found at {}; run `zolana wallet init` first",
            keypair_path.display()
        );
    }
    load_existing_wallet(&keypair_path)
}

fn load_recipient_wallet(path: &str) -> Result<WalletMaterial> {
    let path = PathBuf::from(path);
    if !path.exists() {
        bail!(
            "recipient must be a wallet file path for now; `{}` does not exist",
            path.display()
        );
    }
    load_existing_wallet(&path)
}

fn resolve_transfer_recipient(value: &str, opts: &SyncOptions) -> Result<RecipientLookup> {
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

fn register_wallet_locally(keypair_path: &Path, material: &WalletMaterial) -> Result<()> {
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

fn read_local_user_registry(path: &Path) -> Result<LocalUserRegistryFile> {
    if !path.exists() {
        return Ok(LocalUserRegistryFile {
            version: 1,
            records: HashMap::new(),
        });
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

fn load_existing_wallet(path: &Path) -> Result<WalletMaterial> {
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

fn load_or_create_solana_keypair(path: &Path) -> Result<Keypair> {
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

fn write_json_secret<T: Serialize>(path: &Path, value: &T) -> Result<()> {
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

fn clone_keypair(keypair: &ShieldedKeypair) -> Result<ShieldedKeypair> {
    let mut signing = [0u8; 32];
    signing.copy_from_slice(keypair.signing_key.secret_bytes().as_slice());
    let mut viewing = [0u8; 32];
    viewing.copy_from_slice(keypair.viewing_key.secret_bytes().as_slice());
    Ok(ShieldedKeypair::from_keys(
        SigningKey::from_bytes(&signing)?,
        ViewingKey::from_bytes(&viewing)?,
    )?)
}

fn resolve_keypair_path(value: Option<&str>) -> PathBuf {
    match value {
        Some(path) => PathBuf::from(path),
        None => default_config_dir().join("pid.json"),
    }
}

fn local_user_registry_path(keypair_path: &Path) -> PathBuf {
    keypair_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(default_config_dir)
        .join("user-registry.json")
}

fn default_config_dir() -> PathBuf {
    if let Some(home) = env::var_os("HOME") {
        PathBuf::from(home).join(".config").join("zolana")
    } else {
        PathBuf::from(".zolana")
    }
}

fn ensure_positive(amount: u64) -> Result<()> {
    if amount == 0 {
        bail!("amount must be greater than zero");
    }
    Ok(())
}

fn ensure_sol(value: &str) -> Result<()> {
    if value.eq_ignore_ascii_case("SOL") || parse_address(value)? == SOL_MINT {
        return Ok(());
    }
    bail!("only SOL is supported by the wallet CLI right now")
}

fn parse_address(value: &str) -> Result<Address> {
    if value.eq_ignore_ascii_case("SOL") {
        return Ok(SOL_MINT);
    }
    Ok(Address::new_from_array(parse_pubkey(value)?.to_bytes()))
}

fn parse_pubkey(value: &str) -> Result<Pubkey> {
    value
        .parse::<Pubkey>()
        .with_context(|| format!("invalid pubkey `{value}`"))
}

fn format_address(address: Address) -> String {
    if address == SOL_MINT {
        "SOL".to_string()
    } else {
        Pubkey::new_from_array(address.to_bytes()).to_string()
    }
}

fn now_unix_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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

fn system_create_account_ix(
    payer: &Pubkey,
    new_account: &Pubkey,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let mut data = vec![0u8; 4 + 8 + 8 + 32];
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    data[12..20].copy_from_slice(&space.to_le_bytes());
    data[20..52].copy_from_slice(&owner.to_bytes());
    Instruction {
        program_id: Pubkey::default(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*new_account, true),
        ],
        data,
    }
}

#[allow(dead_code)]
fn _assert_shielded_address_public(address: ShieldedAddress) -> ShieldedAddress {
    address
}

#[cfg(test)]
mod tests {
    use super::*;

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
        run_wallet(WalletCommand::Init(InitOptions {
            path: Some(wallet.display().to_string()),
        }))
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
                keypair: crate::args::WalletKeypairOptions {
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
