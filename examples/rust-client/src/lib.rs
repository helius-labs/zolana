//! Shared setup for the rust client examples.
//!
//! Each example is a thin `main` that calls [`setup`] for a fresh localnet
//! (validator + Photon indexer + prover), creates parties with [`new_party`],
//! and drives the client SDK. The localnet orchestration mirrors the
//! `spp-test-validator` harness: the `zolana` CLI is the single source of truth
//! for starting the validator and Photon.

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::{
    create_associated_token_account, create_deposit, spawn_prover, sync_wallet, CreateDeposit,
    ProverClient, Rpc, SignedTransaction, SolanaRpc, Submit, Transaction as ClientTransaction,
    ZolanaIndexer,
};
use zolana_interface::{
    instruction::{
        CreateAssetCounter, CreateProtocolConfig, CreateSplInterface, CreateTree,
        TransactWithdrawal,
    },
    pda,
    state::tree_account_size,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{ShieldedKeypair, SignatureType};
use zolana_test_utils::{
    smart_account::{self, execute_sync_ix, StandardSigners},
    spl::{create_mint, create_token_account, mint_to},
    test_validator_asserts::wait_for_indexed_transaction,
};
use zolana_transaction::{AssetRegistry, Utxo, Wallet, SOL_MINT};
use zolana_user_registry_interface::{
    instruction::{register as register_ix, RegisterData},
    user_record_pda, user_registry_program_id,
};

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";
const DEFAULT_PROVER_URL: &str = "http://127.0.0.1:3001";

/// SOL occupies asset id 1; the first registered SPL mint gets id 2.
const FIRST_SPL_ASSET_ID: u64 = 2;

/// A registered SPL asset: its mint, the vault a deposit credits, and a shared
/// payer-owned token account that funds deposits.
#[derive(Clone, Copy)]
pub struct SplAsset {
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub user_token: Pubkey,
}

/// Localnet handles plus the protocol config and a created state tree, ready for
/// deposits and transfers.
///
/// `assets` is the registry template: every SPL asset registered via
/// [`ensure_spl_asset`] is recorded here, and [`new_party`] clones it into each
/// new wallet. The SDK reads the registry off the wallet (`wallet.registry`),
/// so register assets before creating the parties that spend them.
pub struct Context {
    pub rpc: SolanaRpc,
    pub indexer: ZolanaIndexer,
    pub assets: AssetRegistry,
    pub payer: Keypair,
    pub authority: Keypair,
    pub protocol_settings: Pubkey,
    pub protocol_vault: Pubkey,
    pub tree: Pubkey,
    pub prover: ProverClient,
    spls: Vec<SplAsset>,
}

/// Start the persistent prover (idempotent), pointing it at the committed keys.
fn start_prover() -> Result<()> {
    std::env::set_var(
        "ZOLANA_PROVER_KEYS_DIR",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../prover/server/proving-keys"
        ),
    );
    spawn_prover()?;
    Ok(())
}

/// Restart a fresh validator + Photon via the `zolana` CLI. `--skip-prover`
/// leaves the persistent prover untouched so its keys stay loaded.
fn restart_localnet() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| format!("{root}/target/debug/zolana"));
    let program_id =
        std::env::var("SHIELDED_POOL_PROGRAM_ID").expect("SHIELDED_POOL_PROGRAM_ID must be set");
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_string());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_string());
    let program_so = format!("{root}/target/deploy/shielded_pool_program.so");

    let user_registry_id = user_registry_program_id().to_string();
    let user_registry_so = format!("{root}/target/deploy/zolana_user_registry.so");

    let smart_account_id = smart_account::SMART_ACCOUNT_PROGRAM_ID.to_string();
    let smart_account_so = format!("{root}/target/deploy/squads_smart_account_program.so");

    let account_dir = "/tmp/zolana-rust-client-example-accounts";
    smart_account::write_program_config_fixture(account_dir);

    let status = std::process::Command::new(&cli)
        .current_dir(root)
        .args([
            "test-validator",
            "--no-use-surfpool",
            "--with-photon",
            "--skip-prover",
            "--rpc-port",
            &rpc_port,
            "--photon-port",
            &photon_port,
            "--ledger",
            "/tmp/zolana-rust-client-example-ledger",
            "--sbf-program",
            &program_id,
            &program_so,
            "--sbf-program",
            &user_registry_id,
            &user_registry_so,
            "--sbf-program",
            &smart_account_id,
            &smart_account_so,
            "--account-dir",
            account_dir,
        ])
        .status()
        .expect("run zolana test-validator");
    assert!(status.success(), "zolana test-validator restart failed");
}

fn send(
    rpc: &mut SolanaRpc,
    ixs: &[Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
) -> Result<Signature> {
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = Message::new(ixs, Some(payer));
    let transaction = Transaction::new(signers, message, blockhash);
    Ok(rpc.send_transaction(&transaction)?)
}

/// Boot a fresh localnet, create the protocol config, and create a state tree.
///
/// The prover is independent of the validator, so start it concurrently with the
/// validator + Photon restart and join before use.
pub fn setup() -> Result<Context> {
    let prover = std::thread::spawn(start_prover);
    restart_localnet();
    prover.join().expect("prover startup thread panicked")?;

    let rpc_url = std::env::var("ZOLANA_LOCALNET_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.into());
    let indexer_url =
        std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| DEFAULT_INDEXER_URL.into());
    let prover_url =
        std::env::var("ZOLANA_PROVER_URL").unwrap_or_else(|_| DEFAULT_PROVER_URL.into());
    let mut rpc = SolanaRpc::new(rpc_url);
    let indexer = ZolanaIndexer::new(indexer_url);
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    rpc.assert_executable(&program_id)?;

    let payer = Keypair::new();
    let authority = Keypair::new();
    let forester_key = Keypair::new();
    let merge_key = Keypair::new();
    let tree_key = Keypair::new();
    let zone_key = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 100_000_000_000)?;
    rpc.airdrop(&authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&forester_key.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&merge_key.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&tree_key.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&zone_key.pubkey(), 1_000_000_000)?;

    let accounts = smart_account::standard_accounts();
    for ix in accounts.create_ixs(
        &payer.pubkey(),
        StandardSigners {
            protocol: authority.pubkey(),
            forester: forester_key.pubkey(),
            merge: merge_key.pubkey(),
            tree: tree_key.pubkey(),
            zone: zone_key.pubkey(),
        },
    ) {
        send(&mut rpc, &[ix], &payer.pubkey(), &[&payer])?;
    }

    // The shielded pool requires fee payer == protocol_authority, so CPI via
    // execute_sync_ix with the protocol vault as the inner fee payer.
    rpc.airdrop(&accounts.protocol_vault, 5_000_000_000)?;

    // Merge authority now lives per-user on the registry record, so the protocol
    // config no longer carries a `merge_authority` field.
    let create_config_ix = CreateProtocolConfig {
        authority: accounts.protocol_vault,
        protocol_authority: accounts.protocol_vault.to_bytes().into(),
        tree_creation_authority: accounts.tree_vault.to_bytes().into(),
        tree_creation_is_permissionless: false,
        forester_authority: accounts.forester_vault.to_bytes().into(),
        zone_creation_authority: accounts.zone_vault.to_bytes().into(),
        zone_creation_is_permissionless: false,
    }
    .instruction();
    let create_config_sync = execute_sync_ix(
        &accounts.protocol_settings,
        0,
        &[authority.pubkey()],
        &[create_config_ix],
    );
    send(
        &mut rpc,
        &[create_config_sync],
        &payer.pubkey(),
        &[&payer, &authority],
    )?;

    let tree = Keypair::new();
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(tree_account_size())
        .map_err(|e| anyhow!("{e}"))?;
    let alloc_ix = zolana_program_test::system_create_account_ix(
        &payer.pubkey(),
        &tree.pubkey(),
        rent,
        tree_account_size() as u64,
        &pda::shielded_pool_program_id(),
    );
    let create_tree_ix = CreateTree {
        authority: accounts.tree_vault,
        tree: tree.pubkey(),
        owner: accounts.tree_vault,
    }
    .instruction();
    let create_tree_sync = execute_sync_ix(
        &accounts.tree_settings,
        0,
        &[tree_key.pubkey()],
        &[create_tree_ix],
    );
    send(
        &mut rpc,
        &[alloc_ix, create_tree_sync],
        &payer.pubkey(),
        &[&payer, &tree, &tree_key],
    )?;

    Ok(Context {
        rpc,
        indexer,
        assets: AssetRegistry::default(),
        payer,
        authority,
        protocol_settings: accounts.protocol_settings,
        protocol_vault: accounts.protocol_vault,
        tree: tree.pubkey(),
        prover: ProverClient::new(prover_url),
        spls: Vec::new(),
    })
}

/// Create a party's pieces: a fresh shielded identity, a funded Solana owner
/// key, and an empty wallet seeded with the context's asset registry.
///
/// The wallet owns the [`AssetRegistry`] the SDK uses to encode/decode UTXO
/// asset ids, so register SPL assets ([`ensure_spl_asset`]) before creating the
/// parties that spend them.
///
/// `funding.pubkey()` is the key the user-registry record is keyed by — the
/// `owner_pubkey` a transfer resolves a recipient against — and is distinct from
/// the shielded keypair. It is NOT the transfer fee payer: the fee `payer` is a
/// separate argument (the Context payer), bound into the proof as
/// `payer_pubkey_hash`.
pub fn new_party(context: &mut Context) -> Result<(ShieldedKeypair, Keypair, Wallet)> {
    let keypair = ShieldedKeypair::new()?;
    let funding = Keypair::new();
    context.rpc.airdrop(&funding.pubkey(), 1_000_000_000)?;
    let wallet = Wallet::new(keypair.clone(), context.assets.clone())?;
    Ok((keypair, funding, wallet))
}

/// Register a party's shielded keys on the user-registry under its Solana owner,
/// so a transfer to that owner resolves to a shielded recipient rather than
/// falling back to a public withdrawal.
pub fn register(
    context: &Context,
    keypair: &ShieldedKeypair,
    funding: &Keypair,
) -> Result<Signature> {
    let owner = funding.pubkey();
    let owner_p256 = match keypair.signing_pubkey().signature_type()? {
        SignatureType::P256 => Some(*keypair.signing_pubkey().as_p256()?.as_bytes()),
        SignatureType::Ed25519 => None,
    };
    let data = RegisterData {
        owner_p256,
        nullifier_pubkey: keypair.nullifier_key.pubkey()?,
        viewing_pubkey: *keypair.viewing_pubkey().as_bytes(),
    };
    let (user_record, _bump) = user_record_pda(&owner);
    let ix = register_ix(user_record, owner, data);
    Ok(context.rpc.create_and_send_transaction(
        &[ix],
        Address::new_from_array(owner.to_bytes()),
        &[funding],
    )?)
}

/// Register one SPL asset (idempotent across a Context): create a mint, ensure the
/// asset counter, create the shielded-pool interface (registry + vault), create a
/// shared payer-owned funding token account, and add the mint to the asset
/// registry so transfers can resolve it.
pub fn ensure_spl_asset(context: &mut Context) -> Result<SplAsset> {
    if let Some(asset) = context.spls.first() {
        return Ok(*asset);
    }
    let payer = context.payer.insecure_clone();
    let authority = context.authority.insecure_clone();
    let asset_id = FIRST_SPL_ASSET_ID;

    let mint = create_mint(&context.rpc, &payer)?;

    // CreateAssetCounter and CreateSplInterface both check protocol_authority,
    // now the protocol vault PDA, so wrap each in execute_sync_ix.
    let counter_addr = Address::new_from_array(pda::spl_asset_counter().to_bytes());
    if context.rpc.get_account(counter_addr)?.is_none() {
        let ix = CreateAssetCounter {
            authority: context.protocol_vault,
        }
        .instruction();
        let sync_ix = execute_sync_ix(&context.protocol_settings, 0, &[authority.pubkey()], &[ix]);
        send(
            &mut context.rpc,
            &[sync_ix],
            &payer.pubkey(),
            &[&payer, &authority],
        )?;
    }

    let ix = CreateSplInterface {
        authority: context.protocol_vault,
        mint,
    }
    .instruction();
    let sync_ix = execute_sync_ix(&context.protocol_settings, 0, &[authority.pubkey()], &[ix]);
    send(
        &mut context.rpc,
        &[sync_ix],
        &payer.pubkey(),
        &[&payer, &authority],
    )?;

    let vault = pda::spl_asset_vault(&mint);
    let user_token = create_token_account(&context.rpc, &payer, &mint, &payer.pubkey())?;
    context
        .assets
        .insert(asset_id, Address::new_from_array(mint.to_bytes()))
        .map_err(|e| anyhow!("register SPL asset: {e}"))?;

    let asset = SplAsset {
        mint,
        vault,
        user_token,
    };
    context.spls.push(asset);
    Ok(asset)
}

/// Shield `amount` lamports of SOL to `keypair` and sync `wallet` so the note is
/// spendable. Used to seed inputs for transfer / withdraw examples.
pub fn shield_sol(
    context: &mut Context,
    keypair: &ShieldedKeypair,
    wallet: &mut Wallet,
    amount: u64,
) -> Result<()> {
    let recipient = keypair.shielded_address()?;
    let prepared = create_deposit(CreateDeposit {
        recipient: &recipient,
        asset: SOL_MINT,
        amount,
        spl_token_account: None,
        memo: None,
    })?;
    let payer = context.payer.insecure_clone();
    let signature = prepared.send(&context.rpc, &payer, context.tree, &payer)?;
    wait_for_indexed_transaction(&context.indexer, prepared.view_tag(), signature);
    sync_wallet(wallet, &context.indexer)?;
    Ok(())
}

/// Shield `amount` base units of `asset` to `keypair`. Mints to the shared
/// funding token account first, then deposits and syncs `wallet` so the note is
/// spendable.
pub fn shield_spl(
    context: &mut Context,
    keypair: &ShieldedKeypair,
    wallet: &mut Wallet,
    asset: &SplAsset,
    amount: u64,
) -> Result<()> {
    let payer = context.payer.insecure_clone();
    mint_to(&context.rpc, &payer, &asset.mint, &asset.user_token, amount)?;
    let recipient = keypair.shielded_address()?;
    let prepared = create_deposit(CreateDeposit {
        recipient: &recipient,
        asset: Address::new_from_array(asset.mint.to_bytes()),
        amount,
        spl_token_account: Some(asset.user_token),
        memo: None,
    })?;
    let signature = prepared.send(&context.rpc, &payer, context.tree, &payer)?;
    wait_for_indexed_transaction(&context.indexer, prepared.view_tag(), signature);
    sync_wallet(wallet, &context.indexer)?;
    Ok(())
}

/// Submit a signed private transaction with the one-call [`Submit`] action: it
/// fetches the per-input merkle and non-inclusion proofs, assembles the witness,
/// proves on the matching circuit, and sends the `Transact` instruction under a
/// compute-unit ceiling.
///
/// `Submit::execute` returns on confirmation but does not wait for the indexer,
/// so we block on `wait_tag` afterward for a follow-up sync to see the result.
pub fn submit_private_transaction(
    context: &mut Context,
    signed: SignedTransaction,
    withdrawal: Option<TransactWithdrawal>,
    wait_tag: [u8; 32],
) -> Result<Signature> {
    let submit = Submit {
        signed,
        withdrawal,
        cu_limit: None,
    };
    let payer = context.payer.insecure_clone();
    let signature = submit.execute(&context.rpc, &context.prover, &payer, context.tree)?;
    wait_for_indexed_transaction(&context.indexer, wait_tag, signature);
    Ok(signature)
}

/// Block until `wait_tag`'s transaction is indexed by Photon.
///
/// The SDK `.submit()` / `Submit::execute` return on on-chain confirmation but do
/// not wait for the indexer, so a caller that immediately syncs a wallet would
/// race Photon. Call this between submit and `sync_wallet`.
pub fn wait_for_indexed(context: &Context, wait_tag: [u8; 32], signature: Signature) {
    wait_for_indexed_transaction(&context.indexer, wait_tag, signature);
}

/// A fresh client-side transaction builder seeded with `keypair`'s address,
/// spend inputs, and fee payer.
///
/// The fee payer is the Context payer, not the party's funding key: its hash
/// (`payer_pubkey_hash`) is bound into the transfer proof, and
/// `submit_private_transaction` submits the `Transact` instruction with
/// `context.payer`. The two must be the same key or on-chain proof verification
/// fails with `TransactProofVerificationFailed`.
pub fn client_transaction(
    context: &Context,
    keypair: &ShieldedKeypair,
    inputs: &[Utxo],
) -> Result<ClientTransaction> {
    let payer = Address::new_from_array(context.payer.pubkey().to_bytes());
    let spends = inputs
        .iter()
        .map(|u| zolana_client::SpendUtxo::from_keypair(u.clone(), keypair))
        .collect();
    Ok(ClientTransaction::new(
        keypair.shielded_address()?,
        spends,
        payer,
    ))
}

/// Create `owner`'s associated token account for `mint` if missing, returning
/// its address. An SPL withdrawal settles into this account, so it must exist
/// before the withdraw. Wraps the idempotent `create_associated_token_account`
/// client action.
pub fn ensure_associated_token_account(
    context: &Context,
    owner: &Pubkey,
    mint: &Pubkey,
) -> Result<Pubkey> {
    let (_signature, ata) =
        create_associated_token_account(&context.rpc, &context.payer, owner, mint)?;
    Ok(ata)
}
