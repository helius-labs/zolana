use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_address_lookup_table_interface::instruction::{
    create_lookup_table, extend_lookup_table,
};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use zolana_client::{
    spawn_prover, sync_wallet, Deposit, DepositParams, Rpc, SolanaRpc, ZolanaIndexer,
};
use zolana_interface::{
    instruction::{CreateAssetCounter, CreateProtocolConfig, CreateSplInterface, CreateTree},
    pda,
    state::tree_account_size,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_program_test::system_create_account_ix;
use zolana_test_utils::{
    localnet::LocalnetValidator,
    smart_account::{self, StandardSigners},
    spl::{create_mint, create_token_account, mint_to},
};
use zolana_transaction::{AssetRegistry, Filter, LocalWalletAuthority, Wallet, SOL_MINT};
use zolana_user_registry_interface::user_registry_program_id;

// SPL the maker shields into the order UTXO (source), and SOL the taker pays (destination).
pub const MAKER_SHIELD_SPL: u64 = 1_000_000_000;
pub const SOURCE_AMOUNT: u64 = 400_000_000;
pub const DESTINATION_AMOUNT: u64 = 250_000_000;

// Each actor is one ed25519 identity: the wallet's signing key doubles as the
// Solana fee payer (`to_solana_keypair`), and the wallet holds the asset
// registry and the synced spendable notes.
pub struct TestEnv {
    pub rpc: SolanaRpc,
    pub indexer: ZolanaIndexer,
    pub tree: Pubkey,
    pub maker: TestWallet,
    pub taker: TestWallet,
    pub spl_mint: Address,
}

pub struct TestWallet {
    pub wallet: Wallet,
    pub keypair: ShieldedKeypair,
}

impl std::ops::Deref for TestWallet {
    type Target = Wallet;
    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl std::ops::DerefMut for TestWallet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wallet
    }
}
pub fn setup() -> Result<TestEnv> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../..");
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| format!("{root}/target/debug/zolana"));
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_string());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_string());

    let swap_program_id = swap_program::ID.to_string();
    let swap_program_so = std::env::var("SWAP_PROGRAM_SO")
        .unwrap_or_else(|_| format!("{root}/target/deploy/swap_program.so"));
    let spp_program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID).to_string();
    let spp_program_so = format!("{root}/target/deploy/shielded_pool_program.so");
    let user_registry_id = user_registry_program_id().to_string();
    let user_registry_so = format!("{root}/target/deploy/zolana_user_registry.so");
    let smart_account_id = smart_account::SMART_ACCOUNT_PROGRAM_ID.to_string();
    let smart_account_so = format!("{root}/target/deploy/squads_smart_account_program.so");

    let account_dir = "/tmp/zolana-swap-inline-smart-account-accounts".to_string();
    LocalnetValidator {
        cli_bin: cli,
        working_dir: root.to_string(),
        rpc_port,
        photon_port,
        ledger: "/tmp/zolana-swap-inline-test-ledger".to_string(),
        account_dir,
        programs: vec![
            (swap_program_id, swap_program_so),
            (spp_program_id, spp_program_so),
            (user_registry_id, user_registry_so),
            (smart_account_id, smart_account_so),
        ],
    }
    .start();

    std::env::set_var(
        "ZOLANA_PROVER_KEYS_DIR",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../prover/server/proving-keys"
        ),
    );
    spawn_prover()?;

    let rpc_url = std::env::var("ZOLANA_LOCALNET_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());
    let indexer_url =
        std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| "http://127.0.0.1:8784".to_string());
    let mut rpc = SolanaRpc::new(rpc_url);
    let indexer = ZolanaIndexer::new(indexer_url);

    let spp_program = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    rpc.assert_executable(&spp_program)?;
    let swap_program = Pubkey::new_from_array(*swap_program::ID.as_array());
    rpc.assert_executable(&swap_program)?;

    let payer = Keypair::new();
    let authority = Keypair::new();
    let forester_authority = Keypair::new();
    let merge_authority = Keypair::new();
    let tree_creation_authority = Keypair::new();
    let zone_creation_authority = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 100_000_000_000)?;
    rpc.airdrop(&authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&forester_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&merge_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&tree_creation_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&zone_creation_authority.pubkey(), 1_000_000_000)?;

    let payer_address = payer.pubkey();

    let accounts = smart_account::standard_accounts();
    for ix in accounts.create_ixs(
        &payer.pubkey(),
        StandardSigners {
            protocol: authority.pubkey(),
            forester: forester_authority.pubkey(),
            merge: merge_authority.pubkey(),
            tree: tree_creation_authority.pubkey(),
            zone: zone_creation_authority.pubkey(),
        },
    ) {
        rpc.create_and_send_transaction(&[ix], payer_address, &[&payer])?;
    }

    rpc.airdrop(&accounts.protocol_vault, 5_000_000_000)?;

    let create_config_ix = CreateProtocolConfig {
        authority: accounts.protocol_vault,
        protocol_authority: accounts.protocol_vault.to_bytes().into(),
        tree_creation_authority: accounts.tree_vault.to_bytes().into(),
        tree_creation_is_permissionless: false,
        forester_authority: accounts.forester_vault.to_bytes().into(),
        zone_creation_authority: accounts.zone_vault.to_bytes().into(),
        zone_creation_is_permissionless: false,
        spl_interface_creation_is_permissionless: false,
    }
    .instruction();
    let create_config_sync = smart_account::execute_sync_ix(
        &accounts.protocol_settings,
        0,
        &[authority.pubkey()],
        &[create_config_ix],
    );
    rpc.create_and_send_transaction(&[create_config_sync], payer_address, &[&payer, &authority])?;

    let tree = Keypair::new();
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(tree_account_size())
        .map_err(|e| anyhow!("{e}"))?;
    let alloc_ix = system_create_account_ix(
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
    let create_tree_sync = smart_account::execute_sync_ix(
        &accounts.tree_settings,
        0,
        &[tree_creation_authority.pubkey()],
        &[create_tree_ix],
    );
    rpc.create_and_send_transaction(
        &[alloc_ix, create_tree_sync],
        payer_address,
        &[&payer, &tree, &tree_creation_authority],
    )?;

    let tree = tree.pubkey();

    // Register an SPL asset with the pool so the maker can order it. Both
    // CreateAssetCounter and CreateSplInterface check the protocol authority (the
    // Squads protocol vault), so each is wrapped in execute_sync_ix.
    let spl_mint = create_mint(&rpc, &payer)?;
    if rpc.get_account(pda::spl_asset_counter())?.is_none() {
        let counter_ix = CreateAssetCounter {
            authority: accounts.protocol_vault,
        }
        .instruction();
        let counter_sync = smart_account::execute_sync_ix(
            &accounts.protocol_settings,
            0,
            &[authority.pubkey()],
            &[counter_ix],
        );
        rpc.create_and_send_transaction(&[counter_sync], payer_address, &[&payer, &authority])?;
    }
    let interface_ix = CreateSplInterface {
        authority: accounts.protocol_vault,
        mint: spl_mint,
    }
    .instruction();
    let interface_sync = smart_account::execute_sync_ix(
        &accounts.protocol_settings,
        0,
        &[authority.pubkey()],
        &[interface_ix],
    );
    rpc.create_and_send_transaction(&[interface_sync], payer_address, &[&payer, &authority])?;

    // SOL occupies asset id 1; the first registered SPL mint gets id 2.
    let spl_asset_id = 2u64;
    let mut assets = AssetRegistry::default();
    assets.insert(spl_asset_id, spl_mint)?;

    let spl_funding = create_token_account(&rpc, &payer, &spl_mint, &payer.pubkey())?;
    mint_to(&rpc, &payer, &spl_mint, &spl_funding, 1_000_000_000)?;

    let maker_solana_keypair = Keypair::new();
    let maker_seed: [u8; 32] = maker_solana_keypair.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let maker_shielded_keypair = ShieldedKeypair::from_ed25519(&maker_seed, ViewingKey::new())?;
    rpc.airdrop(&maker_solana_keypair.pubkey(), 10_000_000_000)?;

    let taker_solana_keypair = Keypair::new();
    rpc.airdrop(&taker_solana_keypair.pubkey(), 10_000_000_000)?;
    let taker_seed: [u8; 32] = taker_solana_keypair.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let taker_shielded_keypair = ShieldedKeypair::from_ed25519(&taker_seed, ViewingKey::new())?;

    // Fund the actors: shield the maker's SPL (the source it orders) and the
    // taker's SOL (what it pays). Then discover the notes through each party's
    // wallet, which scans the indexer for its view tags and decrypts its own
    // outputs. Photon lags the validator, so poll sync until both notes appear.
    Deposit::new(DepositParams {
        recipient: &maker_shielded_keypair.shielded_address()?,
        asset: spl_mint,
        amount: MAKER_SHIELD_SPL,
        spl_token_account: Some(spl_funding),
        memo: None,
    })?
    .send(&rpc, &payer, tree, &payer)?;
    Deposit::new(DepositParams {
        recipient: &taker_shielded_keypair.shielded_address()?,
        asset: SOL_MINT,
        amount: DESTINATION_AMOUNT,
        spl_token_account: None,
        memo: None,
    })?
    .send(&rpc, &payer, tree, &payer)?;

    let maker_address = maker_shielded_keypair
        .shielded_address()
        .map_err(|e| anyhow!("maker address: {e:?}"))?;
    let taker_address = taker_shielded_keypair
        .shielded_address()
        .map_err(|e| anyhow!("taker address: {e:?}"))?;
    let mut maker_wallet =
        Wallet::new(maker_address, assets.clone()).map_err(|e| anyhow!("maker wallet: {e:?}"))?;
    let mut taker_wallet =
        Wallet::new(taker_address, assets.clone()).map_err(|e| anyhow!("taker wallet: {e:?}"))?;
    let maker_authority =
        LocalWalletAuthority::new(maker_solana_keypair.pubkey(), &maker_shielded_keypair);
    let taker_authority =
        LocalWalletAuthority::new(taker_solana_keypair.pubkey(), &taker_shielded_keypair);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        sync_wallet(&mut maker_wallet, &maker_authority, &indexer)?;
        sync_wallet(&mut taker_wallet, &taker_authority, &indexer)?;
        if !maker_wallet
            .balance(spl_mint, Some(Filter::MinAmount(SOURCE_AMOUNT)))?
            .utxos
            .is_empty()
            && !taker_wallet
                .balance(SOL_MINT, Some(Filter::MinAmount(DESTINATION_AMOUNT)))?
                .utxos
                .is_empty()
        {
            break;
        }
        if Instant::now() >= deadline {
            return Err(anyhow!("timed out syncing shielded deposits"));
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    Ok(TestEnv {
        rpc,
        indexer,
        tree,
        maker: TestWallet {
            wallet: maker_wallet,
            keypair: maker_shielded_keypair,
        },
        taker: TestWallet {
            wallet: taker_wallet,
            keypair: taker_shielded_keypair,
        },
        spl_mint,
    })
}

// Submit a single (large) swap instruction as a v0 transaction behind a throwaway
// address lookup table: create + extend the ALT (waiting a slot for each to root),
// then compile and send. Prepends a 1.4M CU budget; `payer` signs and pays. The
// swap lifecycle account lists only fit within the 1232-byte tx limit via an ALT.
pub fn send_v0_with_lookup_table(rpc: &SolanaRpc, payer: &Keypair, ix: Instruction) -> Result<()> {
    let alt_addresses: Vec<Pubkey> = ix
        .accounts
        .iter()
        .filter(|meta| !meta.is_signer)
        .map(|meta| meta.pubkey)
        .chain(std::iter::once(ix.program_id))
        .collect();
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);

    let client = rpc.client();
    let recent_slot = client.get_slot().map_err(|e| anyhow!("get_slot: {e}"))?;
    loop {
        let tip = client.get_slot().map_err(|e| anyhow!("get_slot: {e}"))?;
        if tip > recent_slot {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let (lut_create_ix, table_address) =
        create_lookup_table(payer.pubkey(), payer.pubkey(), recent_slot);
    let lut_extend_ix = extend_lookup_table(
        table_address,
        payer.pubkey(),
        Some(payer.pubkey()),
        alt_addresses.clone(),
    );
    let blockhash = client
        .get_latest_blockhash()
        .map_err(|e| anyhow!("blockhash: {e}"))?;
    let setup = Transaction::new(
        &[payer],
        Message::new(&[lut_create_ix, lut_extend_ix], Some(&payer.pubkey())),
        blockhash,
    );
    client
        .send_and_confirm_transaction(&setup)
        .map_err(|e| anyhow!("create+extend ALT: {e}"))?;
    let extended_slot = client.get_slot().map_err(|e| anyhow!("get_slot: {e}"))?;
    loop {
        let tip = client.get_slot().map_err(|e| anyhow!("get_slot: {e}"))?;
        if tip > extended_slot {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let alt = AddressLookupTableAccount {
        key: table_address,
        addresses: alt_addresses.clone(),
    };
    let blockhash = client
        .get_latest_blockhash()
        .map_err(|e| anyhow!("blockhash: {e}"))?;
    let message = v0::Message::try_compile(
        &payer.pubkey(),
        &[compute, ix],
        std::slice::from_ref(&alt),
        blockhash,
    )
    .map_err(|e| anyhow!("compile v0: {e}"))?;
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[payer])
        .map_err(|e| anyhow!("sign v0: {e}"))?;
    client
        .send_and_confirm_transaction(&tx)
        .map_err(|e| anyhow!("send v0: {e}"))?;
    Ok(())
}
