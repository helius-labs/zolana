use std::time::Duration;

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
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use zolana_client::{
    AsyncProverClient, AsyncZolanaIndexer, ProverClient, Rpc, SolanaRpc, ZolanaClient,
    ZolanaIndexer,
};
use zolana_interface::{
    instruction::{CreateAssetCounter, CreateProtocolConfig, CreateSplInterface, CreateTree},
    pda,
    state::tree_account_size,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{
    constants::BLINDING_LEN, NullifierKey, PublicKey, ShieldedAddress, ShieldedKeypair, SigningKey,
};
use zolana_program_test::system_create_account_ix;
use zolana_test_utils::{
    localnet::{isolated_temp_path, LocalnetValidator, WorkspaceArtifacts},
    prover::spawn_workspace_prover,
    smart_account::{self, StandardSigners},
    spl::{create_mint, create_token_account, mint_to},
};
use zolana_transaction::{
    instructions::types::SppProofInputUtxo, utxo::Utxo, AssetRegistry, Data, Wallet, SOL_MINT,
};
use zolana_user_registry_interface::user_registry_program_id;
use zolana_wallet::{sync_wallet, Deposit, DepositParams};

// SPL the maker shields into the order UTXO (source), and SOL the taker pays (destination).
pub const MAKER_SHIELD_SPL: u64 = 1_000_000_000;
pub const SOURCE_AMOUNT: u64 = 400_000_000;
pub const DESTINATION_AMOUNT: u64 = 250_000_000;

// Each actor is one ed25519 identity: the wallet's signing key doubles as the
// Solana fee payer (`to_solana_keypair`), and the wallet holds the asset
// registry and the synced spendable notes.
pub struct TestEnv {
    pub client: ZolanaClient<SolanaRpc>,
    pub tree: Pubkey,
    pub maker: TestWallet,
    pub maker_input: SppProofInputUtxo,
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
    let artifacts = WorkspaceArtifacts::new(root);
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| artifacts.path("target/debug/zolana"));
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_string());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_string());

    let swap_program_id = swap_program::ID.to_string();
    let swap_program_so = std::env::var("SWAP_PROGRAM_SO")
        .unwrap_or_else(|_| artifacts.path("target/deploy/swap_program.so"));
    let spp_program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID).to_string();
    let spp_program_so = artifacts.path("target/deploy/shielded_pool_program.so");
    let user_registry_id = user_registry_program_id().to_string();
    let user_registry_so = artifacts.path("target/deploy/zolana_user_registry.so");
    let smart_account_id = smart_account::SMART_ACCOUNT_PROGRAM_ID.to_string();
    let smart_account_so = artifacts.path("target/deploy/squads_smart_account_program.so");

    LocalnetValidator {
        cli_bin: cli.clone(),
        working_dir: artifacts.root(),
        rpc_port,
        photon_port,
        ledger: isolated_temp_path("zolana-swap-ledger"),
        account_dir: isolated_temp_path("zolana-swap-smart-accounts"),
        programs: vec![
            (swap_program_id, swap_program_so),
            (spp_program_id, spp_program_so),
            (user_registry_id, user_registry_so),
            (smart_account_id, smart_account_so),
        ],
    }
    .start();

    spawn_workspace_prover();

    let rpc_url = std::env::var("ZOLANA_LOCALNET_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());
    let indexer_url =
        std::env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| "http://127.0.0.1:8784".to_string());
    let mut rpc = SolanaRpc::new(rpc_url);
    let indexer = ZolanaIndexer::new(indexer_url.clone());

    let spp_program = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    rpc.assert_executable(&spp_program)?;
    let swap_program = Pubkey::new_from_array(*swap_program::ID.as_array());
    rpc.assert_executable(&swap_program)?;

    let payer = Keypair::new();
    let authority = Keypair::new();
    let forester_authority = Keypair::new();
    let merge_authority = Keypair::new();
    let tree_creation_authority = Keypair::new();
    let ring_creation_authority = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 100_000_000_000)?;
    rpc.airdrop(&authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&forester_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&merge_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&tree_creation_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&ring_creation_authority.pubkey(), 1_000_000_000)?;

    let payer_address = payer.pubkey();

    let accounts = smart_account::standard_accounts();
    for ix in accounts.create_ixs(
        &payer.pubkey(),
        StandardSigners {
            protocol: authority.pubkey(),
            forester: forester_authority.pubkey(),
            merge: merge_authority.pubkey(),
            tree: tree_creation_authority.pubkey(),
            ring: ring_creation_authority.pubkey(),
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
        ring_creation_authority: accounts.ring_vault.to_bytes().into(),
        ring_creation_is_permissionless: false,
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
        token_program: zolana_interface::pda::spl_token_program_id(),
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
    let maker_shielded_keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&maker_seed))?;
    rpc.airdrop(&maker_solana_keypair.pubkey(), 10_000_000_000)?;

    let taker_solana_keypair = Keypair::new();
    rpc.airdrop(&taker_solana_keypair.pubkey(), 10_000_000_000)?;
    let taker_seed: [u8; 32] = taker_solana_keypair.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let taker_shielded_keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&taker_seed))?;

    // Fund the actors: shield the maker-funded SPL to the order authority so it
    // can authorize the data-bearing order output, and shield the taker's SOL
    // directly to the taker.
    let order_nullifier_key = NullifierKey::from_secret([0u8; BLINDING_LEN]);
    let order_authority_address = ShieldedAddress {
        signing_pubkey: PublicKey::from_ed25519(swap_sdk::order_authority_pda().as_array()),
        nullifier_pubkey: order_nullifier_key.pubkey()?,
        viewing_pubkey: maker_shielded_keypair.viewing_pubkey(),
    };
    let maker_deposit = Deposit::new(DepositParams {
        recipient: &order_authority_address,
        asset: spl_mint,
        amount: MAKER_SHIELD_SPL,
        spl_token_account: Some(spl_funding),
        spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
        memo: None,
    })?;
    maker_deposit.send(&rpc, &payer, tree, &payer)?;
    let maker_input = SppProofInputUtxo::new(
        Utxo {
            owner: order_authority_address.signing_pubkey,
            asset: spl_mint,
            amount: MAKER_SHIELD_SPL,
            blinding: maker_deposit.deposit.blinding,
            ring_program_id: None,
            data: Data::default(),
        },
        order_nullifier_key,
    );
    Deposit::new(DepositParams {
        recipient: &taker_shielded_keypair.shielded_address()?,
        asset: SOL_MINT,
        amount: DESTINATION_AMOUNT,
        spl_token_account: None,
        spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
        memo: None,
    })?
    .send(&rpc, &payer, tree, &payer)?;

    let maker_address = maker_shielded_keypair
        .shielded_address()
        .map_err(|e| anyhow!("maker address: {e:?}"))?;
    let taker_address = taker_shielded_keypair
        .shielded_address()
        .map_err(|e| anyhow!("taker address: {e:?}"))?;

    // The taker's deposit is wallet-owned, so discover it through the indexer.
    // The maker-funded input is program-owned and retained explicitly above.
    let maker_wallet =
        Wallet::new(maker_address, assets.clone()).map_err(|e| anyhow!("maker wallet: {e:?}"))?;
    let mut taker_wallet =
        Wallet::new(taker_address, assets.clone()).map_err(|e| anyhow!("taker wallet: {e:?}"))?;
    sync_wallet(&mut taker_wallet, &taker_shielded_keypair, &indexer)
        .map_err(|e| anyhow!("sync taker deposit: {e:?}"))?;

    let client = ZolanaClient::new(
        rpc,
        indexer,
        ProverClient::default(),
        AsyncZolanaIndexer::new(indexer_url),
        AsyncProverClient::default(),
        Address::new_from_array(tree.to_bytes()),
    );

    let env = TestEnv {
        client,
        tree,
        maker: TestWallet {
            wallet: maker_wallet,
            keypair: maker_shielded_keypair,
        },
        maker_input,
        taker: TestWallet {
            wallet: taker_wallet,
            keypair: taker_shielded_keypair,
        },
        spl_mint,
    };

    // Guard the fixture: the retained order-authority input the make flows
    // spend must be exactly the note the maker deposit just funded.
    debug_assert_eq!(env.maker_input.utxo.asset, spl_mint);
    debug_assert_eq!(env.maker_input.utxo.amount, MAKER_SHIELD_SPL);
    Ok(env)
}

// Submit a single (large) swap instruction as a v0 transaction behind a throwaway
// address lookup table: create + extend the ALT (waiting a slot for each to root),
// then compile and send. Prepends a 1.4M CU budget; `payer` signs and pays. The
// swap lifecycle account lists only fit within the 1232-byte tx limit via an ALT.
pub fn send_v0_with_lookup_table(
    rpc: &SolanaRpc,
    payer: &dyn Signer,
    ix: Instruction,
) -> Result<Signature> {
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
    let signature = client
        .send_and_confirm_transaction(&tx)
        .map_err(|e| anyhow!("send v0: {e}"))?;
    Ok(signature)
}
