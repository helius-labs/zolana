use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    AsyncProverClient, AsyncZolanaIndexer, ComputeBudgetConfig, ProverClient, Rpc, SolanaRpc,
    ZolanaClient, ZolanaIndexer,
};
use zolana_interface::{
    instruction::{CreateAssetCounter, CreateProtocolConfig, CreateSplInterface},
    pda,
    state::{default_tree_fees, nullifier_tree_params},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{
    constants::BLINDING_LEN, NullifierKey, PublicKey, ShieldedAddress, ShieldedKeypair, SigningKey,
};
use zolana_program_test::create_tree_instructions;
use zolana_test_utils::{
    localnet::{isolated_temp_path, LocalnetValidator, UpgradeableProgram, WorkspaceArtifacts},
    prover::spawn_workspace_prover,
    smart_account::{self, StandardSigners},
    spl::{create_mint, create_token_account, mint_to},
    test_validator_asserts::wait_for_indexed_utxo,
};
use zolana_transaction::{
    instructions::types::SppProofInputUtxo, utxo::Utxo, AssetRegistry, Data, Wallet, SOL_MINT,
};
use zolana_user_registry_interface::user_registry_program_id;
use zolana_wallet::{sync_wallet, Deposit, DepositParams};

// The whole per-transaction budget: a swap verifies an SPP proof and its own.
const TRANSACT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

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
    /// Raw id of `tree`, read from its account. Every UTXO commitment folds it
    /// in, so the SPP and swap proofs must hash under the same value.
    pub tree_id: u16,
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

    let protocol_vault = smart_account::standard_accounts()
        .protocol_vault
        .to_string();
    LocalnetValidator {
        cli_bin: cli.clone(),
        working_dir: artifacts.root(),
        rpc_port,
        photon_port,
        ledger: isolated_temp_path("zolana-swap-ledger"),
        account_dir: isolated_temp_path("zolana-swap-smart-accounts"),
        programs: vec![
            (swap_program_id, swap_program_so),
            (user_registry_id, user_registry_so),
            (smart_account_id, smart_account_so),
        ],
    }
    .start_with_upgradeable_programs(&[UpgradeableProgram {
        address: &spp_program_id,
        path: &spp_program_so,
        authority: &protocol_vault,
    }]);

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
        rpc.create_and_send_v1_transaction(
            &[ix],
            payer_address,
            &[&payer],
            ComputeBudgetConfig::for_instruction_count(1),
        )?;
    }

    rpc.airdrop(&accounts.protocol_vault, 5_000_000_000)?;

    let create_config_ix = CreateProtocolConfig {
        fee_payer: payer.pubkey(),
        initialization_authority: accounts.protocol_vault,
        protocol_authority: accounts.protocol_vault.to_bytes().into(),
        fee_authority: accounts.protocol_vault.to_bytes().into(),
        tree_creation_authority: accounts.tree_vault.to_bytes().into(),
        tree_creation_is_permissionless: false,
        forester_authority: accounts.forester_vault.to_bytes().into(),
        ring_creation_authority: accounts.ring_vault.to_bytes().into(),
        ring_activation_is_permissionless: false,
        spl_interface_creation_is_permissionless: false,
    }
    .instruction();
    let create_config_sync = smart_account::execute_sync_ix(
        &accounts.protocol_settings,
        0,
        &[authority.pubkey()],
        &[create_config_ix],
    );
    rpc.create_and_send_v1_transaction(
        &[create_config_sync],
        payer_address,
        &[&payer, &authority],
        ComputeBudgetConfig::for_instruction_count(1),
    )?;

    let tree_creation = create_tree_instructions(
        &rpc,
        &payer.pubkey(),
        &accounts.tree_vault,
        nullifier_tree_params(),
        default_tree_fees(nullifier_tree_params().input_queue_zkp_batch_size)
            .expect("default tree fees"),
    )?;
    let create_tree_syncs = smart_account::execute_sync_each(
        &accounts.tree_settings,
        0,
        &[tree_creation_authority.pubkey()],
        &tree_creation.instructions,
    );
    rpc.create_and_send_v1_transaction(
        &create_tree_syncs,
        payer_address,
        &[&payer, &tree_creation_authority],
        ComputeBudgetConfig::for_instruction_count(create_tree_syncs.len()),
    )?;

    let tree = tree_creation.tree;
    let tree_id = zolana_test_utils::nullifier_pda::tree_id(&rpc, &tree)?;

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
        rpc.create_and_send_v1_transaction(
            &[counter_sync],
            payer_address,
            &[&payer, &authority],
            ComputeBudgetConfig::for_instruction_count(1),
        )?;
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
    rpc.create_and_send_v1_transaction(
        &[interface_sync],
        payer_address,
        &[&payer, &authority],
        ComputeBudgetConfig::for_instruction_count(1),
    )?;

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
    let maker_view_tag = maker_deposit.view_tag();
    let maker_signature = maker_deposit.send(&rpc, &payer, tree, &payer)?;
    // The order authority is a PDA holding no viewing key, but a proofless
    // deposit publishes its UTXO in the clear, so the depositor-chosen view tag
    // reads it back from the indexer.
    let maker_deposited = wait_for_indexed_utxo(&indexer, maker_view_tag, maker_signature)
        .output_slot
        .proofless_output()
        .ok_or_else(|| anyhow!("indexed maker deposit is not a proofless UTXO"))?;
    let maker_input = SppProofInputUtxo::new(
        Utxo {
            owner: order_authority_address.signing_pubkey,
            asset: Address::new_from_array(maker_deposited.asset),
            amount: maker_deposited.amount,
            blinding: maker_deposited.blinding,
            ring_program_id: None,
            data: Data::default(),
        },
        order_nullifier_key,
    );
    assert_eq!(
        (maker_input.utxo.asset, maker_input.utxo.amount),
        (spl_mint, MAKER_SHIELD_SPL)
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
        tree_id,
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

// Submit a single (large) swap instruction as a transaction **v1** message:
// its 4096-byte limit is what holds a swap's account list and proof, which no
// longer fit a 1232-byte legacy packet. v1 has no address lookup table, and it
// carries the compute ceilings in the message header rather than in a
// compute-budget instruction. An unset ceiling means zero, not a default, so
// both are written. `payer` signs and pays.
pub fn send_v1(rpc: &SolanaRpc, payer: &dyn Signer, ix: Instruction) -> Result<Signature> {
    Ok(rpc.create_and_send_v1_transaction(
        std::slice::from_ref(&ix),
        payer.pubkey(),
        &[payer],
        ComputeBudgetConfig::new(TRANSACT_COMPUTE_UNIT_LIMIT),
    )?)
}
