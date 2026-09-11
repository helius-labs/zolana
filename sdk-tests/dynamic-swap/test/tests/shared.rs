// This module is included via `mod shared;` in every localnet test binary in
// this crate; each binary only exercises the subset of setup outputs relevant
// to its own flow, so unused-item warnings here are compilation-unit noise, not
// dead code in the crate as a whole. Only the localnet bring-up (`setup`) and
// the generic v1 transaction sender (`send_v1`) live here; every dynamic-swap
// domain flow is inlined into the test that uses it.
#![allow(dead_code)]

use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use dynamic_swap_sdk::{escrow_authority_pda, instructions::create_pair::CreatePair, pair_pda};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    spawn_prover, ComputeBudgetConfig, ProverClient, Rpc, SolanaRpc, ZolanaClient, ZolanaIndexer,
};
use zolana_interface::{
    instruction::{CreateAssetCounter, CreateProtocolConfig, CreateSplInterface},
    pda,
    state::{default_tree_fees, nullifier_tree_params},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{ShieldedKeypair, ShieldedPda, SigningKey};
use zolana_program_test::create_tree_instructions;
use zolana_test_utils::{
    localnet::{LocalnetValidator, UpgradeableProgram},
    smart_account::{self, StandardSigners},
    spl::{create_mint, create_token_account, mint_to},
    test_validator_asserts::wait_for_indexed_utxo,
};
use zolana_transaction::{
    instructions::transact::spp_proof_inputs::asset_field, utxo::Blinding, AssetRegistry, SOL_MINT,
};
use zolana_user_registry_interface::user_registry_program_id;
use zolana_wallet::{ensure_registered, Deposit, DepositParams};

// The whole per-transaction budget: an escrow settle verifies an SPP proof.
const TRANSACT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// SPL is the pair's source asset (escrowed by the taker); SOL is the pair's
/// destination asset (the maker funds it, the recipient is paid it on settle).
pub const SOURCE_ASSET_ID: u64 = 2;
pub const DESTINATION_ASSET_ID: u64 = 1; // SOL_ASSET_ID

pub const USER_SPL_SHIELD: u64 = 1_000_000_000;
pub const AUTHORITY_SOL_SHIELD: u64 = 2_000_000_000;

/// Each actor is one ed25519 identity: the wallet's signing key doubles as the
/// Solana fee payer (`to_solana_keypair`), and the wallet holds the asset
/// registry and (for real, non-PDA actors) synced spendable notes.
pub struct TestWallet {
    pub keypair: ShieldedKeypair,
}

impl TestWallet {
    pub fn address(&self) -> Result<zolana_keypair::ShieldedAddress> {
        self.keypair
            .shielded_address()
            .map_err(|e| anyhow!("shielded address: {e:?}"))
    }

    pub fn owner_hash(&self) -> Result<[u8; 32]> {
        self.keypair
            .owner_hash()
            .map_err(|e| anyhow!("owner hash: {e:?}"))
    }
}

pub struct TestEnv {
    pub client: ZolanaClient<SolanaRpc>,
    pub tree: Pubkey,
    /// Raw id of `tree`, read from its account. Every UTXO commitment folds it
    /// in, so the SPP and dynamic-swap proofs must hash under the same value.
    pub tree_id: u16,
    pub authority: TestWallet,
    pub user: TestWallet,
    pub spl_mint: Address,
    pub assets: AssetRegistry,
    /// The blinding of the user's own funding UTXO shielded in `setup()`
    /// (`USER_SPL_SHIELD` of `spl_mint`), read back from the indexer: SPP
    /// derives it from the leaf index the output lands at, so it is not known
    /// before the deposit executes.
    pub user_spl_blinding: Blinding,
}

pub fn setup() -> Result<TestEnv> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../..");
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| format!("{root}/target/debug/zolana"));
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_string());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_string());

    let dynamic_swap_program_id = dynamic_swap_program::ID.to_string();
    let dynamic_swap_program_so = std::env::var("DYNAMIC_SWAP_PROGRAM_SO")
        .unwrap_or_else(|_| format!("{root}/target/deploy/dynamic_swap_program.so"));
    let spp_program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID).to_string();
    let spp_program_so = format!("{root}/target/deploy/shielded_pool_program.so");
    let user_registry_id = user_registry_program_id().to_string();
    let user_registry_so = format!("{root}/target/deploy/zolana_user_registry.so");
    let smart_account_id = smart_account::SMART_ACCOUNT_PROGRAM_ID.to_string();
    let smart_account_so = format!("{root}/target/deploy/squads_smart_account_program.so");

    let account_dir = std::env::var("ZOLANA_DYNAMIC_SWAP_ACCOUNT_DIR")
        .unwrap_or_else(|_| "/tmp/zolana-dynamic-swap-inline-smart-account-accounts".to_string());
    let ledger = std::env::var("ZOLANA_DYNAMIC_SWAP_LEDGER")
        .unwrap_or_else(|_| "/tmp/zolana-dynamic-swap-inline-test-ledger".to_string());
    let protocol_vault = smart_account::standard_accounts()
        .protocol_vault
        .to_string();
    LocalnetValidator {
        cli_bin: cli,
        working_dir: root.to_string(),
        rpc_port,
        photon_port,
        ledger,
        account_dir,
        programs: vec![
            (dynamic_swap_program_id, dynamic_swap_program_so),
            (user_registry_id, user_registry_so),
            (smart_account_id, smart_account_so),
        ],
    }
    .start_with_upgradeable_programs(&[UpgradeableProgram {
        address: &spp_program_id,
        path: &spp_program_so,
        authority: &protocol_vault,
    }]);

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
    let indexer = ZolanaIndexer::new(indexer_url.clone());

    let spp_program = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    rpc.assert_executable(&spp_program)?;
    let dynamic_swap_program = Pubkey::new_from_array(*dynamic_swap_program::ID.as_array());
    rpc.assert_executable(&dynamic_swap_program)?;

    let payer = Keypair::new();
    let authority_solana = Keypair::new();
    let forester_authority = Keypair::new();
    let merge_authority = Keypair::new();
    let tree_creation_authority = Keypair::new();
    let ring_creation_authority = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 100_000_000_000)?;
    rpc.airdrop(
        &authority_solana.pubkey(),
        AUTHORITY_SOL_SHIELD + 10_000_000_000,
    )?;
    rpc.airdrop(&forester_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&merge_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&tree_creation_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&ring_creation_authority.pubkey(), 1_000_000_000)?;

    let payer_address = payer.pubkey();

    let accounts = smart_account::standard_accounts();
    for ix in accounts.create_ixs(
        &payer.pubkey(),
        StandardSigners {
            protocol: authority_solana.pubkey(),
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
        &[authority_solana.pubkey()],
        &[create_config_ix],
    );
    rpc.create_and_send_v1_transaction(
        &[create_config_sync],
        payer_address,
        &[&payer, &authority_solana],
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

    // Register an SPL asset with the pool so the user can escrow it as the
    // pair's source asset.
    let spl_mint = create_mint(&rpc, &payer)?;
    if rpc.get_account(pda::spl_asset_counter())?.is_none() {
        let counter_ix = CreateAssetCounter {
            authority: accounts.protocol_vault,
        }
        .instruction();
        let counter_sync = smart_account::execute_sync_ix(
            &accounts.protocol_settings,
            0,
            &[authority_solana.pubkey()],
            &[counter_ix],
        );
        rpc.create_and_send_v1_transaction(
            &[counter_sync],
            payer_address,
            &[&payer, &authority_solana],
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
        &[authority_solana.pubkey()],
        &[interface_ix],
    );
    rpc.create_and_send_v1_transaction(
        &[interface_sync],
        payer_address,
        &[&payer, &authority_solana],
        ComputeBudgetConfig::for_instruction_count(1),
    )?;

    let spl_funding = create_token_account(&rpc, &payer, &spl_mint, &payer.pubkey())?;
    mint_to(&rpc, &payer, &spl_mint, &spl_funding, USER_SPL_SHIELD)?;

    let authority_seed: [u8; 32] = authority_solana.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let authority_shielded_keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&authority_seed))?;

    let user_solana = Keypair::new();
    rpc.airdrop(&user_solana.pubkey(), 10_000_000_000)?;
    let user_seed: [u8; 32] = user_solana.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let user_shielded_keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&user_seed))?;

    // Shield the user's SPL (the source asset it will escrow). The pool's own
    // liquidity is bootstrapped separately per-pair by each test (a zero-amount
    // deposit owned by that pair's `pool_authority` PDA), not funded here.
    let user_address = user_shielded_keypair
        .shielded_address()
        .map_err(|e| anyhow!("user address: {e:?}"))?;
    let user_deposit = Deposit::new(DepositParams {
        recipient: &user_address,
        asset: spl_mint,
        amount: USER_SPL_SHIELD,
        spl_token_account: Some(spl_funding),
        spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
        memo: None,
    })?;
    let user_view_tag = user_deposit.view_tag();
    let user_signature = user_deposit.send(&rpc, &payer, tree, &payer)?;
    // A proofless deposit publishes its UTXO in the clear, so read it back from
    // the indexer.
    let user_spl_blinding = wait_for_indexed_utxo(&indexer, user_view_tag, user_signature)
        .output_slot
        .proofless_output()
        .ok_or_else(|| anyhow!("indexed user deposit is not a proofless UTXO"))?
        .blinding;

    // Register both parties in the user directory (keyed by their Solana
    // pubkeys). On settle, the caller resolves the recipient's shielded address
    // from `Escrow.owner` alone -- its owner hash reconstructs the escrow terms
    // and its viewing pubkey derives the shared escrow viewing key.
    ensure_registered(&rpc, &authority_solana, &authority_shielded_keypair)
        .map_err(|e| anyhow!("register authority: {e:?}"))?;
    ensure_registered(&rpc, &user_solana, &user_shielded_keypair)
        .map_err(|e| anyhow!("register user: {e:?}"))?;

    let mut assets = AssetRegistry::default();
    assets
        .insert(SOURCE_ASSET_ID, spl_mint)
        .map_err(|e| anyhow!("asset registry insert: {e:?}"))?;

    let client = ZolanaClient::new(
        rpc,
        indexer,
        ProverClient::default(),
        zolana_client::AsyncZolanaIndexer::new(indexer_url),
        zolana_client::AsyncProverClient::default(),
        Address::new_from_array(tree.to_bytes()),
    );

    Ok(TestEnv {
        client,
        tree,
        tree_id,
        authority: TestWallet {
            keypair: authority_shielded_keypair,
        },
        user: TestWallet {
            keypair: user_shielded_keypair,
        },
        spl_mint,
        assets,
        user_spl_blinding,
    })
}

/// The maker-derived shielded identity of the pair's escrow_authority PDA
/// (`ShieldedPda::from_viewing_key`); its nullifier pubkey is published in the
/// `Pair` account at `create_pair`, so `create_escrow` binds
/// `Poseidon(solana_owner_identity(pda), nullifier_pk)` as the order owner hash.
pub fn escrow_authority_identity(
    authority: &ShieldedKeypair,
    pair: &Pubkey,
) -> Result<ShieldedPda> {
    ShieldedPda::from_viewing_key(escrow_authority_pda(pair), &authority.viewing_key)
        .map_err(|e| anyhow!("escrow authority identity: {e:?}"))
}

/// `setup()` plus a registered SPL(source)->SOL(destination) pair at `price`.
/// There is no shared pool; the maker funds each escrow directly, so this only
/// creates the pair account. Returns the env and the pair PDA. Tests that
/// exercise `create_pair` itself (pair/negative) keep plain `setup()`.
pub fn setup_with_pair(price: u64) -> Result<(TestEnv, Pubkey)> {
    let env = setup()?;
    let authority_solana = &env.authority.keypair;
    let pair = pair_pda(
        &authority_solana.pubkey(),
        SOURCE_ASSET_ID,
        DESTINATION_ASSET_ID,
    );
    let authority_owner_hash = env.authority.owner_hash()?;
    let source_asset = asset_field(&env.spl_mint).map_err(|e| anyhow!("source asset: {e:?}"))?;
    let destination_asset =
        asset_field(&SOL_MINT).map_err(|e| anyhow!("destination asset: {e:?}"))?;
    let escrow_authority_nullifier_pubkey =
        escrow_authority_identity(&env.authority.keypair, &pair)?
            .nullifier_pubkey()
            .map_err(|e| anyhow!("escrow authority nullifier pubkey: {e:?}"))?;
    let create_pair_ix = CreatePair {
        payer: authority_solana.pubkey(),
        pair,
        price,
        source_asset_id: SOURCE_ASSET_ID,
        destination_asset_id: DESTINATION_ASSET_ID,
        authority_owner_hash,
        source_asset,
        destination_asset,
        escrow_authority_nullifier_pubkey,
    }
    .instruction()
    .map_err(|e| anyhow!("create_pair instruction: {e:?}"))?;
    env.client
        .rpc()
        .create_and_send_v1_transaction(
            &[create_pair_ix],
            authority_solana.pubkey(),
            &[&authority_solana],
            ComputeBudgetConfig::for_instruction_count(1),
        )
        .map_err(|e| anyhow!("send create_pair: {e:?}"))?;
    Ok((env, pair))
}

/// Photon indexes a send asynchronously, poll until the value appears or the deadline passes.
pub fn wait_until<T>(what: &str, mut poll: impl FnMut() -> Result<Option<T>>) -> Result<T> {
    const DEADLINE: Duration = Duration::from_secs(30);
    const INTERVAL: Duration = Duration::from_millis(500);
    let start = Instant::now();
    loop {
        if let Some(value) = poll()? {
            return Ok(value);
        }
        if start.elapsed() >= DEADLINE {
            return Err(anyhow!("{what} did not appear within {DEADLINE:?}"));
        }
        std::thread::sleep(INTERVAL);
    }
}

/// The validator's RPC connection can transiently drop a request right after
/// a long CPU-bound stretch in this same process (e.g. the ~14s in-process
/// Groth16 proving `escrow_open`/`escrow_settle` need), even though the
/// validator itself is healthy -- retry a few times with a short backoff
/// rather than fail the whole flow on one dropped connection.
pub fn get_slot_with_retry(client: &solana_rpc_client::rpc_client::RpcClient) -> Result<u64> {
    const MAX_ATTEMPTS: usize = 5;
    let mut last_err = None;
    for attempt in 0..MAX_ATTEMPTS {
        match client.get_slot() {
            Ok(slot) => return Ok(slot),
            Err(e) => {
                last_err = Some(e);
                if attempt + 1 < MAX_ATTEMPTS {
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }
    Err(anyhow!(
        "get_slot: {}",
        last_err.expect("loop always sets last_err before exhausting attempts")
    ))
}

/// Submit a single (large) instruction as a transaction **v1** message: its
/// 4096-byte limit is what holds the dynamic-swap account lists once the
/// ciphertexts are included, which no longer fit a 1232-byte legacy packet. v1
/// has no address lookup table, and it carries the compute ceilings in the
/// message header rather than in a compute-budget instruction. An unset ceiling
/// means zero, not a default, so both are written. `fee_payer` pays and signs,
/// plus any `extra_signers` (e.g. `create_escrow`'s `owner`, which must sign
/// alongside the pair authority).
pub fn send_v1(
    rpc: &SolanaRpc,
    fee_payer: &dyn Signer,
    extra_signers: &[&dyn Signer],
    ix: Instruction,
) -> Result<Signature> {
    let mut signers: Vec<&dyn Signer> = vec![fee_payer];
    signers.extend(extra_signers.iter().copied());
    Ok(rpc.create_and_send_v1_transaction(
        std::slice::from_ref(&ix),
        fee_payer.pubkey(),
        &signers,
        ComputeBudgetConfig::new(TRANSACT_COMPUTE_UNIT_LIMIT),
    )?)
}
