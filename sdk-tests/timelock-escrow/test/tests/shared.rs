use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    spawn_prover, AsyncProverClient, AsyncZolanaIndexer, ComputeBudgetConfig, ProverClient, Rpc,
    SolanaRpc, ZolanaClient, ZolanaIndexer,
};
use zolana_interface::{
    instruction::CreateProtocolConfig,
    state::{default_tree_fees, nullifier_tree_params},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{
    constants::BLINDING_LEN, NullifierKey, PublicKey, ShieldedAddress, ShieldedKeypair, SigningKey,
};
use zolana_program_test::create_tree_instructions;
use zolana_test_utils::{
    localnet::{LocalnetValidator, UpgradeableProgram},
    smart_account::{self, StandardSigners},
    test_validator_asserts::wait_for_indexed_utxo,
};
use zolana_transaction::{
    instructions::types::SppProofInputUtxo, utxo::Utxo, AssetRegistry, Data, Wallet, SOL_MINT,
};
use zolana_wallet::{Deposit, DepositParams};

// The whole per-transaction budget: the escrow forwards an SPP transact.
const TRANSACT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

pub const SHIELD_AMOUNT: u64 = 500_000_000;
pub const LOCK_AMOUNT: u64 = 300_000_000;

// The committed unlock timestamp is already in the past, so the withdraw in
// these tests always succeeds immediately: the timelock escrow program
// requires `now > unlock_timestamp`.
pub const UNLOCK_TIMESTAMP: u64 = 1_000_000;

// The SPP relayer deadline on the withdraw transact must be in the future
// even when the escrow's own `unlock_timestamp` is already in the past (the
// two are unrelated fields; see timelock_escrow.md's Escrow Terms section).
pub const SPP_RELAYER_DEADLINE: u64 = 2_000_000_000;

// The creator is the only actor: one ed25519 identity whose signing key
// doubles as the Solana fee payer (`to_solana_keypair`), holding the asset
// registry and synced spendable notes.
pub struct TestEnv {
    pub client: ZolanaClient<SolanaRpc>,
    pub tree: Pubkey,
    /// Raw id of `tree`, read from its account. Every UTXO commitment folds it
    /// in, so the SPP and escrow proofs must hash under the same value.
    pub tree_id: u16,
    pub creator: TestWallet,
    pub creator_input: SppProofInputUtxo,
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

    let escrow_program_id = timelock_escrow_program::ID.to_string();
    let escrow_program_so = std::env::var("TIMELOCK_ESCROW_PROGRAM_SO")
        .unwrap_or_else(|_| format!("{root}/target/deploy/timelock_escrow_program.so"));
    let spp_program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID).to_string();
    let spp_program_so = format!("{root}/target/deploy/shielded_pool_program.so");
    let smart_account_id = smart_account::SMART_ACCOUNT_PROGRAM_ID.to_string();
    let smart_account_so = format!("{root}/target/deploy/squads_smart_account_program.so");

    let account_dir = "/tmp/zolana-timelock-escrow-smart-account-accounts".to_string();
    let protocol_vault = smart_account::standard_accounts()
        .protocol_vault
        .to_string();
    LocalnetValidator {
        cli_bin: cli,
        working_dir: root.to_string(),
        rpc_port,
        photon_port,
        ledger: "/tmp/zolana-timelock-escrow-test-ledger".to_string(),
        account_dir,
        programs: vec![
            (escrow_program_id, escrow_program_so),
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
    let escrow_program = Pubkey::new_from_array(*timelock_escrow_program::ID.as_array());
    rpc.assert_executable(&escrow_program)?;

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

    // SOL only: asset id 1 is a built-in AssetRegistry::default() entry, no
    // SPL registration needed.
    let assets = AssetRegistry::default();

    let creator_solana_keypair = Keypair::new();
    let creator_seed: [u8; 32] = creator_solana_keypair.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let creator_shielded_keypair =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&creator_seed))?;
    rpc.airdrop(&creator_solana_keypair.pubkey(), 10_000_000_000)?;

    let escrow_nullifier_key = NullifierKey::from_secret([0u8; BLINDING_LEN]);
    let escrow_authority_address = ShieldedAddress {
        signing_pubkey: PublicKey::from_ed25519(
            timelock_escrow_sdk::escrow_authority_pda().as_array(),
        ),
        nullifier_pubkey: escrow_nullifier_key.pubkey()?,
        viewing_pubkey: creator_shielded_keypair.viewing_pubkey(),
    };
    let creator_deposit = Deposit::new(DepositParams {
        recipient: &escrow_authority_address,
        asset: SOL_MINT,
        amount: SHIELD_AMOUNT,
        spl_token_account: None,
        spl_token_program: Some(zolana_interface::pda::spl_token_program_id()),
        memo: None,
    })?;
    let creator_view_tag = creator_deposit.view_tag();
    let creator_signature = creator_deposit.send(&rpc, &payer, tree, &payer)?;
    // The escrow authority is a PDA holding no viewing key, but a proofless
    // deposit publishes its UTXO in the clear, so the depositor-chosen view tag
    // reads it back from the indexer.
    let creator_deposited = wait_for_indexed_utxo(&indexer, creator_view_tag, creator_signature)
        .output_slot
        .proofless_output()
        .ok_or_else(|| anyhow!("indexed creator deposit is not a proofless UTXO"))?;
    let creator_input = SppProofInputUtxo::new(
        Utxo {
            owner: escrow_authority_address.signing_pubkey,
            asset: Address::new_from_array(creator_deposited.asset),
            amount: creator_deposited.amount,
            blinding: creator_deposited.blinding,
            ring_program_id: None,
            data: Data::default(),
        },
        escrow_nullifier_key,
    );
    assert_eq!(
        (creator_input.utxo.asset, creator_input.utxo.amount),
        (SOL_MINT, SHIELD_AMOUNT)
    );

    let creator_address = creator_shielded_keypair
        .shielded_address()
        .map_err(|e| anyhow!("creator address: {e:?}"))?;

    let creator_wallet = Wallet::new(creator_address, assets.clone())
        .map_err(|e| anyhow!("creator wallet: {e:?}"))?;

    let client = ZolanaClient::new(
        rpc,
        indexer,
        ProverClient::default(),
        AsyncZolanaIndexer::new(indexer_url),
        AsyncProverClient::default(),
        Address::new_from_array(tree.to_bytes()),
    );

    Ok(TestEnv {
        client,
        tree,
        tree_id,
        creator: TestWallet {
            wallet: creator_wallet,
            keypair: creator_shielded_keypair,
        },
        creator_input,
    })
}

// Submit a single (large) instruction as a transaction **v1** message: its
// 4096-byte limit is what holds the escrow/withdraw account lists forwarding
// the SPP transact's tree accounts, which no longer fit a 1232-byte legacy
// packet. v1 has no address lookup table, and it carries the compute ceilings
// in the message header rather than in a compute-budget instruction. An unset
// ceiling means zero, not a default, so both are written. `payer` signs and pays.
pub fn send_v1(rpc: &SolanaRpc, payer: &dyn Signer, ix: Instruction) -> Result<Signature> {
    Ok(rpc.create_and_send_v1_transaction(
        std::slice::from_ref(&ix),
        payer.pubkey(),
        &[payer],
        ComputeBudgetConfig::new(TRANSACT_COMPUTE_UNIT_LIMIT),
    )?)
}
