use anyhow::{anyhow, Result};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    spawn_prover, ComputeBudgetConfig, IndexerRpcConfig, Rpc, SolanaRpc, ZolanaIndexer,
};
use zolana_interface::{
    pda,
    state::{default_tree_fees, nullifier_tree_params},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_program::instruction::{AssetDeposit, CreateProtocolConfig, Deposit, DepositAsset};
use zolana_program_test::{
    create_tree_instructions,
    localnet::{LocalnetValidator, UpgradeableProgram},
    next_tree_id, workspace_path,
};
use zolana_test_utils::{
    localnet::env_localnet_ports,
    smart_account::{self, StandardSigners},
};
use zolana_transaction::{decrypt_spendable, AssetRegistry, WalletUtxo, SOL_MINT};
use zolana_user_registry_interface::{
    instruction::{register, set_merging_enabled, RegisterData},
    user_record_pda,
};

pub mod cached_merge;
pub mod merge;

pub struct SetupContext {
    pub rpc_url: String,
    pub indexer_url: String,
    pub prover_url: String,
    /// Raw id of the pool's only tree. The account is `pda::tree(tree_id)`,
    /// derived where one is needed rather than carried alongside.
    pub tree_id: u16,
    pub sender: ShieldedKeypair,
    pub recipient_address: ShieldedAddress,
}

pub fn setup() -> Result<SetupContext> {
    let deploy = |file: &str| workspace_path("target/deploy").join(file);
    let account_dir = std::env::temp_dir().join("zolana-client-example-accounts");
    smart_account::write_program_config_fixture(&account_dir);
    LocalnetValidator {
        cli_bin: std::env::var("ZOLANA_CLI_BIN")
            .map(Into::into)
            .unwrap_or_else(|_| workspace_path("target/debug/zolana")),
        working_dir: workspace_path(""),
        ports: env_localnet_ports(),
        account_dir,
        log_dir: workspace_path("test-ledger"),
        programs: vec![
            (
                zolana_user_registry_interface::user_registry_program_id(),
                deploy("zolana_user_registry.so"),
            ),
            (
                smart_account::SMART_ACCOUNT_PROGRAM_ID,
                deploy("squads_smart_account_program.so"),
            ),
        ],
        slot_time: None,
    }
    .start_with_upgradeable_programs(&[UpgradeableProgram {
        address: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        path: deploy("shielded_pool_program.so"),
        authority: smart_account::standard_accounts().protocol_vault,
    }])?;

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
    let prover_url =
        std::env::var("ZOLANA_PROVER_URL").unwrap_or_else(|_| "http://127.0.0.1:3001".to_string());

    let mut rpc = SolanaRpc::new(rpc_url.clone());

    rpc.assert_executable(&Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID))?;

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
        rpc.create_and_send_transaction(
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
        protocol_authority: accounts.protocol_vault,
        fee_authority: accounts.protocol_vault,
        tree_creation_authority: accounts.tree_vault,
        tree_creation_is_permissionless: false,
        forester_authority: accounts.forester_vault,
        ring_creation_authority: accounts.ring_vault,
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
    rpc.create_and_send_transaction(
        &[create_config_sync],
        payer_address,
        &[&payer, &authority],
        ComputeBudgetConfig::for_instruction_count(1),
    )?;

    // Read before the tree exists, so it is the id the creation will take.
    let tree_id = next_tree_id(&rpc)?;
    let tree_creation = create_tree_instructions(
        &rpc,
        &payer.pubkey(),
        &accounts.tree_vault,
        nullifier_tree_params(),
        default_tree_fees(nullifier_tree_params().input_queue_zkp_batch_size)
            .ok_or_else(|| anyhow::anyhow!("default tree fees do not fit the zkp batch size"))?,
    )?;
    let create_tree_syncs = smart_account::execute_sync_each(
        &accounts.tree_settings,
        0,
        &[tree_creation_authority.pubkey()],
        &tree_creation.instructions,
    );
    rpc.create_and_send_transaction(
        &create_tree_syncs,
        payer_address,
        &[&payer, &tree_creation_authority],
        ComputeBudgetConfig::for_instruction_count(create_tree_syncs.len()),
    )?;

    let sender = new_wallet(&mut rpc)?;
    let recipient_address = new_wallet(&mut rpc)?.shielded_address()?;

    Ok(SetupContext {
        rpc_url,
        indexer_url,
        prover_url,
        tree_id,
        sender,
        recipient_address,
    })
}

fn new_wallet(rpc: &mut SolanaRpc) -> Result<ShieldedKeypair> {
    let solana_keypair = Keypair::new();
    let keypair = ShieldedKeypair::from_keypair(&solana_keypair)?;
    rpc.airdrop(&solana_keypair.pubkey(), 10_000_000_000)?;
    Ok(keypair)
}

/// Deposits are batched only to stay inside the 4 KB transaction v1 limit.
const DEPOSITS_PER_TRANSACTION: usize = 12;

/// What the merge examples start from, on top of [`setup`]: a sender
/// registered for merging, a rent sponsor for the cache account, and a private
/// balance already split across many UTXOs.
pub struct MergeScenario {
    pub rpc_url: String,
    pub indexer_url: String,
    pub prover_url: String,
    pub tree: Pubkey,
    pub tree_id: u16,
    pub sender: ShieldedKeypair,
    pub recipient: ShieldedKeypair,
    /// Funds the cache account, is its write authority, and sends the merge.
    /// The sender signs no merge: its record opted into merging.
    pub rent_sponsor: Keypair,
    /// The sender's spendable UTXOs, one per deposit.
    pub utxos: Vec<WalletUtxo>,
}

/// Registers the sender, opts the record into merging, funds a rent sponsor,
/// and splits `utxo_count * amount` lamports of the sender's private balance
/// into `utxo_count` UTXOs.
pub fn setup_merge_scenario(utxo_count: usize, amount: u64) -> Result<MergeScenario> {
    let SetupContext {
        rpc_url,
        indexer_url,
        prover_url,
        tree_id,
        sender,
        recipient_address: _,
    } = setup()?;
    let tree = pda::tree(tree_id);

    let mut rpc = SolanaRpc::new(rpc_url.clone());
    // The recipient is kept as a keypair here, not just an address, so the
    // example can decrypt what it received.
    let recipient = new_wallet(&mut rpc)?;
    // The sponsor pays for the merge as well as the cache rent: the nullifier
    // PDAs and the forester fee come out of this balance.
    let rent_sponsor = Keypair::new();
    rpc.airdrop(&rent_sponsor.pubkey(), 2_000_000_000)?;

    // `merge_transact` reads the registry record for the owner's signing and
    // nullifier keys, and rejects an owner that has not opted into merging.
    let user_record = user_record_pda(&sender.pubkey()).0;
    rpc.create_and_send_transaction(
        &[
            register(
                user_record,
                sender.pubkey(),
                sender.pubkey(),
                RegisterData {
                    owner_p256: None,
                    nullifier_pubkey: sender.nullifier_key.pubkey()?,
                    viewing_pubkey: *sender.viewing_pubkey().as_bytes(),
                },
            ),
            set_merging_enabled(user_record, sender.pubkey(), true),
        ],
        sender.pubkey(),
        &[&sender],
        ComputeBudgetConfig::for_instruction_count(2),
    )?;

    let shielded_address = sender.shielded_address()?;
    let view_tag = shielded_address.confidential_view_tag()?;
    let owner = shielded_address.owner_hash()?;
    let mut slot = 0;
    for batch in (0..utxo_count).step_by(DEPOSITS_PER_TRANSACTION) {
        let count = DEPOSITS_PER_TRANSACTION.min(utxo_count - batch);
        let deposit_ix = Deposit {
            tree,
            depositor: sender.pubkey(),
            deposits: (0..count)
                .map(|_| AssetDeposit {
                    asset: DepositAsset::Sol,
                    view_tag,
                    owner,
                    amount,
                    utxo_data: None,
                    memo: None,
                })
                .collect(),
        }
        .instruction()?;
        let signature = rpc.create_and_send_transaction(
            &[deposit_ix],
            sender.pubkey(),
            &[&sender],
            ComputeBudgetConfig::new(1_400_000),
        )?;
        slot = rpc
            .get_signature_statuses(vec![signature])?
            .first()
            .and_then(|status| status.as_ref())
            .map(|status| status.slot)
            .ok_or_else(|| anyhow!("deposit {signature} has no confirmed slot"))?;
    }

    let indexer = ZolanaIndexer::new(&indexer_url);
    let response = indexer.get_shielded_transactions_by_tags(
        vec![view_tag],
        None,
        Some(50),
        Some(IndexerRpcConfig::at_slot(slot)),
    )?;
    let balances = decrypt_spendable(&sender, &response.transactions, &AssetRegistry::default())
        .map_err(|e| anyhow!("decrypt sender transactions: {e:?}"))?
        .balances;
    let utxos = balances
        .get_balance(SOL_MINT)
        .ok_or_else(|| anyhow!("sender has no SOL balance"))?
        .utxos
        .clone();
    if utxos.len() != utxo_count {
        return Err(anyhow!(
            "expected {utxo_count} deposited utxos, indexer returned {}",
            utxos.len()
        ));
    }

    Ok(MergeScenario {
        rpc_url,
        indexer_url,
        prover_url,
        tree,
        tree_id,
        sender,
        recipient,
        rent_sponsor,
        utxos,
    })
}
