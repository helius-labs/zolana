//! Local-validator proofless deposit test.

use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::{prover::field::right_align, Rpc, SolanaRpc};
use zolana_event::{indexed_events_from_instruction_groups, instruction_may_emit_events};
use zolana_interface::{
    instruction::{
        encode_instruction, tag, CreateProtocolConfig, CreateZoneConfigData, Deposit, ZoneDeposit,
    },
    pda,
    state::tree_account_size,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::{
    create_tree_instructions, deposit_outputs_from_event, index_events,
    parsed_instruction_from_compiled, rpc_state_root, single_deposit_view, DepositOutput,
    IndexedEvent, IndexedTransaction, TestIndexer, ZolanaProgramTest, ZONE_TEST_PROGRAM_ID,
};
use zolana_test_utils::{
    spl::{create_mint, create_spl_interface, create_token_account, ensure_asset_counter, mint_to},
    test_validator_asserts::{fetch_account, token_amount},
};
use zolana_transaction::{
    AssetRegistry, LocalWalletAuthority, SyncWalletAuthority, Wallet, DEFAULT_TAG_WINDOW,
};

const RPC_URL_ENV: &str = "ZOLANA_LOCALNET_URL";
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const DEPOSIT_LAMPORTS: u64 = 750_000_000;
const DEPOSIT_TOKENS: u64 = 1_000;

type TestResult<T = ()> = anyhow::Result<T>;

#[test]
fn deposit_sol_on_localnet_prints_signatures() -> TestResult {
    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());

    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let zone_program_id = Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID);
    let mut rpc = SolanaRpc::new(rpc_url.clone());
    let mut indexer = TestIndexer::new();
    rpc.assert_executable(&program_id)?;
    rpc.assert_executable(&zone_program_id)?;

    let payer = Keypair::new();
    let authority = Keypair::new();
    let depositor = Keypair::new();
    print_signature(
        "airdrop payer",
        &rpc.airdrop(&payer.pubkey(), 20_000_000_000)?,
    );
    print_signature(
        "airdrop authority",
        &rpc.airdrop(&authority.pubkey(), 1_000_000_000)?,
    );
    print_signature(
        "airdrop depositor",
        &rpc.airdrop(&depositor.pubkey(), 5_000_000_000)?,
    );

    let authority_bytes = authority.pubkey().to_bytes();
    let create_config = CreateProtocolConfig {
        authority: authority.pubkey(),
        protocol_authority: authority_bytes.into(),
        tree_creation_authority: authority_bytes.into(),
        tree_creation_is_permissionless: false,
        forester_authority: authority_bytes.into(),
        zone_creation_authority: authority_bytes.into(),
        zone_creation_is_permissionless: false,
        spl_interface_creation_is_permissionless: false,
    }
    .instruction();
    let create_config_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &[create_config],
        &authority.pubkey(),
        &[&authority],
    )?;
    print_signature("create_protocol_config", &create_config_tx.signature);

    let tree = Keypair::new();
    let create_tree = create_tree_instructions(
        &rpc,
        &payer.pubkey(),
        &authority.pubkey(),
        &tree.pubkey(),
        tree_account_size() as u64,
    )?;
    let create_tree_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &create_tree,
        &payer.pubkey(),
        &[&payer, &tree, &authority],
    )?;
    print_signature("create_tree", &create_tree_tx.signature);

    let direct_keypair = ShieldedKeypair::new()?;
    let mut direct_recipient =
        Wallet::new(direct_keypair.shielded_address()?, AssetRegistry::default())?;
    let direct_data = ZolanaProgramTest::wallet_sol_shield_data(
        DEPOSIT_LAMPORTS,
        &direct_recipient.identity,
        &right_align(&[3u8; 31]),
        0,
    )?;
    let direct_root_before = rpc_state_root(&rpc, &tree.pubkey())?;
    let direct_ix = Deposit {
        tree: tree.pubkey(),
        depositor: depositor.pubkey(),
        deposits: vec![direct_data],
    }
    .instruction()?;
    let direct_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &[direct_ix],
        &payer.pubkey(),
        &[&payer, &depositor],
    )?;
    print_signature("deposit", &direct_tx.signature);
    let direct_root_after = rpc_state_root(&rpc, &tree.pubkey())?;
    assert_ne!(direct_root_after, direct_root_before);
    let direct_view = single_deposit_view(&direct_tx.events)?;
    assert_eq!(direct_root_after, indexer.root());
    assert_wallet_discovers(
        &mut direct_recipient,
        &LocalWalletAuthority::new(Pubkey::default(), &direct_keypair),
        &direct_view,
    )?;

    let zone_config = pda::zone_auth(&zone_program_id).0;
    let create_zone_config = Instruction {
        program_id: zone_program_id,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(zone_config, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(program_id, false),
        ],
        data: encode_instruction(
            tag::CREATE_ZONE_CONFIG,
            &CreateZoneConfigData {
                program_id: Address::new_from_array(zone_program_id.to_bytes()),
                authority: Address::new_from_array(authority.pubkey().to_bytes()),
                zone_authority_transact_is_enabled: true,
            },
        ),
    };
    send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &[create_zone_config],
        &authority.pubkey(),
        &[&authority],
    )?;

    let mint = create_mint(&rpc, &payer)?;
    let user_token = create_token_account(&rpc, &payer, &mint, &depositor.pubkey())?;
    mint_to(&rpc, &payer, &mint, &user_token, DEPOSIT_TOKENS)?;
    ensure_asset_counter(&rpc, &authority)?;
    let (_, vault) = create_spl_interface(&rpc, &authority, &mint)?;
    let vault_before = token_amount(&fetch_account(&rpc, &vault)?);
    let user_token_before = token_amount(&fetch_account(&rpc, &user_token)?);

    let zone_sol_keypair = ShieldedKeypair::new()?;
    let mut zone_sol_recipient = Wallet::new(
        zone_sol_keypair.shielded_address()?,
        AssetRegistry::default(),
    )?;
    let mut zone_sol_data = ZolanaProgramTest::wallet_zone_sol_shield_data(
        DEPOSIT_LAMPORTS,
        &zone_sol_recipient.identity,
        &right_align(&[5u8; 31]),
        0,
    )?;
    zone_sol_data.zone_data_hash = [5u8; 32];
    zone_sol_data.zone_data = vec![5, 6];

    let zone_spl_keypair = ShieldedKeypair::new()?;
    let spl_assets = AssetRegistry::new([(2, Address::new_from_array(mint.to_bytes()))])?;
    let mut zone_spl_recipient = Wallet::new(zone_spl_keypair.shielded_address()?, spl_assets)?;
    let mut zone_spl_data = ZolanaProgramTest::wallet_zone_spl_shield_data(
        DEPOSIT_TOKENS,
        mint,
        user_token,
        &zone_spl_recipient.identity,
        &right_align(&[7u8; 31]),
        1,
    )?;
    zone_spl_data.zone_data_hash = [7u8; 32];
    zone_spl_data.zone_data = vec![7, 8];

    let zone_root_before = rpc_state_root(&rpc, &tree.pubkey())?;
    let zone_ix = ZoneDeposit {
        tree: tree.pubkey(),
        depositor: depositor.pubkey(),
        zone_program_id,
        deposits: vec![zone_sol_data, zone_spl_data],
    }
    .instruction()?;
    let zone_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &[zone_ix],
        &payer.pubkey(),
        &[&payer, &depositor],
    )?;
    print_signature("zone_deposit", &zone_tx.signature);
    let zone_root_after = rpc_state_root(&rpc, &tree.pubkey())?;
    assert_ne!(zone_root_after, zone_root_before);
    let zone_event = zone_tx
        .events
        .first()
        .ok_or_else(|| anyhow::anyhow!("zone batch emitted no event"))?;
    let zone_views = deposit_outputs_from_event(zone_event)?;
    assert_eq!(zone_views.len(), 2);
    assert_eq!(zone_views[0].output.asset, [0u8; 32]);
    assert_eq!(zone_views[0].output.zone_data_hash, Some([5u8; 32]));
    assert_eq!(zone_views[0].output.zone_data, Some(vec![5, 6]));
    assert_eq!(zone_views[1].output.asset, mint.to_bytes());
    assert_eq!(zone_views[1].output.zone_data_hash, Some([7u8; 32]));
    assert_eq!(zone_views[1].output.zone_data, Some(vec![7, 8]));
    assert_eq!(
        token_amount(&fetch_account(&rpc, &vault)?),
        vault_before + DEPOSIT_TOKENS
    );
    assert_eq!(
        token_amount(&fetch_account(&rpc, &user_token)?),
        user_token_before - DEPOSIT_TOKENS
    );
    assert_eq!(zone_root_after, indexer.root());
    assert_wallet_discovers(
        &mut zone_sol_recipient,
        &LocalWalletAuthority::new(Pubkey::default(), &zone_sol_keypair),
        &zone_views[0],
    )?;
    assert_wallet_discovers(
        &mut zone_spl_recipient,
        &LocalWalletAuthority::new(Pubkey::default(), &zone_spl_keypair),
        &zone_views[1],
    )?;

    println!("localnet proofless deposit test passed via {rpc_url}");
    Ok(())
}

fn send_indexed(
    rpc: &mut SolanaRpc,
    indexer: &mut TestIndexer,
    program_id: Pubkey,
    ixs: &[solana_instruction::Instruction],
    payer: &Pubkey,
    signers: &[&Keypair],
) -> TestResult<zolana_program_test::IndexedTransaction> {
    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = Message::new(ixs, Some(payer));
    let produces_events = produces_shielded_events(program_id, &message);
    let transaction = Transaction::new(signers, message, blockhash);
    let signature = rpc.send_transaction(&transaction)?;
    let events = if produces_events {
        fetch_indexed_events(rpc, indexer, program_id, &signature)?
    } else {
        Vec::new()
    };
    Ok(IndexedTransaction { signature, events })
}

fn fetch_indexed_events(
    rpc: &SolanaRpc,
    indexer: &mut TestIndexer,
    program_id: Pubkey,
    signature: &Signature,
) -> TestResult<Vec<IndexedEvent>> {
    let confirmed = rpc.fetch_confirmed_instruction_groups(signature)?;
    let events = indexed_events_from_instruction_groups(program_id, &confirmed.groups);
    index_events(indexer, &events, *signature)?;
    Ok(events)
}

fn produces_shielded_events(program_id: Pubkey, message: &Message) -> bool {
    message.instructions.iter().any(|instruction| {
        parsed_instruction_from_compiled(&message.account_keys, instruction, Some(1))
            .is_ok_and(|instruction| instruction_may_emit_events(program_id, &instruction))
    })
}

fn assert_wallet_discovers<A: SyncWalletAuthority + ?Sized>(
    wallet: &mut Wallet,
    authority: &A,
    view: &DepositOutput,
) -> TestResult {
    wallet.sync(
        authority,
        &[view.to_shielded_transaction(Signature::default())],
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    assert_eq!(wallet.utxos.len(), 1);
    assert_eq!(
        wallet.utxos.first().expect("one utxo").output_context.hash,
        view.utxo_hash
    );
    Ok(())
}

fn print_signature(label: &str, signature: &solana_signature::Signature) {
    println!("{label}: {signature}");
}

#[test]
fn shielded_event_detection_checks_program_context() {
    use solana_instruction::{AccountMeta, Instruction};

    let shielded_pool = Pubkey::new_unique();
    let other_program = Pubkey::new_unique();

    let unrelated = Message::new(
        &[Instruction {
            program_id: other_program,
            accounts: Vec::new(),
            data: vec![tag::DEPOSIT],
        }],
        None,
    );
    assert!(!produces_shielded_events(shielded_pool, &unrelated));

    let direct = Message::new(
        &[Instruction {
            program_id: shielded_pool,
            accounts: Vec::new(),
            data: vec![tag::DEPOSIT],
        }],
        None,
    );
    assert!(produces_shielded_events(shielded_pool, &direct));

    let zone_wrapper = Message::new(
        &[Instruction {
            program_id: other_program,
            accounts: vec![AccountMeta::new_readonly(shielded_pool, false)],
            data: vec![tag::ZONE_DEPOSIT],
        }],
        None,
    );
    assert!(produces_shielded_events(shielded_pool, &zone_wrapper));

    let direct_transact = Message::new(
        &[Instruction {
            program_id: shielded_pool,
            accounts: Vec::new(),
            data: vec![tag::TRANSACT],
        }],
        None,
    );
    assert!(produces_shielded_events(shielded_pool, &direct_transact));

    let zone_transact_wrapper = Message::new(
        &[Instruction {
            program_id: other_program,
            accounts: vec![AccountMeta::new_readonly(shielded_pool, false)],
            data: vec![tag::ZONE_TRANSACT],
        }],
        None,
    );
    assert!(produces_shielded_events(
        shielded_pool,
        &zone_transact_wrapper
    ));

    let zone_merge_wrapper = Message::new(
        &[Instruction {
            program_id: other_program,
            accounts: vec![AccountMeta::new_readonly(shielded_pool, false)],
            data: vec![tag::ZONE_MERGE_TRANSACT],
        }],
        None,
    );
    assert!(produces_shielded_events(shielded_pool, &zone_merge_wrapper));

    let false_positive = Message::new(
        &[Instruction {
            program_id: other_program,
            accounts: vec![AccountMeta::new_readonly(shielded_pool, false)],
            data: vec![tag::TRANSACT],
        }],
        None,
    );
    assert!(!produces_shielded_events(shielded_pool, &false_positive));
}
