//! Local-validator proofless shield test.

use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{
    event::{
        indexed_events_from_instruction_groups, instruction_may_emit_events, ProoflessShieldView,
    },
    instruction::{create_protocol_config, tag, CreateProtocolConfigData, ProoflessShieldAccounts},
    state::tree_account_size,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypair};
use zolana_program_test::{
    create_tree_instructions, index_events, parsed_instruction_from_compiled, protocol_config_pda,
    rpc_state_root, single_proofless_shield_view, zone_auth_pda, IndexedEvent, IndexedTransaction,
    TestIndexer, ZolanaProgramTest, ZONE_TEST_PROGRAM_ID,
};
use zolana_transaction::{AssetRegistry, Wallet, DEFAULT_TAG_WINDOW};

const RPC_URL_ENV: &str = "ZOLANA_LOCALNET_URL";
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const DEPOSIT_LAMPORTS: u64 = 750_000_000;

type TestResult<T = ()> = anyhow::Result<T>;

#[test]
fn proofless_shield_sol_on_localnet_prints_signatures() -> TestResult {
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

    let create_config = create_protocol_config(
        authority.pubkey(),
        protocol_config_pda(&program_id),
        CreateProtocolConfigData {
            authority: authority.pubkey().to_bytes(),
            merge_authorities: Vec::new(),
        },
    );
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
        program_id,
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

    let mut direct_recipient = Wallet::new(ShieldedKeypair::new()?)?;
    let direct_data = ZolanaProgramTest::wallet_sol_shield_data(
        DEPOSIT_LAMPORTS,
        &direct_recipient,
        &[3u8; BLINDING_LEN],
        0,
    )?;
    let direct_root_before = rpc_state_root(&rpc, &tree.pubkey())?;
    let direct_ix = direct_data.instruction(ProoflessShieldAccounts::sol(
        tree.pubkey(),
        depositor.pubkey(),
    ));
    let direct_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &[direct_ix],
        &payer.pubkey(),
        &[&payer, &depositor],
    )?;
    print_signature("proofless_shield", &direct_tx.signature);
    let direct_root_after = rpc_state_root(&rpc, &tree.pubkey())?;
    assert_ne!(direct_root_after, direct_root_before);
    let direct_view = single_proofless_shield_view(&direct_tx.events)?;
    assert_eq!(direct_root_after, indexer.root());
    assert_wallet_discovers(&mut direct_recipient, &direct_view)?;

    let mut zone_recipient = Wallet::new(ShieldedKeypair::new()?)?;
    let (_, zone_auth_bump) = zone_auth_pda(&zone_program_id);
    let mut zone_data = ZolanaProgramTest::wallet_zone_sol_shield_data_for_zone(
        DEPOSIT_LAMPORTS,
        &zone_recipient,
        &[5u8; BLINDING_LEN],
        0,
        ZONE_TEST_PROGRAM_ID,
        zone_auth_bump,
    )?;
    zone_data.policy_data_hash = Some([5u8; 32]);
    let zone_root_before = rpc_state_root(&rpc, &tree.pubkey())?;
    let zone_ix = zone_data.instruction(tree.pubkey(), depositor.pubkey());
    let zone_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &[zone_ix],
        &payer.pubkey(),
        &[&payer, &depositor],
    )?;
    print_signature("zone_proofless_shield", &zone_tx.signature);
    let zone_root_after = rpc_state_root(&rpc, &tree.pubkey())?;
    assert_ne!(zone_root_after, zone_root_before);
    let zone_view = single_proofless_shield_view(&zone_tx.events)?;
    assert_eq!(zone_root_after, indexer.root());
    assert_wallet_discovers(&mut zone_recipient, &zone_view)?;

    println!("localnet proofless shield test passed via {rpc_url}");
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
    index_events(indexer, &events)?;
    Ok(events)
}

fn produces_shielded_events(program_id: Pubkey, message: &Message) -> bool {
    message.instructions.iter().any(|instruction| {
        parsed_instruction_from_compiled(&message.account_keys, instruction, Some(1))
            .is_ok_and(|instruction| instruction_may_emit_events(program_id, &instruction))
    })
}

fn assert_wallet_discovers(wallet: &mut Wallet, view: &ProoflessShieldView) -> TestResult {
    let event = zolana_program_test::proofless_event_for_wallet(view);
    wallet.sync(
        &[],
        std::slice::from_ref(&event),
        &AssetRegistry::default(),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    assert_eq!(wallet.utxos.len(), 1);
    assert_eq!(wallet.utxos[0].hash, event.utxo_hash);
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
            data: vec![tag::PROOFLESS_SHIELD],
        }],
        None,
    );
    assert!(!produces_shielded_events(shielded_pool, &unrelated));

    let direct = Message::new(
        &[Instruction {
            program_id: shielded_pool,
            accounts: Vec::new(),
            data: vec![tag::PROOFLESS_SHIELD],
        }],
        None,
    );
    assert!(produces_shielded_events(shielded_pool, &direct));

    let zone_wrapper = Message::new(
        &[Instruction {
            program_id: other_program,
            accounts: vec![AccountMeta::new_readonly(shielded_pool, false)],
            data: vec![tag::ZONE_PROOFLESS_SHIELD],
        }],
        None,
    );
    assert!(produces_shielded_events(shielded_pool, &zone_wrapper));
}
