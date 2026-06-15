//! Local-validator proofless shield test.

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{
        create_protocol_config, proofless_shield, zone_proofless_shield, CreateProtocolConfigData,
        ProoflessShieldEvent,
    },
    state::tree_account_size,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypair};
use zolana_program_test::{
    create_tree_instructions, protocol_config_pda, rpc_state_root, single_proofless_shield_event,
    zone_auth_pda, Rpc, SolanaRpc, ZolanaProgramTest, ZONE_TEST_PROGRAM_ID,
};
use zolana_transaction::Wallet;

const RPC_URL_ENV: &str = "ZOLANA_LOCALNET_URL";
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const DEPOSIT_LAMPORTS: u64 = 750_000_000;

type TestResult<T = ()> = anyhow::Result<T>;

#[test]
fn proofless_shield_sol_on_localnet_prints_signatures() -> TestResult {
    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());

    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let zone_program_id = Pubkey::new_from_array(ZONE_TEST_PROGRAM_ID);
    let mut rpc = SolanaRpc::new(rpc_url.clone(), program_id);
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
    let create_config_tx =
        rpc.create_and_send_transaction(&[create_config], &authority.pubkey(), &[&authority])?;
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
    let create_tree_tx = rpc.create_and_send_transaction(
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
    let direct_ix = proofless_shield(tree.pubkey(), depositor.pubkey(), &direct_data);
    let direct_tx =
        rpc.create_and_send_transaction(&[direct_ix], &payer.pubkey(), &[&payer, &depositor])?;
    print_signature("proofless_shield", &direct_tx.signature);
    let direct_root_after = rpc_state_root(&rpc, &tree.pubkey())?;
    assert_ne!(direct_root_after, direct_root_before);
    let direct_event = single_proofless_shield_event(&direct_tx.events)?;
    assert_eq!(direct_root_after, rpc.indexer().root());
    assert_wallet_discovers(&mut direct_recipient, &direct_event)?;

    let mut zone_recipient = Wallet::new(ShieldedKeypair::new()?)?;
    let (zone_auth, zone_auth_bump) = zone_auth_pda(&zone_program_id);
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
    let zone_ix = zone_proofless_shield(
        zone_program_id,
        zone_auth,
        tree.pubkey(),
        depositor.pubkey(),
        &zone_data,
    );
    let zone_tx =
        rpc.create_and_send_transaction(&[zone_ix], &payer.pubkey(), &[&payer, &depositor])?;
    print_signature("zone_proofless_shield", &zone_tx.signature);
    let zone_root_after = rpc_state_root(&rpc, &tree.pubkey())?;
    assert_ne!(zone_root_after, zone_root_before);
    let zone_event = single_proofless_shield_event(&zone_tx.events)?;
    assert_eq!(zone_root_after, rpc.indexer().root());
    assert_wallet_discovers(&mut zone_recipient, &zone_event)?;

    println!("localnet proofless shield test passed via {rpc_url}");
    Ok(())
}

fn assert_wallet_discovers(wallet: &mut Wallet, event: &ProoflessShieldEvent) -> TestResult {
    let event = zolana_program_test::proofless_event_for_wallet(event);
    assert!(wallet.sync_proofless_deposit(&event)?);
    assert_eq!(wallet.utxos.len(), 1);
    assert_eq!(wallet.utxos[0].hash, event.utxo_hash);
    Ok(())
}

fn print_signature(label: &str, signature: &solana_signature::Signature) {
    println!("{label}: {signature}");
}
