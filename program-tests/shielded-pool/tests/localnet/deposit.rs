//! Local-validator proofless deposit test.

use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::SolanaRpc;
use zolana_interface::{
    instruction::{encode_instruction, tag, CreateZoneConfigData, Deposit, ZoneDeposit},
    pda, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypair};
use zolana_program_test::{
    rpc_state_root, single_deposit_view, DepositOutput, TestIndexer, ZolanaProgramTest,
    ZONE_TEST_PROGRAM_ID,
};
use zolana_transaction::{
    AssetRegistry, LocalWalletAuthority, SyncWalletAuthority, Wallet, DEFAULT_TAG_WINDOW,
};

use shielded_pool_tests::support::localnet::{
    initialize_indexed_pool, print_signature, send_indexed, LocalnetPool,
};

const RPC_URL_ENV: &str = "ZOLANA_LOCALNET_URL";
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const DEPOSIT_LAMPORTS: u64 = 750_000_000;

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

    let LocalnetPool {
        payer,
        authority,
        tree,
    } = initialize_indexed_pool(&mut rpc, &mut indexer, program_id)?;
    let depositor = Keypair::new();
    print_signature(
        "airdrop depositor",
        &rpc.airdrop(&depositor.pubkey(), 5_000_000_000)?,
    );

    let direct_keypair = ShieldedKeypair::new()?;
    let mut direct_recipient =
        Wallet::new(direct_keypair.shielded_address()?, AssetRegistry::default())?;
    let direct_data = ZolanaProgramTest::wallet_sol_shield_data(
        DEPOSIT_LAMPORTS,
        &direct_recipient.identity,
        &[3u8; BLINDING_LEN],
        0,
    )?;
    let direct_root_before = rpc_state_root(&rpc, &tree.pubkey())?;
    let direct_ix = Deposit {
        tree: tree.pubkey(),
        depositor: depositor.pubkey(),
        spl: None,
        view_tag: direct_data.view_tag,
        owner: direct_data.owner,
        blinding: direct_data.blinding,
        amount: direct_data.amount,
        utxo_data: direct_data.utxo_data,
        memo: direct_data.memo,
    }
    .instruction();
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

    // A zone deposit is authorized by the zone's `zone_config` (its `zone_auth`
    // PDA), which the zone program signs for on the CPI into SPP. Create that
    // config first via the zone program's `CREATE_ZONE_CONFIG` forwarding
    // instruction; without it SPP rejects the zone deposit with
    // `InvalidZoneConfig`.
    // The instruction's fee-payer account (index 0) must be the protocol config's
    // `zone_creation_authority` -- here the `authority` keypair -- since zone
    // creation is not permissionless. `zone_authority` is the config's stored
    // owner and needs no signature at creation.
    let zone_authority = Keypair::new();
    let (zone_auth, _) = pda::zone_auth(&zone_program_id);
    let create_zone_config = Instruction {
        program_id: zone_program_id,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(zone_auth, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(program_id, false),
        ],
        data: encode_instruction(
            tag::CREATE_ZONE_CONFIG,
            &CreateZoneConfigData {
                program_id: ZONE_TEST_PROGRAM_ID.into(),
                authority: zone_authority.pubkey().to_bytes().into(),
                zone_authority_transact_is_enabled: true,
            },
        ),
    };
    let create_zone_config_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &[create_zone_config],
        &authority.pubkey(),
        &[&authority],
    )?;
    print_signature("create_zone_config", &create_zone_config_tx.signature);

    let zone_keypair = ShieldedKeypair::new()?;
    let mut zone_recipient =
        Wallet::new(zone_keypair.shielded_address()?, AssetRegistry::default())?;
    let mut zone_data = ZolanaProgramTest::wallet_zone_sol_shield_data(
        DEPOSIT_LAMPORTS,
        &zone_recipient.identity,
        &[5u8; BLINDING_LEN],
        0,
    )?;
    zone_data.zone_data_hash = [5u8; 32];
    let zone_root_before = rpc_state_root(&rpc, &tree.pubkey())?;
    let zone_ix = ZoneDeposit {
        tree: tree.pubkey(),
        depositor: depositor.pubkey(),
        spl: None,
        view_tag: zone_data.view_tag,
        owner: zone_data.owner,
        blinding: zone_data.blinding,
        amount: zone_data.amount,
        zone_program_id,
        zone_data_hash: zone_data.zone_data_hash,
        zone_data: zone_data.zone_data.clone(),
        utxo_data: zone_data.utxo_data,
        memo: zone_data.memo,
    }
    .instruction();
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
    let zone_view = single_deposit_view(&zone_tx.events)?;
    assert_eq!(zone_root_after, indexer.root());
    assert_wallet_discovers(
        &mut zone_recipient,
        &LocalWalletAuthority::new(Pubkey::default(), &zone_keypair),
        &zone_view,
    )?;

    println!("localnet proofless deposit test passed via {rpc_url}");
    Ok(())
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
