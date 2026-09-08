//! Local-validator proofless deposit test.

use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::SolanaRpc;
use zolana_interface::{
    instruction::{
        encode_instruction, tag, CreateRingConfigData, Deposit, RingDeposit, SetRingActivation,
    },
    pda, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::{
    rpc_state_root, single_deposit_view, DepositOutput, TestIndexer, ZolanaProgramTest,
    RING_TEST_PROGRAM_ID,
};
use zolana_transaction::{
    AssetRegistry, KeypairWalletAuthority, SyncWalletAuthority, Wallet, DEFAULT_TAG_WINDOW,
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
    let ring_program_id = Pubkey::new_from_array(RING_TEST_PROGRAM_ID);
    let mut rpc = SolanaRpc::new(rpc_url.clone());
    let mut indexer = TestIndexer::new();
    rpc.assert_executable(&program_id)?;
    rpc.assert_executable(&ring_program_id)?;

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

    let direct_keypair = ShieldedKeypair::new_p256()?;
    let mut direct_recipient =
        Wallet::new(direct_keypair.shielded_address()?, AssetRegistry::default())?;
    let direct_data =
        ZolanaProgramTest::wallet_sol_shield_data(DEPOSIT_LAMPORTS, &direct_recipient.identity)?;
    let direct_root_before = rpc_state_root(&rpc, &tree)?;
    let direct_ix = Deposit {
        tree,
        depositor: depositor.pubkey(),
        deposits: vec![direct_data],
    }
    .instruction()
    .expect("deposit instruction");
    let direct_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &[direct_ix],
        &payer.pubkey(),
        &[&payer, &depositor],
    )?;
    print_signature("deposit", &direct_tx.signature);
    let direct_root_after = rpc_state_root(&rpc, &tree)?;
    assert_ne!(direct_root_after, direct_root_before);
    let direct_view = single_deposit_view(&direct_tx.events)?;
    assert_eq!(direct_root_after, indexer.root());
    assert_wallet_discovers(
        &mut direct_recipient,
        &KeypairWalletAuthority::new(Pubkey::default(), &direct_keypair),
        &direct_view,
    )?;

    // A ring deposit is authorized by the ring's `ring_config` (its `ring_auth`
    // PDA), which the ring program signs for on the CPI into SPP. Create that
    // config first via the ring program's `CREATE_RING_CONFIG` forwarding
    // instruction; without it SPP rejects the ring deposit with
    // `InvalidRingConfig`.
    // Creation is permissionless and lands the config inert; the pool's
    // `authority` is also its `ring_creation_authority`, so it activates the
    // ring in the same transaction.
    let ring_authority = Keypair::new();
    let (ring_auth, _) = pda::ring_auth(&ring_program_id);
    let create_ring_config = Instruction {
        program_id: ring_program_id,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(ring_auth, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(program_id, false),
        ],
        data: encode_instruction(
            tag::CREATE_RING_CONFIG,
            &CreateRingConfigData {
                program_id: RING_TEST_PROGRAM_ID.into(),
                authority: ring_authority.pubkey().to_bytes().into(),
            },
        ),
    };
    let set_ring_activation = SetRingActivation {
        authority: authority.pubkey(),
        ring_config: ring_auth,
        activated: true,
        ring_authority_transact_is_enabled: true,
    }
    .instruction();
    let create_ring_config_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &[create_ring_config, set_ring_activation],
        &authority.pubkey(),
        &[&authority],
    )?;
    print_signature("create_ring_config", &create_ring_config_tx.signature);

    let ring_keypair = ShieldedKeypair::new_p256()?;
    let mut ring_recipient =
        Wallet::new(ring_keypair.shielded_address()?, AssetRegistry::default())?;
    let mut ring_data = ZolanaProgramTest::wallet_ring_sol_shield_data(
        DEPOSIT_LAMPORTS,
        &ring_recipient.identity,
        &[5u8; 32],
        0,
    )?;
    ring_data.ring_data_hash = [5u8; 32];
    let ring_root_before = rpc_state_root(&rpc, &tree)?;
    let ring_ix = RingDeposit {
        tree,
        depositor: depositor.pubkey(),
        ring_program_id,
        deposits: vec![ring_data],
    }
    .instruction()
    .expect("ring deposit instruction");
    let ring_tx = send_indexed(
        &mut rpc,
        &mut indexer,
        program_id,
        &[ring_ix],
        &payer.pubkey(),
        &[&payer, &depositor],
    )?;
    print_signature("ring_deposit", &ring_tx.signature);
    let ring_root_after = rpc_state_root(&rpc, &tree)?;
    assert_ne!(ring_root_after, ring_root_before);
    let ring_view = single_deposit_view(&ring_tx.events)?;
    assert_eq!(ring_root_after, indexer.root());
    assert_wallet_discovers(
        &mut ring_recipient,
        &KeypairWalletAuthority::new(Pubkey::default(), &ring_keypair),
        &ring_view,
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
