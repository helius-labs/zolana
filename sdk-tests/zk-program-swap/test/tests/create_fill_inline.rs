use std::time::{Duration, Instant};

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
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use swap_sdk::{
    instructions::{
        create_swap::{CreateSwap, CreateSwapProofInputs, EscrowCreate},
        fill::{EscrowFill, Fill, FillSharedInputs},
    },
    order::{marker_output_utxo, BlindingField, Escrow, OrderTerms, SOL_ASSET_ID},
    prover::SwapProverClient,
};
use zolana_client::{
    spawn_prover, sync_wallet, CreateDeposit, Deposit, ProverClient, Rpc, SolanaRpc, SpendProof,
    Transaction as TxBuilder, ZolanaIndexer,
};
use zolana_interface::{
    instruction::{CreateAssetCounter, CreateProtocolConfig, CreateSplInterface, CreateTree},
    pda,
    state::tree_account_size,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, ShieldedKeypair, ViewingKey};
use zolana_program_test::system_create_account_ix;
use zolana_test_utils::localnet::LocalnetValidator;
use zolana_test_utils::smart_account::{self, StandardSigners};
use zolana_test_utils::spl::{create_mint, create_token_account, mint_to};
use zolana_transaction::{instructions::types::SpendUtxo, AssetRegistry, Utxo, Wallet, SOL_MINT};
use zolana_user_registry_interface::user_registry_program_id;

// SPL the maker shields and escrows (source), and SOL the taker pays (destination).
const MAKER_SHIELD_SPL: u64 = 1_000_000_000;
const SOURCE_AMOUNT: u64 = 400_000_000;
const DESTINATION_AMOUNT: u64 = 250_000_000;
const EXPIRY: u64 = 2_000_000_000;

// Each actor is one ed25519 identity: the wallet's signing key doubles as the
// Solana fee payer (`to_solana_keypair`), and the wallet carries the asset
// registry and the synced spendable notes.
struct TestEnv {
    rpc: SolanaRpc,
    indexer: ZolanaIndexer,
    tree: Pubkey,
    maker: Wallet,
    taker: Wallet,
    spl_mint: Address,
}

fn spendable_utxo(wallet: &Wallet, mint: Address, min_amount: u64) -> Result<Utxo> {
    wallet
        .balances(false)
        .map_err(|e| anyhow!("balances: {e:?}"))?
        .into_iter()
        .find(|b| b.mint == mint)
        .and_then(|b| b.utxos.into_iter().find(|u| u.amount >= min_amount))
        .ok_or_else(|| anyhow!("no spendable utxo of {mint} >= {min_amount}"))
}

fn setup() -> Result<TestEnv> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../..");
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| format!("{root}/target/debug/zolana"));
    let rpc_port = std::env::var("ZOLANA_LOCALNET_RPC_PORT").unwrap_or_else(|_| "8899".to_string());
    let photon_port =
        std::env::var("ZOLANA_LOCALNET_PHOTON_PORT").unwrap_or_else(|_| "8784".to_string());

    let swap_program_id = swap_program::SWAP_PROGRAM_ID.to_string();
    let swap_program_so = std::env::var("SWAP_PROGRAM_SO")
        .unwrap_or_else(|_| format!("{root}/target/deploy/swap_program.so"));
    let spp_program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID).to_string();
    let spp_program_so = format!("{root}/target/deploy/shielded_pool_program.so");
    let user_registry_id = user_registry_program_id().to_string();
    let user_registry_so = format!("{root}/target/deploy/zolana_user_registry.so");
    let smart_account_id = smart_account::SMART_ACCOUNT_PROGRAM_ID.to_string();
    let smart_account_so = format!("{root}/target/deploy/squads_smart_account_program.so");

    let account_dir = "/tmp/zolana-swap-inline-smart-account-accounts".to_string();
    LocalnetValidator {
        cli_bin: cli,
        working_dir: root.to_string(),
        rpc_port,
        photon_port,
        ledger: "/tmp/zolana-swap-inline-test-ledger".to_string(),
        account_dir,
        programs: vec![
            (swap_program_id, swap_program_so),
            (spp_program_id, spp_program_so),
            (user_registry_id, user_registry_so),
            (smart_account_id, smart_account_so),
        ],
    }
    .start();

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
    let indexer = ZolanaIndexer::new(indexer_url);

    let spp_program = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    rpc.assert_executable(&spp_program)?;
    let swap_program = Pubkey::new_from_array(*swap_program::SWAP_PROGRAM_ID.as_array());
    rpc.assert_executable(&swap_program)?;

    let payer = Keypair::new();
    let authority = Keypair::new();
    let forester_authority = Keypair::new();
    let merge_authority = Keypair::new();
    let tree_creation_authority = Keypair::new();
    let zone_creation_authority = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 100_000_000_000)?;
    rpc.airdrop(&authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&forester_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&merge_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&tree_creation_authority.pubkey(), 1_000_000_000)?;
    rpc.airdrop(&zone_creation_authority.pubkey(), 1_000_000_000)?;

    let payer_address = payer.pubkey();

    let accounts = smart_account::standard_accounts();
    for ix in accounts.create_ixs(
        &payer.pubkey(),
        StandardSigners {
            protocol: authority.pubkey(),
            forester: forester_authority.pubkey(),
            merge: merge_authority.pubkey(),
            tree: tree_creation_authority.pubkey(),
            zone: zone_creation_authority.pubkey(),
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
        zone_creation_authority: accounts.zone_vault.to_bytes().into(),
        zone_creation_is_permissionless: false,
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
        owner: accounts.tree_vault,
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

    // Register an SPL asset with the pool so the maker can escrow it. Both
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

    let maker_solana = Keypair::new();
    let maker_seed: [u8; 32] = maker_solana.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let maker_shielded = ShieldedKeypair::from_ed25519(&maker_seed, ViewingKey::new())?;
    rpc.airdrop(&maker_solana.pubkey(), 10_000_000_000)?;

    let taker_solana = Keypair::new();
    rpc.airdrop(&taker_solana.pubkey(), 10_000_000_000)?;
    let taker_seed: [u8; 32] = taker_solana.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    let taker_shielded = ShieldedKeypair::from_ed25519(&taker_seed, ViewingKey::new())?;

    // Fund the actors: shield the maker's SPL (the source it escrows) and the
    // taker's SOL (what it pays). Then discover the notes through each party's
    // wallet, which scans the indexer for its view tags and decrypts its own
    // outputs. Photon lags the validator, so poll sync until both notes land.
    Deposit::new(CreateDeposit {
        recipient: &maker_shielded.shielded_address()?,
        asset: spl_mint,
        amount: MAKER_SHIELD_SPL,
        spl_token_account: Some(spl_funding),
        memo: None,
    })?
    .send(&rpc, &payer, tree, &payer)?;
    Deposit::new(CreateDeposit {
        recipient: &taker_shielded.shielded_address()?,
        asset: SOL_MINT,
        amount: DESTINATION_AMOUNT,
        spl_token_account: None,
        memo: None,
    })?
    .send(&rpc, &payer, tree, &payer)?;

    let mut maker_wallet = Wallet::new(maker_shielded.clone(), assets.clone())
        .map_err(|e| anyhow!("maker wallet: {e:?}"))?;
    let mut taker_wallet = Wallet::new(taker_shielded.clone(), assets.clone())
        .map_err(|e| anyhow!("taker wallet: {e:?}"))?;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        sync_wallet(&mut maker_wallet, &indexer)?;
        sync_wallet(&mut taker_wallet, &indexer)?;
        if spendable_utxo(&maker_wallet, spl_mint, SOURCE_AMOUNT).is_ok()
            && spendable_utxo(&taker_wallet, SOL_MINT, DESTINATION_AMOUNT).is_ok()
        {
            break;
        }
        if Instant::now() >= deadline {
            return Err(anyhow!("timed out syncing shielded deposits"));
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    Ok(TestEnv {
        rpc,
        indexer,
        tree,
        maker: maker_wallet,
        taker: taker_wallet,
        spl_mint,
    })
}

// Submit a single (large) swap instruction as a v0 transaction behind a throwaway
// address lookup table: create + extend the ALT (waiting a slot for each to root),
// then compile and send. Prepends a 1.4M CU budget; `payer` signs and pays. The
// swap create/fill account lists only fit within the 1232-byte tx limit via an ALT.
fn send_v0_with_lookup_table(rpc: &SolanaRpc, payer: &Keypair, ix: Instruction) -> Result<()> {
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
    client
        .send_and_confirm_transaction(&tx)
        .map_err(|e| anyhow!("send v0: {e}"))?;
    Ok(())
}

// Confidential SOL<->SPL swap on the shielded pool -- create then derived fill --
// driven against a real localnet (validator + Photon indexer + prover) that
// `setup()` spins up, including registering an SPL asset with the pool.
//
// The maker escrows an SPL token and wants SOL; the taker pays SOL and receives the
// SPL -- i.e. the taker swaps SOL for the SPL token. Destination is SOL, so the
// derived fill rail applies; the SPL source rides the shielded UTXOs (the SPP
// transact is asset-generic for a purely-shielded spend, and EscrowCreate/EscrowFill
// denominate change in the escrow asset).
//
// Flow:
//   1. Fund (in setup): maker shields 1.0 SPL, taker shields 0.25 SOL; each wallet
//      syncs from the indexer to discover and decrypt its own note.
//   2. Create: maker spends its 1.0 SPL UTXO -> escrow 0.4 SPL (taker-owned, held
//      under the escrow-authority PDA), marker (0-value taker-owned discovery
//      note), change 0.6 SPL (back to maker). ZK create proof, v0 tx via ALT.
//   3. Fill (derived): taker spends escrow (0.4 SPL) + its own 0.25 SOL UTXO ->
//      source_output 0.4 SPL (to taker), destination_output 0.25 SOL (to maker).
//      ZK fill proof, v0 tx.
//   4. Assert both fill outputs are indexed.
//
// Net: maker 1.0 SPL -> 0.6 SPL + 0.25 SOL; taker 0.25 SOL -> 0.4 SPL.
#[test]
fn create_and_fill_swap_inline() -> Result<()> {
    let TestEnv {
        rpc,
        indexer,
        tree,
        maker,
        taker,
        spl_mint,
    } = setup()?;
    let swap_prover_client = SwapProverClient::new_ffi();

    let source_asset_id = maker
        .registry
        .asset_id(&spl_mint)
        .map_err(|e| anyhow!("source asset id: {e}"))?;

    let taker_address = taker.keypair.shielded_address()?;
    // The taker's ed25519 authorization identity: the fill's taker input UTXO
    // owner must match the order-committed taker.
    let taker_authorization_address = taker_address
        .solana_address()
        .map_err(|e| anyhow!("taker solana address: {e:?}"))?;
    // The order opening (terms + escrow blinding) both parties hold off-chain.
    let terms = OrderTerms {
        source_asset_id,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: SOL_ASSET_ID,
        destination_mint: SOL_MINT,
        destination_amount: DESTINATION_AMOUNT,
        // The swap settlement goes to the maker's shielded address.
        destination: maker.keypair.shielded_address()?,
        taker: taker_authorization_address,
        expiry: EXPIRY,
        fill_mode: swap_prover::FILL_MODE_DERIVED,
    };
    let escrow_blinding = random_blinding();
    {
        let maker_address = maker.keypair.shielded_address()?;
        let escrow_output_utxo = Escrow {
            // TODO: rename to OrderUtxo
            terms: terms.clone(),
            blinding: escrow_blinding,
            source_mint: spl_mint,
        }
        .output_utxo(taker_address.viewing_pubkey)?;
        let marker_output_utxo = marker_output_utxo(taker_address);

        // We got all utxos

        // Build Prover inputs

        let maker_input_utxo = spendable_utxo(&maker, spl_mint, SOURCE_AMOUNT)?;
        let create_spend = SpendUtxo::from_keypair(maker_input_utxo, &maker.keypair);
        let create_tx = TxBuilder::new(
            maker_address,
            vec![create_spend],
            maker_address.solana_address()?,
        );

        let signed_private_transaction = EscrowCreate {
            tx: create_tx,
            escrow: escrow_output_utxo,
            marker: marker_output_utxo,
            payer: maker_address.solana_address()?,
        }
        .sign(&maker.keypair, &maker.registry)
        .map_err(|e| anyhow!("escrow create sign: {e:?}"))?;

        let spp_proof = indexer
            .prove_transact(tree, signed_private_transaction.clone())
            .map_err(|e| anyhow!("create transact proof: {e:?}"))?;

        // Custom proof
        let first_input_utxo = signed_private_transaction
            .inputs
            .first()
            .ok_or_else(|| anyhow!("no create input"))?;
        let create_nullifier_pubkey = first_input_utxo
            .nullifier_key
            .pubkey()
            .map_err(|e| anyhow!("create nullifier pubkey: {e:?}"))?;
        let source_input_hash = first_input_utxo
            .utxo
            .hash(
                &create_nullifier_pubkey,
                &first_input_utxo.data_hash.unwrap_or([0u8; 32]),
                &first_input_utxo.zone_data_hash.unwrap_or([0u8; 32]),
            )
            .map_err(|e| anyhow!("source input hash: {e:?}"))?;
        let change_output = signed_private_transaction
            .outputs
            .first()
            .ok_or_else(|| anyhow!("no create change output"))?;
        let change_amount = change_output.amount;
        let change_blinding = change_output.blinding.to_field();
        let external_data_hash = signed_private_transaction
            .external_data
            .hash()
            .map_err(|e| anyhow!("create external data hash: {e:?}"))?;

        let create_swap_proof_inputs = CreateSwapProofInputs {
            terms: terms.clone(),
            source_mint: spl_mint,
            escrow_blinding,
            taker_address,
            source_input_hash,
            change_amount,
            change_blinding,
            external_data_hash,
        };

        let create_swap_proof = swap_prover_client
            .prove_create_swap(&create_swap_proof_inputs)
            .map_err(|e| anyhow!("create proof: {e:?}"))?;

        let create_swap_ix = CreateSwap {
            inputs: create_swap_proof_inputs,
            payer: maker_address.solana_address()?,
            tree,
            proof: create_swap_proof.proof.into(),
            transact: spp_proof,
            source_asset_id,
        }
        .instruction()?;

        send_v0_with_lookup_table(&rpc, &maker.keypair.to_solana_keypair()?, create_swap_ix)?;
    }

    {
        // TODO: sync taker wallet and deserialize terms from the utxo data, use the marker data to fetch it
        let taker_owner_hash = taker
            .keypair
            .owner_hash()
            .map_err(|e| anyhow!("taker owner hash: {e:?}"))?;
        let taker_input_utxo = spendable_utxo(&taker, SOL_MINT, DESTINATION_AMOUNT)?;
        let source_output_blinding = random_blinding();
        let fill_inputs = FillSharedInputs {
            terms: terms.clone(),
            source_mint: spl_mint,
            destination_mint: SOL_MINT,
            escrow_blinding,
            taker_address: taker_owner_hash,
            taker_in_blinding: taker_input_utxo.blinding,
            source_output_blinding,
            external_data_hash: [0u8; 32],
            maker_recipient: maker.keypair.shielded_address()?,
            taker_recipient: taker.keypair.shielded_address()?,
        };
        let source_output = fill_inputs.source_output();
        let destination_output = fill_inputs
            .destination_output()
            .map_err(|e| anyhow!("destination output: {e:?}"))?;
        let source_output_hash = source_output
            .hash()
            .map_err(|e| anyhow!("source output hash: {e:?}"))?;
        let destination_output_hash = destination_output
            .hash()
            .map_err(|e| anyhow!("destination output hash: {e:?}"))?;

        let escrow_input = Escrow {
            terms: terms.clone(),
            blinding: escrow_blinding,
            source_mint: spl_mint,
        }
        .spend()
        .map_err(|e| anyhow!("escrow spend: {e:?}"))?;
        let taker_spend = SpendUtxo::from_keypair(taker_input_utxo, &taker.keypair);

        let fill_tx = TxBuilder::new(
            taker_address,
            vec![escrow_input, taker_spend],
            taker_address.solana_address()?,
        )
        .with_expiry(terms.expiry);
        let fill_signed = EscrowFill {
            tx: fill_tx,
            source_output,
            destination_output,
        }
        .sign(&taker.keypair, &taker.registry)
        .map_err(|e| anyhow!("escrow fill sign: {e:?}"))?;

        let fill_commitments = fill_signed
            .input_utxo_hashes()
            .map_err(|e| anyhow!("fill input commitments: {e:?}"))?;
        let fill_states = indexer
            .get_merkle_proofs(tree, fill_commitments.iter().map(|c| c.utxo_hash).collect())
            .map_err(|e| anyhow!("fill merkle proofs: {e}"))?
            .proofs;
        let fill_nullifier_proofs = indexer
            .get_non_inclusion_proofs(tree, fill_commitments.iter().map(|c| c.nullifier).collect())
            .map_err(|e| anyhow!("fill non-inclusion proofs: {e}"))?
            .proofs;
        let fill_spend_proofs: Vec<SpendProof> = fill_states
            .into_iter()
            .zip(fill_nullifier_proofs)
            .map(|(state, nullifier)| SpendProof { state, nullifier })
            .collect();

        let fill_external_data_hash = fill_signed
            .external_data
            .hash()
            .map_err(|e| anyhow!("fill external data hash: {e:?}"))?;
        let fill_inputs = FillSharedInputs {
            external_data_hash: fill_external_data_hash,
            ..fill_inputs
        };

        let (fill_ix, _fill_result) = Fill {
            inputs: fill_inputs,
            signed: fill_signed,
            payer: taker_address.solana_address()?,
            tree,
        }
        .instruction(
            &fill_spend_proofs,
            &ProverClient::local(),
            &swap_prover_client,
        )?;

        send_v0_with_lookup_table(&rpc, &taker.keypair.to_solana_keypair()?, fill_ix)?;

        indexer
            .get_merkle_proofs(tree, vec![source_output_hash, destination_output_hash])
            .map_err(|e| anyhow!("fill outputs index: {e}"))?;
    }
    Ok(())
}
