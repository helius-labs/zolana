//! Local-validator SOL cycle backed by a real Photon Zolana indexer.
//!
//! TODO(pr164-port): this suite targets the pre-PR164 transact API
//! (`TransactSolWithdrawal`, `assemble_eddsa_transfer_proof_inputs`); it needs
//! the behavioral port to the PR164 interface-transfer protocol.
//!
//! Run with `just test-localnet-e2e-photon`.

use std::{
    collections::VecDeque,
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::anyhow;
use serial_test::serial;
use shielded_pool_tests::support::{
    forester::{ForesterAuthority, NullifierTestForester},
    localnet::{
        account_lamports, initialize_pool, on_chain_roots, print_signature, send_transaction,
        LocalnetPool,
    },
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    prover::field::{be, right_align_slice},
    ConfidentialTransfer, EncryptedUtxoMatch, MerkleProof as IndexedMerkleProof,
    NonInclusionProof as IndexedNonInclusionProof, ProofInputUtxo, ProverClient, ProverInputs, Rpc,
    ShieldedTransaction, SolanaRpc, SpendProof, SppProofInputUtxo, TransferInput, TransferOutput,
    ZolanaIndexer,
};
use zolana_event::OutputDataEncoding;
use zolana_hasher::{sha256::Sha256BE, Hasher};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{InterfaceTransfer, ResolvedInterfaceTransfer},
        CreateProtocolConfig, CreateTree, Deposit, Transact, TransactInterfaceTransferAccounts,
        TransactSolTransferAccounts,
    },
    pda,
    state::{
        address_tree_params, tree_account_size, ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
        ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{
    hash::owner_hash, pubkey::PublicKey, shielded::ShieldedKeypair, NullifierKey, ViewingKey,
};
use zolana_program_test::{rpc_state_root, system_create_account_ix, ZolanaProgramTest};
use zolana_smart_account_client::execute_sync_ix;
use zolana_test_utils::smart_account::{self, StandardSigners};
use zolana_test_utils::{
    localnet::start_shielded_pool_localnet, prover::spawn_workspace_prover,
    test_validator_asserts::assert_transaction_compute_units,
};
use zolana_transaction::{
    instructions::transact::PrivateTxHash,
    serialization::confidential::{Confidential, ConfidentialOutputPlaintext},
    AssetRegistry, Data, LocalWalletAuthority, Utxo, Wallet, WalletUtxo, DEFAULT_TAG_WINDOW,
    SOL_MINT,
};
use zolana_tree::TreeAccount;

use zolana_test_utils::transact::{
    assemble_eddsa_transfer_proof_inputs, dummy_input, dummy_transfer_output, eddsa_input_utxo,
    external_data_hash, fe, inline_outputs, new_transact_ix_data, output_owner_pk_hashes,
    pack_proof, prove_and_verify_transfer, public_sol_field, real_output, set_output_owner_tags,
    transfer_output, EddsaTransferProofArgs,
};

const RPC_URL_ENV: &str = "ZOLANA_LOCALNET_URL";
const INDEXER_URL_ENV: &str = "ZOLANA_INDEXER_URL";
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8899";
const DEFAULT_INDEXER_URL: &str = "http://127.0.0.1:8784";
const INDEXER_TIMEOUT: Duration = Duration::from_secs(120);
const AMOUNT: u64 = 1_000_000_000;
const TRANSFER_AMOUNT: u64 = 400_000_000;
const CHANGE_AMOUNT: u64 = AMOUNT - TRANSFER_AMOUNT;
const LOCALNET_NULLIFIER_ZKP_BATCH_SIZE: u64 = 10;
const LOCALNET_NULLIFIER_BATCH_UPDATE_COUNT: u64 = 20;
const LOCALNET_NULLIFIERS_PER_QUEUE_TX: u64 = 2;
const BATCH_NULLIFIER_TREE_CU_LIMIT: u64 = 500_000;

type TestResult<T = ()> = anyhow::Result<T>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpendRail {
    Eddsa,
}

impl SpendRail {
    fn label(self) -> &'static str {
        match self {
            SpendRail::Eddsa => "eddsa",
        }
    }
}

// `#[path]` is required here: this file is the `localnet_photon_e2e` test-crate
// root, so an ordinary `mod cycle;` would resolve against `tests/localnet/`
// rather than this binary's `photon/` submodule directory. These three modules
// form one intentional execution suite (the Photon-backed SOL cycle).
#[path = "photon/cycle.rs"]
mod cycle;
#[path = "photon/encrypted_transfer.rs"]
mod encrypted_transfer;
#[path = "photon/forester.rs"]
mod forester;

struct IndexedSpendInputArgs<'a> {
    utxo: &'a Utxo,
    owner_field: &'a [u8; 32],
    state_proof: &'a IndexedMerkleProof,
    nullifier_proof: &'a IndexedNonInclusionProof,
    nullifier: &'a [u8; 32],
    owner_pk_hash: &'a [u8; 32],
    nullifier_key: &'a NullifierKey,
}

fn indexed_spend_input(args: IndexedSpendInputArgs<'_>) -> TestResult<TransferInput> {
    Ok(TransferInput {
        utxo: ProofInputUtxo::new(
            *args.owner_field,
            &args.utxo.asset,
            args.utxo.amount,
            &args.utxo.blinding,
        )?
        .with_zone([0u8; 32], &args.utxo.zone_program_id)?,
        is_dummy: be(&fe(0)),
        state_path_elements: args.state_proof.path.iter().map(be).collect(),
        state_path_index: be(&fe(args.state_proof.leaf_index)),
        nullifier_low_value: be(&args.nullifier_proof.low_element),
        nullifier_next_value: be(&args.nullifier_proof.high_element),
        nullifier_low_path_elements: args.nullifier_proof.path.iter().map(be).collect(),
        nullifier_low_path_index: be(&fe(args.nullifier_proof.low_element_index)),
        utxo_tree_root: be(&args.state_proof.root),
        nullifier_tree_root: be(&args.nullifier_proof.root),
        nullifier: be(args.nullifier),
        owner_pk_hash: be(args.owner_pk_hash),
        nullifier_secret: be(&right_align_slice(args.nullifier_key.secret())?),
    })
}

struct LatestTreeRoots {
    utxo_root: [u8; 32],
    nullifier_root_index: u16,
    nullifier_root: [u8; 32],
}

struct RealSpendUtxo {
    utxo: Utxo,
    hash: [u8; 32],
    nullifier: [u8; 32],
}

impl RealSpendUtxo {
    fn new(
        utxo: Utxo,
        nullifier_key: &NullifierKey,
        nullifier_pk: &[u8; 32],
        zero: &[u8; 32],
    ) -> TestResult<Self> {
        let hash = utxo.hash(nullifier_pk, zero, zero)?;
        let nullifier = utxo.nullifier(&hash, nullifier_key)?;
        Ok(Self {
            utxo,
            hash,
            nullifier,
        })
    }
}

fn latest_tree_roots(rpc: &SolanaRpc, tree: &Pubkey) -> TestResult<LatestTreeRoots> {
    let address = Address::new_from_array(tree.to_bytes());
    let mut data = rpc
        .get_account(address)?
        .ok_or_else(|| anyhow!("tree account not found: {tree}"))?
        .data;
    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes())
        .map_err(|err| anyhow!("load tree account: {err:?}"))?;
    let utxo_root_index = account.utxo_tree().current_root_index();
    let utxo_root = account
        .get_utxo_tree_root(utxo_root_index)
        .map_err(|err| anyhow!("get utxo root {utxo_root_index}: {err:?}"))?;
    let (nullifier_root_index, nullifier_root) = {
        let nullifier_tree = account.nullifer_tree();
        let root_index = u16::try_from(nullifier_tree.get_root_index())
            .map_err(|_| anyhow!("nullifier root index does not fit in u16"))?;
        let root = nullifier_tree
            .get_root()
            .ok_or_else(|| anyhow!("nullifier tree has no current root"))?;
        (root_index, root)
    };
    Ok(LatestTreeRoots {
        utxo_root,
        nullifier_root_index,
        nullifier_root,
    })
}

fn localnet_nullifier_params() -> zolana_tree::InitAddressTreeAccountsInstructionData {
    let mut params = address_tree_params();
    let zkp_batch_count =
        ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE / ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE;
    params.input_queue_zkp_batch_size = LOCALNET_NULLIFIER_ZKP_BATCH_SIZE;
    params.input_queue_batch_size = LOCALNET_NULLIFIER_ZKP_BATCH_SIZE * zkp_batch_count;
    params
}

fn create_tree_instructions_with_nullifier_params(
    rpc: &SolanaRpc,
    payer: &Pubkey,
    authority: &Pubkey,
    tree: &Pubkey,
    account_size: u64,
    nullifier_params: zolana_tree::InitAddressTreeAccountsInstructionData,
) -> TestResult<Vec<solana_instruction::Instruction>> {
    let rent = rpc.get_minimum_balance_for_rent_exemption(account_size as usize)?;
    Ok(vec![
        system_create_account_ix(
            payer,
            tree,
            rent,
            account_size,
            &pda::shielded_pool_program_id(),
        ),
        CreateTree {
            authority: *authority,
            tree: *tree,
        }
        .instruction_with_nullifier_params(nullifier_params),
    ])
}

fn stress_blinding(index: u64) -> [u8; 31] {
    let mut blinding = [0u8; 31];
    blinding[0] = 0x51;
    blinding[23..].copy_from_slice(&index.to_be_bytes());
    blinding
}

fn wait_for_indexed_utxo(
    indexer: &ZolanaIndexer,
    tag: [u8; 32],
    signature: Signature,
) -> TestResult<EncryptedUtxoMatch> {
    wait_for("indexed UTXO", || {
        let response = indexer.get_encrypted_utxos_by_tags(vec![tag], None, Some(50), None)?;
        Ok(response
            .matches
            .into_iter()
            .find(|item| item.tx_signature == signature))
    })
}

fn wait_for_indexed_transaction(
    indexer: &ZolanaIndexer,
    tag: [u8; 32],
    signature: Signature,
) -> TestResult<ShieldedTransaction> {
    wait_for("indexed transaction", || {
        let response =
            indexer.get_shielded_transactions_by_tags(vec![tag], None, Some(100), None)?;
        Ok(response
            .transactions
            .into_iter()
            .find(|item| item.tx_signature == signature))
    })
}

fn wait_for_merkle_proof(
    indexer: &ZolanaIndexer,
    tree: Address,
    leaf: [u8; 32],
) -> TestResult<IndexedMerkleProof> {
    wait_for("indexed merkle proof", || {
        let response = indexer.get_merkle_proofs(tree, vec![leaf], None)?;
        Ok(response.proofs.into_iter().next())
    })
}

fn wait_for_non_inclusion_proof(
    indexer: &ZolanaIndexer,
    tree: Address,
    leaf: [u8; 32],
) -> TestResult<IndexedNonInclusionProof> {
    wait_for("indexed non-inclusion proof", || {
        let response = indexer.get_non_inclusion_proofs(tree, vec![leaf], None)?;
        Ok(response.proofs.into_iter().next())
    })
}

fn wait_for<T>(
    label: impl AsRef<str>,
    mut poll: impl FnMut() -> Result<Option<T>, zolana_client::ClientError>,
) -> TestResult<T> {
    let label = label.as_ref();
    let started = Instant::now();
    let mut last_error = None;
    while started.elapsed() < INDEXER_TIMEOUT {
        match poll() {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => {}
            Err(error) => last_error = Some(error.to_string()),
        }
        sleep(Duration::from_millis(500));
    }
    Err(anyhow!(
        "timed out waiting for {label}; last indexer error: {}",
        last_error.unwrap_or_else(|| "none".to_string())
    ))
}

fn shielded_ed25519_from_solana(signer: &Keypair) -> TestResult<ShieldedKeypair> {
    let seed: [u8; 32] = signer.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    Ok(ShieldedKeypair::from_ed25519(&seed, ViewingKey::new())?)
}

/// Restart a fresh validator + Photon indexer so each test runs against clean
/// chain state. The protocol config is a global singleton, so tests cannot share
/// a validator; combined with `#[serial]` this gives every test an isolated
/// localnet.
///
fn restart_localnet() {
    start_shielded_pool_localnet("zolana-photon", &[]);
}

/// End-to-end encrypted transfer: shield two sender UTXOs, transfer one private
/// output to a recipient using the high-level `Transaction` builder (real HPKE
/// encryption), then recover the recipient UTXO purely by DECRYPTING the
/// ciphertext the Photon indexer returns -- no plaintext reconstruction.
///
/// Two real inputs are used so the proof shape is exactly (2, 3), matching the
/// available `transfer_2_3` key without padding the instruction with dummy
/// (zero) nullifiers that the program would reject on insertion.
#[test]
#[serial]
fn shield_encrypted_transfer_eddsa_recovered_by_decryption() -> TestResult {
    shield_encrypted_transfer_recovered_by_decryption_for(SpendRail::Eddsa)
}

fn shield_encrypted_transfer_recovered_by_decryption_for(expected_rail: SpendRail) -> TestResult {
    restart_localnet();
    spawn_workspace_prover();

    let rpc_url = std::env::var(RPC_URL_ENV).unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());
    let indexer_url =
        std::env::var(INDEXER_URL_ENV).unwrap_or_else(|_| DEFAULT_INDEXER_URL.to_owned());

    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut rpc = SolanaRpc::new(rpc_url.clone());
    let indexer = ZolanaIndexer::new(indexer_url.clone());
    rpc.assert_executable(&program_id)?;

    let payer = Keypair::new();
    let authority = Keypair::new();
    rpc.airdrop(&payer.pubkey(), 20_000_000_000)?;
    rpc.airdrop(&authority.pubkey(), 1_000_000_000)?;

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
    send_transaction(
        &mut rpc,
        &[create_config],
        &authority.pubkey(),
        &[&authority],
    )?;

    let tree = Keypair::new();
    let create_tree = create_tree_instructions(
        &rpc,
        &payer.pubkey(),
        &authority.pubkey(),
        &tree.pubkey(),
        tree_account_size() as u64,
    )?;
    send_transaction(
        &mut rpc,
        &create_tree,
        &payer.pubkey(),
        &[&payer, &tree, &authority],
    )?;
    let tree_pubkey = tree.pubkey();
    let tree_address = Address::new_from_array(tree_pubkey.to_bytes());
    let zero = [0u8; 32];

    let assets = AssetRegistry::default();
    let sender = match expected_rail {
        SpendRail::Eddsa => shielded_ed25519_from_solana(&payer)?,
    };
    let recipient = match expected_rail {
        SpendRail::Eddsa => shielded_ed25519_from_solana(&Keypair::new())?,
    };
    let recipient_address = recipient.shielded_address()?;
    let recipient_view_tag = recipient.signing_pubkey().confidential_view_tag()?;
    let sender_nullifier_key = NullifierKey::from_secret(*sender.nullifier_key.secret());
    let sender_nullifier_pk = sender_nullifier_key.pubkey()?;

    // ---- shield two sender-owned UTXOs (reconstructable from fixed blindings) ----
    let half = AMOUNT / 2;
    let deposit_blindings: [[u8; 31]; 2] = [[7u8; 31], [8u8; 31]];
    let mut spends = Vec::new();
    for blinding in deposit_blindings {
        let utxo = Utxo {
            owner: sender.signing_pubkey(),
            asset: SOL_MINT,
            amount: half,
            blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let owner_field = owner_hash(&utxo.owner, &sender_nullifier_pk)?;
        let shield_data = ZolanaProgramTest::sol_shield_data(half, owner_field, blinding);
        let shield_ix = Deposit {
            tree: tree_pubkey,
            depositor: payer.pubkey(),
            deposits: vec![shield_data],
        }
        .instruction()?;
        send_transaction(&mut rpc, &[shield_ix], &payer.pubkey(), &[&payer])?;
        let utxo_hash = utxo.hash(&sender_nullifier_pk, &zero, &zero)?;
        wait_for_merkle_proof(&indexer, tree_address, utxo_hash)?;
        spends.push(SppProofInputUtxo::new(utxo, &sender));
    }

    // ---- build the encrypted transfer with the high-level client builder ----
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let mut transfer = ConfidentialTransfer::new(sender.shielded_address()?, spends, payer_address);
    transfer.send(&recipient_address, SOL_MINT, TRANSFER_AMOUNT)?;
    let proof_inputs = transfer.sign(&sender, &assets)?;

    let commitments = proof_inputs.input_utxo_hashes()?;
    let mut spend_proofs = Vec::new();
    for commitment in &commitments {
        let state = wait_for_merkle_proof(&indexer, tree_address, commitment.utxo_hash)?;
        let nullifier = wait_for_non_inclusion_proof(&indexer, tree_address, commitment.nullifier)?;
        spend_proofs.push(SpendProof { state, nullifier });
    }
    // Each padding dummy needs a real non-inclusion witness for its own nullifier.
    let mut dummy_proofs = Vec::new();
    for nullifier in proof_inputs.dummy_nullifiers()? {
        dummy_proofs.push(wait_for_non_inclusion_proof(
            &indexer,
            tree_address,
            nullifier,
        )?);
    }

    let assembled = zolana_client::assemble(proof_inputs, &spend_proofs, &dummy_proofs)?;
    let proof = match &assembled.prover_inputs {
        ProverInputs::Eddsa(inputs) => ProverClient::local().prove_transfer(inputs)?,
        // The P256 rail is removed; the SDK keeps the variant as a placeholder.
        ProverInputs::P256(_) => return Err(anyhow!("P256 rail removed")),
    };
    let packed = pack_proof(&proof)?;
    let ix_data = assembled.with_proof(packed);

    let transfer_ix = Transact {
        payer: payer.pubkey(),
        tree: tree_pubkey,
        interface_transfer_accounts: Vec::new(),
        data: ix_data,
    }
    .instruction();
    // The P256 rail's Groth16 proof carries an extra BSB22 Pedersen-PoK pairing,
    // so verification exceeds the 200k default compute budget.
    let compute_budget =
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
            1_400_000,
        );
    let transfer_sig = send_transaction(
        &mut rpc,
        &[compute_budget, transfer_ix],
        &payer.pubkey(),
        &[&payer],
    )?;
    print_signature("encrypted_transfer", &transfer_sig);

    let indexed = wait_for_indexed_transaction(&indexer, recipient_view_tag, transfer_sig)?;
    assert!(
        indexed.tx_viewing_pk.is_some(),
        "encrypted transfer must carry a tx viewing key"
    );
    assert!(
        indexed.salt.is_some(),
        "encrypted transfer must carry a salt"
    );

    // ---- recover the recipient UTXO purely by decrypting the indexed ciphertext ----
    let tx_viewing_pk = indexed
        .tx_viewing_pk
        .ok_or_else(|| anyhow!("indexed transfer missing tx_viewing_pk"))?;
    let salt = indexed
        .salt
        .ok_or_else(|| anyhow!("indexed transfer missing salt"))?;
    let first_nullifier = commitments
        .first()
        .ok_or_else(|| anyhow!("no input commitment"))?
        .nullifier;

    // Independently reconstruct the expected recipient UTXO: the author re-derives
    // the transaction viewing key and decrypts the recipient slot (output position
    // 2) directly, reading its committed blinding out. Each slot's borsh
    // `OutputDataEncoding` carries a scheme byte plus the per-scheme ciphertext
    // body.
    let tx_key = sender
        .viewing_key
        .get_transaction_viewing_key(&first_nullifier)?;
    if tx_key.pubkey() != tx_viewing_pk {
        return Err(anyhow!("sender did not author the indexed transfer"));
    }
    let recipient_slot = indexed
        .output_slots
        .get(2)
        .ok_or_else(|| anyhow!("indexed transfer missing recipient slot"))?;
    let recipient_blob = match recipient_slot
        .output_data()
        .ok_or_else(|| anyhow!("recipient slot is not decodable output data"))?
    {
        OutputDataEncoding::Encrypted(blob)
        | OutputDataEncoding::VerifiablyEncrypted(blob)
        | OutputDataEncoding::Plaintext(blob) => blob,
    };
    let (_scheme, recipient_ciphertext) = recipient_blob
        .split_first()
        .ok_or_else(|| anyhow!("recipient slot missing scheme byte"))?;
    let recipient_plaintext =
        Confidential::decrypt_with_tx_key(&tx_key, recipient_ciphertext, salt, 2)?;
    let expected_utxo = Utxo {
        owner: recipient_address.signing_pubkey,
        asset: SOL_MINT,
        amount: TRANSFER_AMOUNT,
        blinding: recipient_plaintext.blinding,
        zone_program_id: None,
        data: Data::default(),
    };

    // The recipient wallet is handed only the on-chain ciphertext and recovers by
    // decrypting it. `Wallet::store` keeps only recipient-owned notes, so the
    // sender's change slot (encrypted to the sender) is not stored.
    let mut wallet = Wallet::new(recipient.shielded_address()?, AssetRegistry::default())?;
    let authority = LocalWalletAuthority::new(Pubkey::default(), &recipient);
    wallet.sync(
        &authority,
        std::slice::from_ref(&indexed),
        0,
        DEFAULT_TAG_WINDOW,
    )?;
    assert_eq!(
        wallet.utxos.len(),
        1,
        "recipient decrypts exactly its own transferred output"
    );
    let recovered = wallet
        .utxos
        .first()
        .ok_or_else(|| anyhow!("recipient did not recover the transferred UTXO by decryption"))?;

    // Full-struct comparison against an independently derived expected UTXO (hash
    // and nullifier computed the same way the wallet does). The output context is
    // located in the indexed transaction by the independently computed hash.
    let nullifier_pk = recipient.nullifier_key.pubkey()?;
    let expected_hash = expected_utxo.hash(&nullifier_pk, &zero, &zero)?;
    let output_context = indexed
        .output_slots
        .iter()
        .find(|slot| slot.output_context.hash == expected_hash)
        .map(|slot| slot.output_context.clone())
        .ok_or_else(|| anyhow!("expected output not found in indexed transfer"))?;
    let expected_nullifier =
        expected_utxo.nullifier(&output_context.hash, &recipient.nullifier_key)?;
    let expected = WalletUtxo {
        utxo: expected_utxo,
        output_context,
        nullifier: expected_nullifier,
        data_hash: None,
        zone_data_hash: None,
        spent: false,
    };
    assert_eq!(*recovered, expected);

    // The decrypted note is the exact committed on-chain output, so its hash is
    // Merkle-provable (and therefore spendable by the recipient).
    wait_for_merkle_proof(&indexer, tree_address, recovered.output_context.hash)?;

    println!(
        "encrypted shield-transfer rail={} recovered by decryption via rpc={rpc_url} indexer={indexer_url}",
        expected_rail.label()
    );
    Ok(())
}
