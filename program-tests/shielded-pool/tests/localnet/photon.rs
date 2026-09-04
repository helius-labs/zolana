//! Local-validator SOL cycle backed by a real Photon Zolana indexer.
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
        account_lamports, build_sol_transfer_witness, dummy_witness_outputs, initialize_pool,
        on_chain_roots, print_signature, send_transaction, LocalnetPool, SolTransferWitnessArgs,
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
    SolanaRpc, SpendProof, SppProofInputUtxo, TransferInput, ZolanaIndexer,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::output_data::OutputDataEncoding;
use zolana_interface::{
    instruction::{
        instruction_data::transact::InterfaceTransfer, Deposit, Transact,
        TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    },
    pda,
    state::{
        nullifier_tree_params, NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE,
        NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{
    hash::owner_hash,
    pubkey::PublicKey,
    shielded::{ShieldedAddress, ShieldedKeypair},
    NullifierKey, SigningKey,
};
use zolana_program_test::{rpc_state_root, ZolanaProgramTest};
use zolana_test_utils::smart_account;
use zolana_test_utils::{
    harness::{BootstrapConfig, LocalnetHarness},
    localnet::{start_shielded_pool_localnet, ValidatorBackend},
    prover::spawn_workspace_prover,
    test_validator_asserts::{
        assert_transaction_compute_units, wait_for_indexed_transaction, wait_for_indexed_utxo,
        wait_for_merkle_proof, wait_for_non_inclusion_proof,
    },
};
use zolana_transaction::{
    serialization::confidential::{Confidential, ConfidentialOutputPlaintext},
    AssetRegistry, Data, KeypairWalletAuthority, Utxo, Wallet, WalletUtxo, DEFAULT_TAG_WINDOW,
    SOL_MINT,
};
use zolana_tree::TreeAccount;

use zolana_test_utils::transact::{
    dummy_input_with_proof, dummy_nullifier, dummy_transfer_output, fe, pack_transact_proof,
    public_sol_field, real_output, transfer_output, ResolvedInterfaceTransfer,
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

// `#[path]` is required here: this file is the `localnet_photon` test-crate
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
        .with_ring([0u8; 32], &args.utxo.ring_program_id)?,
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
        nullifier_secret: be(&right_align_slice(&*args.nullifier_key.secret())?),
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
        let nullifier_tree = account.nullifier_tree();
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

fn localnet_nullifier_params() -> zolana_tree::NullifierTreeInitParams {
    let mut params = nullifier_tree_params();
    let zkp_batch_count =
        NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE / NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE;
    params.input_queue_zkp_batch_size = LOCALNET_NULLIFIER_ZKP_BATCH_SIZE;
    params.input_queue_batch_size = LOCALNET_NULLIFIER_ZKP_BATCH_SIZE * zkp_batch_count;
    params
}

fn stress_blinding(index: u64) -> [u8; 32] {
    let mut blinding = [0u8; 32];
    blinding[1] = 0x51;
    blinding[24..].copy_from_slice(&index.to_be_bytes());
    blinding
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
    Ok(ShieldedKeypair::from_keypair(
        SigningKey::from_ed25519_bytes(&seed),
    )?)
}

/// Restart a fresh validator + Photon indexer so each test runs against clean
/// chain state. The protocol config is a global singleton, so tests cannot share
/// a validator; combined with `#[serial]` this gives every test an isolated
/// localnet.
fn restart_localnet() {
    start_shielded_pool_localnet("zolana-photon", ValidatorBackend::default(), &[]);
}
