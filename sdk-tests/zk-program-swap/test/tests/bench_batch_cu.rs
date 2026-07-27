//! Dual CU: legacy make/take/cancel vs batch twins under LiteSVM with agave
//! batch syscalls. Writes CU pairs into CU_MATRIX batch cells.
//!
//! Run: `just bench-batch-cu`

use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use num_bigint::BigUint;
use solana_account::Account as SolAccount;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use swap_prover::{preload, CircuitId};
use swap_sdk::{
    instructions::{
        cancel::{Cancel, CancelBatch, CancelProofInputParams},
        make::{Make, MakeBatch, MakeProofInputParams, OrderMarker, SppTxHashes},
        pack_standard_vk,
        take::{Take, TakeBatch, TakeProofInputParams},
    },
    order_authority_pda,
    prover::SwapProverClient,
    shared::input_sum,
    state::{OrderTerms, OrderUtxo},
};
use zolana_batch_syscalls::with_batch_syscalls;
use zolana_client::{
    MerkleContext, MerkleProof, NonInclusionProof, ProverClient, SpendProof, NULLIFIER_TREE_HEIGHT,
    STATE_TREE_HEIGHT,
};
use zolana_hasher::Poseidon;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData,
    state::{
        address_tree_params, discriminator::TREE_ACCOUNT_DISCRIMINATOR, tree_account_size,
        STATE_HEIGHT,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, ShieldedKeypair, ViewingKey};
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};
use zolana_transaction::{
    instructions::{
        transact::{
            encrypt_transaction_data, get_transaction_viewing_key,
            spp_proof_inputs::BN254_MODULUS_DEC, ExternalData, SppProofInputs, SppProofOutputUtxo,
        },
        types::SppProofInputUtxo,
    },
    AssetRegistry, Data, Utxo, SOL_ASSET_ID, SOL_MINT,
};
use zolana_tree::TreeAccount;

const SBF_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../target/swap-batch-bench");
const PROVER_KEYS_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../prover/server/proving-keys"
);
const MATRIX_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../program-libs/groth16-batch/CU_MATRIX.md"
);
const RESULTS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../program-libs/groth16-batch/BATCH_CU_RESULTS.md"
);

fn start_prover() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::env::set_var("ZOLANA_PROVER_KEYS_DIR", PROVER_KEYS_DIR);
    });
    zolana_client::spawn_prover().expect("spawn prover");
}

fn keypair_from_payer(payer: &Keypair) -> ShieldedKeypair {
    let seed: [u8; 32] = payer.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    ShieldedKeypair::from_ed25519(&seed, ViewingKey::new()).expect("keypair from payer")
}

fn build_tree_bytes(tree: &Pubkey, leaves: &[[u8; 32]]) -> (Vec<u8>, [u8; 32], [u8; 32], u16) {
    let mut tree_account_bytes = vec![0u8; tree_account_size()];
    let root_index = leaves.len() as u16;
    let (utxo_root, nullifier_root) = {
        let mut account = TreeAccount::init(
            &mut tree_account_bytes,
            TREE_ACCOUNT_DISCRIMINATOR,
            STATE_HEIGHT as u8,
            tree.to_bytes(),
            address_tree_params(),
        )
        .expect("init tree account");
        for leaf in leaves {
            account.utxo_tree().append(*leaf).expect("append leaf");
        }
        (
            account.get_utxo_tree_root(root_index).expect("utxo root"),
            account.get_nullifier_tree_root(0).expect("nullifier root"),
        )
    };
    (tree_account_bytes, utxo_root, nullifier_root, root_index)
}

fn local_state_tree(leaves: &[[u8; 32]]) -> MerkleTree<Poseidon> {
    let mut tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    for leaf in leaves {
        tree.append(leaf).expect("append state leaf");
    }
    tree
}

fn nullifier_tree() -> IndexedMerkleTree<Poseidon, usize> {
    let modulus_minus_one =
        BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10).expect("parse bn254 modulus") - 1u32;
    IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(
        NULLIFIER_TREE_HEIGHT,
        0,
        modulus_minus_one,
    )
    .expect("nullifier tree")
}

fn build_spend_proofs(
    tree: &Pubkey,
    state_tree: &MerkleTree<Poseidon>,
    nf_tree: &IndexedMerkleTree<Poseidon, usize>,
    commitments: &[zolana_transaction::instructions::types::InputUtxoContext],
    utxo_root: [u8; 32],
    nullifier_root: [u8; 32],
    root_index: u16,
) -> Vec<SpendProof> {
    let merkle_context = MerkleContext {
        tree_type: 0,
        tree: Address::new_from_array(tree.to_bytes()),
    };
    commitments
        .iter()
        .enumerate()
        .map(|(leaf_index, commitment)| {
            let state_path = state_tree
                .get_proof_of_leaf(leaf_index, true)
                .expect("state proof")
                .to_vec();
            let nf = nf_tree
                .get_non_inclusion_proof(&BigUint::from_bytes_be(&commitment.nullifier))
                .expect("non inclusion proof");
            SpendProof {
                state: MerkleProof {
                    leaf: commitment.utxo_hash,
                    merkle_context: merkle_context.clone(),
                    path: state_path,
                    leaf_index: leaf_index as u64,
                    root: utxo_root,
                    root_seq: 0,
                    root_index,
                },
                nullifier: NonInclusionProof {
                    leaf: commitment.nullifier,
                    merkle_context: merkle_context.clone(),
                    path: nf.merkle_proof.to_vec(),
                    low_element: nf.leaf_lower_range_value,
                    low_element_index: nf.leaf_index as u64,
                    high_element: nf.leaf_higher_range_value,
                    high_element_index: 0,
                    root: nullifier_root,
                    root_seq: 0,
                    root_index: 0,
                },
            }
        })
        .collect()
}

fn prove_transact(
    proof_inputs: SppProofInputs,
    spend_proofs: &[SpendProof],
    prover: &ProverClient,
) -> (TransactIxData, Duration) {
    prover
        .prove_transact(proof_inputs.clone(), spend_proofs, &[])
        .expect("warm prove transact");
    let start = Instant::now();
    let transact = prover
        .prove_transact(proof_inputs, spend_proofs, &[])
        .expect("prove transact");
    (transact, start.elapsed())
}

struct SvmHarness {
    svm: litesvm::LiteSVM,
}

impl SvmHarness {
    fn new(batch: bool) -> Self {
        let spp_path = PathBuf::from(SBF_DIR).join("shielded_pool_program.so");
        let swap_path = PathBuf::from(SBF_DIR).join("swap_program.so");
        assert!(
            spp_path.exists() && swap_path.exists(),
            "missing SBF under {SBF_DIR}; run just bench-batch-cu"
        );
        let mut svm = litesvm::LiteSVM::new();
        if batch {
            svm = with_batch_syscalls(svm);
        }
        let spp_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        svm.add_program(spp_id, &std::fs::read(&spp_path).expect("read spp"))
            .expect("add spp");
        svm.add_program(swap_program::ID, &std::fs::read(&swap_path).expect("read swap"))
            .expect("add swap");
        Self { svm }
    }

    fn set_tree(&mut self, tree: &Pubkey, data: Vec<u8>) {
        let acc = SolAccount {
            lamports: 1_000_000_000_000,
            data,
            owner: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            executable: false,
            rent_epoch: 0,
        };
        self.svm
            .set_account(*tree, acc)
            .expect("set tree account");
    }

    fn set_system(&mut self, key: &Pubkey, lamports: u64) {
        let acc = SolAccount {
            lamports,
            data: Vec::new(),
            owner: Pubkey::default(),
            executable: false,
            rent_epoch: 0,
        };
        self.svm.set_account(*key, acc).expect("set system account");
    }

    fn set_data(&mut self, key: &Pubkey, data: Vec<u8>) {
        let acc = SolAccount {
            lamports: 1_000_000_000,
            data,
            owner: Pubkey::default(),
            executable: false,
            rent_epoch: 0,
        };
        self.svm.set_account(*key, acc).expect("set data account");
    }

    fn ensure_accounts(&mut self, ix: &Instruction, fixtures: &[(Pubkey, Vec<u8>)]) {
        let spp = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        for meta in &ix.accounts {
            if meta.pubkey == spp || meta.pubkey == swap_program::ID || meta.pubkey == Pubkey::default()
            {
                continue;
            }
            if self.svm.get_account(&meta.pubkey).is_some() {
                continue;
            }
            if let Some((_, data)) = fixtures.iter().find(|(k, _)| *k == meta.pubkey) {
                if data.is_empty() {
                    self.set_system(&meta.pubkey, 100_000_000_000);
                } else {
                    self.set_data(&meta.pubkey, data.clone());
                }
            } else {
                self.set_system(&meta.pubkey, 1_000_000_000);
            }
        }
        // order authority PDA: empty system-owned is fine (invoke_signed only).
        let order_auth = order_authority_pda();
        if self.svm.get_account(&order_auth).is_none() {
            self.set_system(&order_auth, 0);
        }
    }

    fn run_cu(&mut self, ix: Instruction, payer: &Keypair, extra: &[&Keypair]) -> u64 {
        let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let message = Message::new(&[compute, ix], Some(&payer.pubkey()));
        let mut signers: Vec<&Keypair> = vec![payer];
        signers.extend_from_slice(extra);
        let tx = Transaction::new(&signers, message, self.svm.latest_blockhash());
        let meta = self
            .svm
            .send_transaction(tx)
            .unwrap_or_else(|e| panic!("tx failed: {e:?}"));
        meta.compute_units_consumed
    }
}

fn measure_make() -> (u64, u64) {
    const INPUT_AMOUNT: u64 = 1_000_000;
    const SOURCE_AMOUNT: u64 = 400_000;
    const EXPIRY: u64 = 1_900_000_000;

    let tree = Keypair::new().pubkey();
    let payer = Keypair::new();
    let maker = keypair_from_payer(&payer);

    let input_utxo = Utxo {
        owner: maker.signing_pubkey(),
        asset: SOL_MINT,
        amount: INPUT_AMOUNT,
        blinding: random_blinding(),
        zone_program_id: None,
        data: Data::default(),
    };
    let taker = ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([0x4d; 32]))
        .expect("taker");
    let taker_address = taker.shielded_address().expect("taker address");
    let terms = OrderTerms {
        destination_mint: Address::new_from_array([7u8; 32]),
        destination_amount: 250,
        destination: maker.shielded_address().expect("maker address"),
        taker: Address::new_from_array(taker.signing_pubkey().as_ed25519().expect("taker pk")),
        expiry: EXPIRY,
        take_mode: swap_prover::TAKE_MODE_VERIFIABLE,
    };
    let order_utxo = OrderUtxo {
        terms,
        blinding: random_blinding(),
        source_mint: SOL_MINT,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: 2,
    };
    let order_output_utxo = order_utxo
        .output_utxo(taker_address.viewing_pubkey)
        .expect("order output");

    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let spend = SppProofInputUtxo::new(input_utxo, &maker);
    let input_utxos = vec![spend, SppProofInputUtxo::new_dummy()];
    let assets = AssetRegistry::default();
    let leftover =
        input_sum(&input_utxos, &order_output_utxo.asset) - i128::from(order_output_utxo.amount);
    let change_amount = u64::try_from(leftover).expect("balance");
    let change = SppProofOutputUtxo::new(
        order_output_utxo.asset,
        change_amount,
        maker.shielded_address().expect("maker address"),
    )
    .expect("change");
    let order_utxo_hash = order_output_utxo.hash().expect("order hash");
    let marker_message = OrderMarker {
        order_utxo_hash,
        maker_pubkey: payer.pubkey(),
        taker_address,
    }
    .message()
    .expect("marker");
    let tvk = get_transaction_viewing_key(&maker, &input_utxos).expect("tvk");
    let encoded =
        encrypt_transaction_data(&[change.clone(), order_output_utxo], &assets, &tvk)
            .expect("encode");
    let external_data = ExternalData::new(
        *tvk.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![marker_message],
    );
    let spp_proof_inputs =
        SppProofInputs::new(input_utxos, encoded.output_utxos, external_data, payer_address);
    let commitments = spp_proof_inputs.input_utxo_hashes().expect("commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|c| c.utxo_hash).collect();
    let (tree_bytes, utxo_root, nullifier_root, root_index) = build_tree_bytes(&tree, &leaves);
    let state_tree = local_state_tree(&leaves);
    let nf_tree = nullifier_tree();
    let spend_proofs = build_spend_proofs(
        &tree,
        &state_tree,
        &nf_tree,
        &commitments,
        utxo_root,
        nullifier_root,
        root_index,
    );
    let make_params = MakeProofInputParams {
        order_utxo,
        change,
        spp_tx_hashes: SppTxHashes::new(&spp_proof_inputs).expect("hashes"),
    };
    let prover = ProverClient::local();
    let swap_prover = SwapProverClient::new();
    let (transact, _) = prove_transact(spp_proof_inputs, &spend_proofs, &prover);
    let make_proof = swap_prover
        .prove_make(&make_params.to_proof_inputs().expect("make inputs"))
        .expect("make prove");

    let legacy_ix = Make {
        payer: payer.pubkey(),
        tree,
        make_proof: make_proof.clone().into(),
        spp_proof: transact.clone(),
    }
    .instruction()
    .expect("make ix");

    let foreign_vk = Keypair::new().pubkey();
    let vk_bytes = pack_standard_vk(&swap_program::verifying_keys::make::VERIFYINGKEY);
    let batch_ix = MakeBatch {
        payer: payer.pubkey(),
        foreign_vk,
        tree,
        make_proof: make_proof.into(),
        spp_proof: transact,
    }
    .instruction()
    .expect("make batch ix");

    // Fresh SVM per incarnation so tree state is independent.
    let mut legacy_svm = SvmHarness::new(false);
    legacy_svm.set_tree(&tree, tree_bytes.clone());
    legacy_svm.set_system(&payer.pubkey(), 100_000_000_000);
    legacy_svm.ensure_accounts(&legacy_ix, &[(tree, tree_bytes.clone())]);
    let cu_legacy = legacy_svm.run_cu(legacy_ix, &payer, &[]);

    let mut batch_svm = SvmHarness::new(true);
    batch_svm.set_tree(&tree, tree_bytes.clone());
    batch_svm.set_system(&payer.pubkey(), 100_000_000_000);
    batch_svm.set_data(&foreign_vk, vk_bytes);
    batch_svm.ensure_accounts(
        &batch_ix,
        &[(tree, tree_bytes), (foreign_vk, Vec::new())],
    );
    let cu_batch = batch_svm.run_cu(batch_ix, &payer, &[]);

    (cu_legacy, cu_batch)
}

fn measure_take() -> (u64, u64) {
    const SOURCE_AMOUNT: u64 = 400_000;
    const DESTINATION_AMOUNT: u64 = 250;
    const EXPIRY: u64 = 1_900_000_000;

    let tree = Keypair::new().pubkey();
    let taker_payer = Keypair::new();
    let taker = keypair_from_payer(&taker_payer);
    let taker_address = taker.shielded_address().expect("taker address");
    let maker = ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([0x51; 32]))
        .expect("maker");
    let maker_address = maker.shielded_address().expect("maker address");
    let terms = OrderTerms {
        destination_mint: SOL_MINT,
        destination_amount: DESTINATION_AMOUNT,
        destination: maker_address,
        taker: Address::new_from_array(taker.signing_pubkey().as_ed25519().expect("taker pk")),
        expiry: EXPIRY,
        take_mode: swap_prover::TAKE_MODE_DERIVED,
    };
    let order_utxo = OrderUtxo {
        terms,
        blinding: random_blinding(),
        source_mint: SOL_MINT,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: SOL_ASSET_ID,
    };
    let taker_in_blinding = random_blinding();
    let source_output_blinding = random_blinding();
    let taker_in = order_utxo.destination_output(taker_address, taker_in_blinding);
    let source_output = order_utxo.source_output(taker_address, source_output_blinding);
    let destination_output = order_utxo
        .derived_destination_output(maker_address)
        .expect("dest out");
    let order_input_utxo = order_utxo.to_input_utxo().expect("order spend");
    let taker_utxo = Utxo {
        owner: taker.signing_pubkey(),
        asset: SOL_MINT,
        amount: DESTINATION_AMOUNT,
        blinding: taker_in_blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let taker_spend = SppProofInputUtxo::new(taker_utxo, &taker);
    let input_utxos = vec![order_input_utxo, taker_spend];
    let assets = AssetRegistry::default();
    let payer_address = Address::new_from_array(taker_payer.pubkey().to_bytes());
    let tvk = get_transaction_viewing_key(&taker, &input_utxos).expect("tvk");
    let encoded = encrypt_transaction_data(
        &[source_output.clone(), destination_output.clone()],
        &assets,
        &tvk,
    )
    .expect("encode");
    let mut external_data = ExternalData::new(
        *tvk.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    external_data.expiry_unix_ts = order_utxo.terms.expiry;
    let spp_proof_inputs =
        SppProofInputs::new(input_utxos, encoded.output_utxos, external_data, payer_address);
    let commitments = spp_proof_inputs.input_utxo_hashes().expect("commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|c| c.utxo_hash).collect();
    let (tree_bytes, utxo_root, nullifier_root, root_index) = build_tree_bytes(&tree, &leaves);
    let state_tree = local_state_tree(&leaves);
    let nf_tree = nullifier_tree();
    let spend_proofs = build_spend_proofs(
        &tree,
        &state_tree,
        &nf_tree,
        &commitments,
        utxo_root,
        nullifier_root,
        root_index,
    );
    let take_params = TakeProofInputParams {
        order_utxo,
        taker_in,
        source_output,
        destination_output,
        external_data_hash: spp_proof_inputs
            .external_data
            .hash()
            .expect("external data hash"),
    };
    let prover = ProverClient::local();
    let swap_prover = SwapProverClient::new();
    let (transact, _) = prove_transact(spp_proof_inputs, &spend_proofs, &prover);
    let take_proof = swap_prover
        .prove_take(&take_params.to_proof_inputs().expect("take inputs"))
        .expect("take prove");

    let legacy_ix = Take {
        payer: taker_payer.pubkey(),
        tree,
        take_proof: take_proof.clone().into(),
        spp_proof: transact.clone(),
    }
    .instruction()
    .expect("take ix");
    let foreign_vk = Keypair::new().pubkey();
    let vk_bytes = pack_standard_vk(&swap_program::verifying_keys::take::VERIFYINGKEY);
    let batch_ix = TakeBatch {
        payer: taker_payer.pubkey(),
        foreign_vk,
        tree,
        take_proof: take_proof.into(),
        spp_proof: transact,
    }
    .instruction()
    .expect("take batch ix");

    let mut legacy_svm = SvmHarness::new(false);
    legacy_svm.set_tree(&tree, tree_bytes.clone());
    legacy_svm.set_system(&taker_payer.pubkey(), 100_000_000_000);
    legacy_svm.ensure_accounts(&legacy_ix, &[(tree, tree_bytes.clone())]);
    let cu_legacy = legacy_svm.run_cu(legacy_ix, &taker_payer, &[]);

    let mut batch_svm = SvmHarness::new(true);
    batch_svm.set_tree(&tree, tree_bytes.clone());
    batch_svm.set_system(&taker_payer.pubkey(), 100_000_000_000);
    batch_svm.set_data(&foreign_vk, vk_bytes);
    batch_svm.ensure_accounts(
        &batch_ix,
        &[(tree, tree_bytes), (foreign_vk, Vec::new())],
    );
    let cu_batch = batch_svm.run_cu(batch_ix, &taker_payer, &[]);
    (cu_legacy, cu_batch)
}

fn set_clock_after(svm: &mut litesvm::LiteSVM, expiry: u64) {
    use solana_clock::Clock;
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = (expiry as i64).saturating_add(1);
    svm.set_sysvar::<Clock>(&clock);
}

fn measure_cancel() -> (u64, u64) {
    const SOURCE_AMOUNT: u64 = 400_000;
    const ORDER_EXPIRY: u64 = 1_000_000;
    const SPP_RELAYER_DEADLINE: u64 = u64::MAX;

    let tree = Keypair::new().pubkey();
    let maker_payer = Keypair::new();
    let maker = keypair_from_payer(&maker_payer);
    let maker_address = maker.shielded_address().expect("maker address");
    let taker = ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([0x4d; 32]))
        .expect("taker");
    let taker_viewing_pubkey = taker
        .shielded_address()
        .expect("taker address")
        .viewing_pubkey;
    let terms = OrderTerms {
        destination_mint: Address::new_from_array([7u8; 32]),
        destination_amount: 250,
        destination: maker_address,
        taker: Address::new_from_array(taker.signing_pubkey().as_ed25519().expect("taker pk")),
        expiry: ORDER_EXPIRY,
        take_mode: swap_prover::TAKE_MODE_VERIFIABLE,
    };
    let order_utxo = OrderUtxo {
        terms,
        blinding: random_blinding(),
        source_mint: SOL_MINT,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: 2,
    };
    let source_output =
        order_utxo.source_output(maker_address, random_blinding());
    let order_input_utxo = order_utxo.to_input_utxo().expect("order spend");
    let input_utxos = vec![order_input_utxo];
    let assets = AssetRegistry::default();
    let payer_address = Address::new_from_array(maker_payer.pubkey().to_bytes());
    let tvk = get_transaction_viewing_key(&maker, &input_utxos).expect("tvk");
    let encoded =
        encrypt_transaction_data(std::slice::from_ref(&source_output), &assets, &tvk)
            .expect("encode");
    let mut external_data = ExternalData::new(
        *tvk.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    external_data.expiry_unix_ts = SPP_RELAYER_DEADLINE;
    let spp_proof_inputs =
        SppProofInputs::new(input_utxos, encoded.output_utxos, external_data, payer_address);
    let commitments = spp_proof_inputs.input_utxo_hashes().expect("commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|c| c.utxo_hash).collect();
    let (tree_bytes, utxo_root, nullifier_root, root_index) = build_tree_bytes(&tree, &leaves);
    let state_tree = local_state_tree(&leaves);
    let nf_tree = nullifier_tree();
    let spend_proofs = build_spend_proofs(
        &tree,
        &state_tree,
        &nf_tree,
        &commitments,
        utxo_root,
        nullifier_root,
        root_index,
    );
    let cancel_params = CancelProofInputParams {
        order_utxo: order_utxo.clone(),
        taker_viewing_pubkey,
        source_output,
        external_data_hash: spp_proof_inputs
            .external_data
            .hash()
            .expect("external data hash"),
    };
    let prover = ProverClient::local();
    let swap_prover = SwapProverClient::new();
    let (transact, _) = prove_transact(spp_proof_inputs, &spend_proofs, &prover);
    let cancel_proof = swap_prover
        .prove_cancel(&cancel_params.to_proof_inputs().expect("cancel inputs"))
        .expect("cancel prove");

    let maker_signer = Pubkey::new_from_array(
        maker_address
            .signing_pubkey
            .as_ed25519()
            .expect("maker ed25519"),
    );
    let legacy_ix = Cancel {
        maker: maker_signer,
        payer: maker_payer.pubkey(),
        tree,
        cancel_proof: cancel_proof.clone().into(),
        order_expiry: order_utxo.terms.expiry,
        spp_proof: transact.clone(),
    }
    .instruction()
    .expect("cancel ix");
    let foreign_vk = Keypair::new().pubkey();
    let vk_bytes = pack_standard_vk(&swap_program::verifying_keys::cancel::VERIFYINGKEY);
    let batch_ix = CancelBatch {
        maker: maker_signer,
        payer: maker_payer.pubkey(),
        foreign_vk,
        tree,
        cancel_proof: cancel_proof.into(),
        order_expiry: order_utxo.terms.expiry,
        spp_proof: transact,
    }
    .instruction()
    .expect("cancel batch ix");

    let mut legacy_svm = SvmHarness::new(false);
    legacy_svm.set_tree(&tree, tree_bytes.clone());
    legacy_svm.set_system(&maker_payer.pubkey(), 100_000_000_000);
    set_clock_after(&mut legacy_svm.svm, ORDER_EXPIRY);
    legacy_svm.ensure_accounts(&legacy_ix, &[(tree, tree_bytes.clone())]);
    let cu_legacy = legacy_svm.run_cu(legacy_ix, &maker_payer, &[]);

    let mut batch_svm = SvmHarness::new(true);
    batch_svm.set_tree(&tree, tree_bytes.clone());
    batch_svm.set_system(&maker_payer.pubkey(), 100_000_000_000);
    set_clock_after(&mut batch_svm.svm, ORDER_EXPIRY);
    batch_svm.set_data(&foreign_vk, vk_bytes);
    batch_svm.ensure_accounts(
        &batch_ix,
        &[(tree, tree_bytes), (foreign_vk, Vec::new())],
    );
    let cu_batch = batch_svm.run_cu(batch_ix, &maker_payer, &[]);
    (cu_legacy, cu_batch)
}

fn patch_matrix(results: &BTreeMap<&str, (u64, u64)>) {
    let path = PathBuf::from(MATRIX_PATH);
    let mut md = fs::read_to_string(&path).expect("read CU_MATRIX");
    for (name, (legacy, batch)) in results {
        // Replace blank batch CU cell for known rows: "| Swap make | batch | 2 | | ..."
        let needle = format!("| {name} | batch | 2 | |");
        let repl = format!("| {name} | batch | 2 | {batch} |");
        if md.contains(&needle) {
            md = md.replacen(&needle, &repl, 1);
        }
        let _ = legacy; // legacy already filled from BENCHMARK.md
    }
    // Also note dual harness
    if !md.contains("bench-batch-cu") {
        md = md.replacen(
            "Regenerate: `cargo test -p zolana-groth16-batch --test matrix_measure -- --nocapture`",
            "Regenerate sizes: `just bench-batch-matrix`\n\nBatch full-path CU: `just bench-batch-cu` (LiteSVM + agave batch syscalls)",
            1,
        );
    }
    fs::write(&path, md).expect("write CU_MATRIX");
}

#[test]
#[ignore = "dual CU; needs SBF + prover. Run via just bench-batch-cu"]
fn bench_batch_cu_dual() {
    start_prover();
    preload(CircuitId::Make).expect("preload make");
    preload(CircuitId::Take).expect("preload take");
    preload(CircuitId::Cancel).expect("preload cancel");

    let mut results = BTreeMap::new();
    let mut report = String::from("# Batch dual CU (LiteSVM + agave batch syscalls)\n\n");
    report.push_str("| Use case | Legacy CU | Batch CU | Delta |\n| --- | ---: | ---: | ---: |\n");

    println!("measuring make…");
    let (ml, mb) = measure_make();
    results.insert("Swap make", (ml, mb));
    report.push_str(&format!(
        "| Swap make | {ml} | {mb} | {} |\n",
        ml as i64 - mb as i64
    ));
    println!("make legacy={ml} batch={mb}");

    println!("measuring take…");
    let (tl, tb) = measure_take();
    results.insert("Swap take", (tl, tb));
    report.push_str(&format!(
        "| Swap take | {tl} | {tb} | {} |\n",
        tl as i64 - tb as i64
    ));
    println!("take legacy={tl} batch={tb}");

    println!("measuring cancel…");
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(measure_cancel)) {
        Ok((cl, cb)) => {
            results.insert("Swap cancel", (cl, cb));
            report.push_str(&format!(
                "| Swap cancel | {cl} | {cb} | {} |\n",
                cl as i64 - cb as i64
            ));
            println!("cancel legacy={cl} batch={cb}");
        }
        Err(_) => {
            report.push_str("| Swap cancel | (failed) | (failed) | |\n");
            eprintln!("cancel dual measure panicked; skip");
        }
    }

    fs::write(RESULTS_PATH, &report).expect("write results");
    patch_matrix(&results);
    println!("{report}");
}
