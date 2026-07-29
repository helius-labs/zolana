//! Full-path dual CU for the same-vk batch instructions: N solo instructions vs
//! one RLC batch on the SBF program under LiteSVM with agave-priced batch
//! syscalls, plus non-ignored e2e twins proving both batch paths execute with
//! proofs.
//!
//! The ignored dual writes `program-libs/groth16-batch/BATCH_CU_RESULTS.md`
//! (run via `just bench-batch-dual`). It measures compact (1,1) entries, which
//! fit the 1232-byte packet at N=2, and wallet-shaped (2,3) entries with
//! synthetic ciphertexts, which need larger packets and are labeled as a 4096
//! size simulation.
#![cfg(not(feature = "localnet"))]

#[path = "common/setup.rs"]
mod common;
#[path = "common/transact.rs"]
mod transact_common;

use std::fs;

use num_bigint::BigUint;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::{
    BatchAddressAppendInputs, ProofCompressed, ProverClient, Rpc, STATE_TREE_HEIGHT,
};
use zolana_hasher::hash_chain::create_hash_chain_from_array;
use zolana_hasher::primitives::hash_bytes;
use zolana_hasher::{sha256::Sha256BE, Hasher, Poseidon};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{CircuitId, TransactIxData},
        BatchTransact, BatchUpdateNullifierTree, BatchUpdateNullifierTreeData,
        BatchUpdateNullifierTreeMany, CompressedProof, CreateTree, Transact,
    },
    pda,
    state::address_tree_params,
    N_PUBLIC_SLOTS,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{system_create_account_ix, test_blinding, ZolanaProgramTest};
use zolana_transaction::{instructions::transact::PrivateTxHash, Data, Utxo, SOL_MINT};
use zolana_tree::TreeAccount;

use crate::transact_common::{
    build_transfer_prover_inputs, dummy_input, dummy_transfer_output, eddsa_input_utxo,
    external_data_hash, fe, inline_outputs, new_transact_ix_data, nullifier_tree,
    output_owner_pk_hashes, prove_and_verify_transfer_vk, public_input_hash, real_output,
    set_output_owner_tags, sol_public_slots, spend_input, start_prover, transfer_output,
    SpendInputArgs, TransferProverInputsArgs,
};

/// Entry shapes for the duals. `Wallet23` mirrors a wallet transfer: the (2,3)
/// circuit with one dummy input, two dummy outputs, and synthetic ciphertexts
/// sized so one entry matches the measured 773-byte wallet entry.
#[derive(Clone, Copy, PartialEq)]
enum EntryShape {
    Compact11,
    Wallet23,
}

/// Per-output synthetic ciphertext bytes for `Wallet23`.
const WALLET_CIPHERTEXT_BYTES: usize = 90;

const TRANSFER_AMOUNT: u64 = 1_000_000;
/// Nullifier-many legs pin the 40_10 address-append proving key.
const NULLIFIER_ZKP_BATCH: u64 = 10;
const RESULTS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../program-libs/groth16-batch/BATCH_CU_RESULTS.md"
);

fn program_test_batch() -> Option<ZolanaProgramTest> {
    match ZolanaProgramTest::with_batch_syscalls() {
        Ok(rpc) => Some(rpc),
        Err(zolana_program_test::ProgramTestError::MissingProgram(_)) => {
            eprintln!(
                "skipping batch dual test: shielded_pool_program.so missing - \
                 run `just build-programs`"
            );
            None
        }
        Err(e) => panic!("program test boot failed: {e}"),
    }
}

/// Send `ixs` as one transaction under an explicit compute limit and return the
/// consumed CU (includes the compute-budget instruction itself in every leg, so
/// leg deltas are comparable).
fn run_cu(rpc: &mut ZolanaProgramTest, ixs: &[Instruction], signers: &[&Keypair]) -> u64 {
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let mut all = vec![compute];
    all.extend_from_slice(ixs);
    let payer = signers.first().expect("fee payer").pubkey();
    let message = Message::new(&all, Some(&payer));
    let tx = Transaction::new(signers, message, rpc.svm.latest_blockhash());
    let meta = rpc
        .svm
        .send_transaction(tx)
        .unwrap_or_else(|e| panic!("dual leg tx failed: {e:?}"));
    meta.compute_units_consumed
}

fn tree_roots(rpc: &ZolanaProgramTest, tree: &Pubkey, utxo_index: u16) -> ([u8; 32], [u8; 32]) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.get_utxo_tree_root(utxo_index).expect("utxo root"),
        account.get_nullifier_tree_root(0).expect("nullifier root"),
    )
}

fn tree_indices(rpc: &ZolanaProgramTest, tree: &Pubkey) -> (u64, u64) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    let output_index = account.utxo_tree().next_index();
    let nullifier_index = account.nullifer_tree().queue_batches.next_index;
    (output_index, nullifier_index)
}

// --- BatchTransact side -----------------------------------------------------

/// Boot a batch-syscall env with a pool tree holding `n` deposits owned by
/// `spender`. Deterministic inputs so a second boot reproduces identical tree
/// state and the same proofs stay valid across legs.
fn boot_transact_env(spender: &Keypair, n: usize) -> Option<(ZolanaProgramTest, Pubkey)> {
    let mut rpc = program_test_batch()?;
    start_prover().expect("start prover");
    let authority = Keypair::new_from_array([88u8; 32]);
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = rpc
        .create_tree(common::tree_account_size(), &authority)
        .expect("create tree");
    rpc.airdrop(&spender.pubkey(), 10_000_000_000)
        .expect("fund spender");
    for i in 0..n {
        let (utxo, nullifier_key, owner_field) = entry_utxo(spender, i);
        let event = rpc
            .deposit_sol(
                &tree.pubkey(),
                spender,
                TRANSFER_AMOUNT,
                owner_field,
                utxo.blinding,
            )
            .expect("proofless deposit");
        let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
        let zero = [0u8; 32];
        let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
        assert_eq!(event.utxo_hash, utxo_hash, "deposited UTXO hash");
    }
    Some((rpc, tree.pubkey()))
}

/// The i-th deterministic (utxo, nullifier key, owner field) owned by `spender`.
fn entry_utxo(spender: &Keypair, i: usize) -> (Utxo, NullifierKey, [u8; 32]) {
    let owner = PublicKey::from_ed25519(&spender.pubkey().to_bytes());
    let nullifier_key = NullifierKey::from_secret([30 + i as u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo = Utxo {
        owner,
        asset: SOL_MINT,
        amount: TRANSFER_AMOUNT,
        blinding: test_blinding(100 + i as u8),
        zone_program_id: None,
        data: Data::default(),
    };
    let owner_field = owner_hash(&owner, &nullifier_pk).expect("owner field");
    (utxo, nullifier_key, owner_field)
}

/// Build `n` independent transact bodies with proofs, each spending deposit
/// `i` against the post-deposit root (history index `n`). `Wallet23` entries
/// pad to the (2,3) circuit with one dummy input and two dummy outputs and
/// carry synthetic ciphertexts, mirroring the transfer flow in
/// `tests/transact/transact.rs`.
fn build_entries(
    rpc: &ZolanaProgramTest,
    tree: &Pubkey,
    spender: &Keypair,
    n: usize,
    shape: EntryShape,
) -> Vec<TransactIxData> {
    let spender_bytes = spender.pubkey().to_bytes();
    let zero = [0u8; 32];
    let roots = tree_roots(rpc, tree, n as u16);
    let (utxo_root, nullifier_root) = roots;

    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    let mut prepared = Vec::with_capacity(n);
    for i in 0..n {
        let (utxo, nullifier_key, owner_field) = entry_utxo(spender, i);
        let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
        let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
        state_tree.append(&utxo_hash).expect("append state leaf");
        prepared.push((utxo, nullifier_key, owner_field, utxo_hash));
    }
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");

    let owner = PublicKey::from_ed25519(&spender_bytes);
    let owner_pk_hash = hash_bytes(&spender_bytes).expect("owner pk hash");
    let payer_pubkey_hash = Sha256BE::hash(&spender_bytes).expect("payer hash");
    let circuit = match shape {
        EntryShape::Compact11 => CircuitId::ConfidentialEddsa(1, 1, N_PUBLIC_SLOTS as u8),
        EntryShape::Wallet23 => CircuitId::ConfidentialEddsa(2, 3, N_PUBLIC_SLOTS as u8),
    };
    let vk = circuit.verifying_key().expect("verifying key");

    let mut entries = Vec::with_capacity(n);
    for (i, (utxo, nullifier_key, owner_field, utxo_hash)) in prepared.iter().enumerate() {
        let state_path: Vec<[u8; 32]> = state_tree
            .get_proof_of_leaf(i, true)
            .expect("state proof")
            .to_vec();
        let nullifier = nullifier_key
            .nullifier(utxo_hash, &utxo.blinding)
            .expect("nullifier");
        let non_inclusion = nf_tree
            .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
            .expect("non-inclusion proof");
        let real_input = spend_input(SpendInputArgs {
            utxo,
            owner_field,
            state_path: &state_path,
            state_path_index: i as u64,
            non_inclusion: &non_inclusion,
            roots,
            nullifier: &nullifier,
            owner_pk_hash: &owner_pk_hash,
            nullifier_key,
        })
        .expect("spend input");

        let output_nullifier_pk = NullifierKey::from_secret([60 + i as u8; 31])
            .pubkey()
            .expect("output nullifier pubkey");
        let output = real_output(
            owner,
            output_nullifier_pk,
            SOL_MINT,
            TRANSFER_AMOUNT,
            [80 + i as u8; 31],
        );
        let output_hash = output.hash().expect("output hash");

        // Per-shape padding: extra nullifiers, output hashes, and witnesses.
        let mut prover_inputs_vec = vec![real_input];
        let mut nullifiers = vec![nullifier];
        let mut output_hashes = vec![output_hash];
        let mut witness_outputs = vec![transfer_output(&output).expect("witness output")];
        let mut output_nullifier_pks = vec![output_nullifier_pk];
        if shape == EntryShape::Wallet23 {
            let (dummy_spend, dummy_nullifier) =
                dummy_input(&[140 + i as u8; 31], &nf_tree, roots, &owner_pk_hash)
                    .expect("dummy input");
            prover_inputs_vec.push(dummy_spend);
            nullifiers.push(dummy_nullifier);
            for blinding in [[150 + i as u8; 31], [160 + i as u8; 31]] {
                let (witness, hash) = dummy_transfer_output(&blinding).expect("dummy output");
                witness_outputs.push(witness);
                output_hashes.push(hash);
                output_nullifier_pks.push(zero);
            }
        }

        let mut ix_outputs = inline_outputs(
            &output_hashes,
            &vec![spender_bytes; output_hashes.len()],
        );
        if shape == EntryShape::Wallet23 {
            for output in &mut ix_outputs {
                output.data = Some(vec![7u8; WALLET_CIPHERTEXT_BYTES]);
            }
        }
        let inputs = nullifiers
            .iter()
            .map(|nf| eddsa_input_utxo(*nf, n as u16))
            .collect();
        let mut ix_data = new_transact_ix_data(inputs, Vec::new(), ix_outputs);
        let owner_pk_hashes =
            output_owner_pk_hashes(&ix_data.outputs).expect("output owner pk hashes");
        set_output_owner_tags(&mut witness_outputs, &owner_pk_hashes, &output_nullifier_pks);

        let external_data_hash = external_data_hash(&ix_data, &[]).expect("external data hash");
        // Dummy slots contribute zero to the private hash.
        let mut private_inputs = vec![*utxo_hash];
        let mut private_outputs = vec![output_hash];
        private_inputs.resize(nullifiers.len(), zero);
        private_outputs.resize(output_hashes.len(), zero);
        let private_tx = PrivateTxHash::new(&private_inputs, &private_outputs, &external_data_hash)
            .hash()
            .expect("private tx hash");
        let (public_slot_assets, public_slot_amounts) = sol_public_slots(zero);
        let input_owner_pk_hashes = vec![owner_pk_hash; nullifiers.len()];
        let public_hash = public_input_hash(
            &nullifiers,
            &output_hashes,
            &vec![utxo_root; nullifiers.len()],
            &vec![nullifier_root; nullifiers.len()],
            &private_tx,
            &external_data_hash,
            &public_slot_assets,
            &public_slot_amounts,
            &payer_pubkey_hash,
            &input_owner_pk_hashes,
            &owner_pk_hashes,
        );
        let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
            inputs: prover_inputs_vec,
            outputs: witness_outputs,
            external_data_hash,
            private_tx_hash: private_tx,
            public_slot_assets,
            public_slot_amounts,
            payer_pubkey_hash,
            public_input_hash: public_hash,
        });
        ix_data.proof = prove_and_verify_transfer_vk(&prover_inputs, public_hash, vk, "dual entry")
            .expect("prove dual entry");
        ix_data.private_tx_hash = private_tx;
        entries.push(ix_data);
    }
    entries
}

fn solo_transact_ix(tree: &Pubkey, spender: &Keypair, data: TransactIxData) -> Instruction {
    Transact {
        payer: spender.pubkey(),
        input_tree: *tree,
        output_tree: *tree,
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction()
}

// --- BatchUpdateNullifierTreeMany side --------------------------------------

/// Boot a batch-syscall env with a pool tree using the small nullifier zkp
/// batch, `count * NULLIFIER_ZKP_BATCH` synthetically queued nullifiers, and a
/// lamport top-up covering forester reimbursements. Returns (env, authority,
/// tree, queued values).
fn boot_nullifier_env(count: usize) -> Option<(ZolanaProgramTest, Keypair, Pubkey, Vec<[u8; 32]>)> {
    let mut rpc = program_test_batch()?;
    start_prover().expect("start prover");
    let authority = Keypair::new_from_array([89u8; 32]);
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    rpc.airdrop(&authority.pubkey(), 10_000_000_000)
        .expect("fund forester authority");

    // Tree with zkp batch 10 so proofs pin the on-disk 40_10 append key; the
    // batch count stays at the default so the account layout size is unchanged.
    let mut params = address_tree_params();
    let zkp_batch_count = params.input_queue_batch_size / params.input_queue_zkp_batch_size;
    params.input_queue_zkp_batch_size = NULLIFIER_ZKP_BATCH;
    params.input_queue_batch_size = NULLIFIER_ZKP_BATCH * zkp_batch_count;

    let tree = Keypair::new_from_array([99u8; 32]);
    let size = common::tree_account_size();
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(size as usize)
        .expect("rent");
    let payer = rpc.payer.pubkey();
    let ixs = [
        system_create_account_ix(
            &payer,
            &tree.pubkey(),
            rent,
            size,
            &pda::shielded_pool_program_id(),
        ),
        CreateTree {
            authority: authority.pubkey(),
            tree: tree.pubkey(),
        }
        .instruction_with_nullifier_params(params),
    ];
    rpc.create_and_send_default_payer_transaction(&ixs, &[&tree, &authority])
        .expect("create nullifier tree");

    // Queue the values directly (the localnet path queues them via transacts)
    // and top up lamports: a synthetic queue never collected forester fees, and
    // reimbursement must not drop the account under rent minimum.
    let queued: Vec<[u8; 32]> = (0..count as u64 * NULLIFIER_ZKP_BATCH)
        .map(|j| fe(1_000 + j))
        .collect();
    let tree_pk = tree.pubkey();
    let mut account = rpc.svm.get_account(&tree_pk).expect("tree account");
    {
        let mut tree_account = TreeAccount::from_bytes(&mut account.data, tree_pk.to_bytes())
            .expect("load tree account");
        let mut nullifier = tree_account.nullifer_tree();
        for value in &queued {
            nullifier
                .insert_nullifier_into_queue(value)
                .expect("queue nullifier");
        }
    }
    account.lamports += 1_000_000_000;
    rpc.svm
        .set_account(tree_pk, account)
        .expect("write seeded tree");
    Some((rpc, authority, tree_pk, queued))
}

/// Build `count` consecutive address-append updates with proofs, mirroring
/// the on-chain public-input derivation for zkp batches `0..count` before any
/// of them is applied.
fn plan_nullifier_updates(
    rpc: &ZolanaProgramTest,
    tree: &Pubkey,
    queued: &[[u8; 32]],
    count: usize,
) -> Vec<BatchUpdateNullifierTreeData> {
    let mut data = rpc.account_data(tree).expect("tree account");
    let mut tree_account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    let nullifier = tree_account.nullifer_tree();
    let metadata = *nullifier.get_metadata();
    let pending_batch_index = metadata.queue_batches.pending_batch_index as usize;
    let zkp_batch_size = metadata.queue_batches.zkp_batch_size as usize;
    let mut current_root = nullifier.get_root().expect("nullifier root");

    let mut reference = nullifier_tree().expect("reference nullifier tree");
    assert_eq!(reference.root(), current_root, "reference root gate");

    let mut updates = Vec::with_capacity(count);
    for zkp_index in 0..count {
        let leaves_hash_chain = nullifier
            .get_hash_chain(pending_batch_index, zkp_index)
            .expect("zkp batch hash chain");
        let start_index = metadata.next_index + (zkp_index * zkp_batch_size) as u64;
        let values = &queued[zkp_index * zkp_batch_size..(zkp_index + 1) * zkp_batch_size];

        let mut low_element_values = Vec::with_capacity(values.len());
        let mut low_element_indices = Vec::with_capacity(values.len());
        let mut low_element_next_values = Vec::with_capacity(values.len());
        let mut new_element_values = Vec::with_capacity(values.len());
        let mut low_element_proofs = Vec::with_capacity(values.len());
        let mut new_element_proofs = Vec::with_capacity(values.len());
        for (offset, value_bytes) in values.iter().enumerate() {
            let value = BigUint::from_bytes_be(value_bytes);
            let non_inclusion = reference
                .get_non_inclusion_proof(&value)
                .expect("non-inclusion proof");
            low_element_values.push(BigUint::from_bytes_be(
                &non_inclusion.leaf_lower_range_value,
            ));
            low_element_indices.push(BigUint::from(non_inclusion.leaf_index as u64));
            low_element_next_values.push(BigUint::from_bytes_be(
                &non_inclusion.leaf_higher_range_value,
            ));
            low_element_proofs.push(path_to_biguint(non_inclusion.merkle_proof));
            new_element_values.push(value.clone());

            reference.append(&value).expect("append to reference");
            let new_index = start_index as usize + offset;
            let new_proof = reference
                .get_proof_of_leaf(new_index, true)
                .expect("new element proof");
            new_element_proofs.push(path_to_biguint(new_proof));
        }

        let new_root = reference.root();
        let mut start_index_bytes = [0u8; 32];
        start_index_bytes[24..].copy_from_slice(&start_index.to_be_bytes());
        let public_input_hash = create_hash_chain_from_array([
            current_root,
            new_root,
            leaves_hash_chain,
            start_index_bytes,
        ])
        .expect("public input hash");

        let inputs = BatchAddressAppendInputs {
            public_input_hash: BigUint::from_bytes_be(&public_input_hash),
            old_root: BigUint::from_bytes_be(&current_root),
            new_root: BigUint::from_bytes_be(&new_root),
            hashchain_hash: BigUint::from_bytes_be(&leaves_hash_chain),
            start_index,
            low_element_values,
            low_element_indices,
            low_element_next_values,
            new_element_values,
            low_element_proofs,
            new_element_proofs,
            tree_height: metadata.height,
            batch_size: values.len() as u32,
        };
        // The lazy prover 408s while the 137MB append key loads on first
        // request; the load continues server-side, so retry until it is warm.
        let proof = (0..5)
            .find_map(|attempt| {
                match ProverClient::local().prove_batch_address_append(&inputs) {
                    Ok(proof) => Some(proof),
                    Err(err) if attempt < 4 => {
                        eprintln!("address-append proof retry after: {err}");
                        None
                    }
                    Err(err) => panic!("prove address append: {err}"),
                }
            })
            .expect("prove address append");
        let compressed = ProofCompressed::try_from(proof).expect("compress proof");
        updates.push(BatchUpdateNullifierTreeData {
            new_root,
            old_root: current_root,
            zkp_batch_index: zkp_index as u16,
            compressed_proof: CompressedProof {
                a: compressed.a,
                b: compressed.b,
                c: compressed.c,
            },
        });
        current_root = new_root;
    }
    updates
}

fn path_to_biguint(path: Vec<[u8; 32]>) -> Vec<BigUint> {
    path.into_iter()
        .map(|item| BigUint::from_bytes_be(&item))
        .collect()
}

fn solo_nullifier_ix(
    tree: &Pubkey,
    authority: &Keypair,
    update: &BatchUpdateNullifierTreeData,
) -> Instruction {
    BatchUpdateNullifierTree {
        authority: authority.pubkey(),
        tree: *tree,
        reimbursement_recipient: authority.pubkey(),
        new_root: update.new_root,
        old_root: update.old_root,
        zkp_batch_index: update.zkp_batch_index,
        compressed_proof_a: update.compressed_proof.a,
        compressed_proof_b: update.compressed_proof.b,
        compressed_proof_c: update.compressed_proof.c,
    }
    .instruction()
}

fn nullifier_root(rpc: &ZolanaProgramTest, tree: &Pubkey) -> [u8; 32] {
    let mut data = rpc.account_data(tree).expect("tree account");
    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    let root = account.nullifer_tree().get_root().expect("root");
    root
}

// --- tests ------------------------------------------------------------------

/// BatchTransact N=2 executes end-to-end with proofs: the runnable example
/// for `docs/batching/examples.md`.
#[test]
fn batch_transact_executes_n2() {
    let spender = Keypair::new_from_array([77u8; 32]);
    let Some((mut rpc, tree)) = boot_transact_env(&spender, 2) else {
        return;
    };
    let entries = build_entries(&rpc, &tree, &spender, 2, EntryShape::Compact11);
    let (out_before, null_before) = tree_indices(&rpc, &tree);

    let ix = BatchTransact {
        payer: spender.pubkey(),
        input_tree: tree,
        output_tree: tree,
        signers: vec![],
        entries,
    }
    .instruction();
    run_cu(&mut rpc, &[ix], &[&spender]);

    let (out_after, null_after) = tree_indices(&rpc, &tree);
    assert_eq!(out_after, out_before + 2, "both outputs appended");
    assert_eq!(null_after, null_before + 2, "both nullifiers queued");
}

/// BatchUpdateNullifierTreeMany N=2 executes end-to-end with proofs.
#[test]
fn nullifier_tree_many_executes_n2() {
    let Some((mut rpc, authority, tree, queued)) = boot_nullifier_env(2) else {
        return;
    };
    let updates = plan_nullifier_updates(&rpc, &tree, &queued, 2);
    let expected_root = updates.last().expect("two updates").new_root;

    let ix = BatchUpdateNullifierTreeMany {
        authority: authority.pubkey(),
        tree,
        reimbursement_recipient: authority.pubkey(),
        updates,
    }
    .instruction();
    run_cu(&mut rpc, &[ix], &[&authority]);

    assert_eq!(
        nullifier_root(&rpc, &tree),
        expected_root,
        "both zkp batches applied"
    );
}

/// Serialized size of an unsigned legacy transaction carrying the compute ix
/// plus `ix`, matching the client probe.
fn probe_tx_bytes(payer: &Pubkey, ix: Instruction) -> usize {
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let message = Message::new(&[compute, ix], Some(payer));
    let signatures = usize::from(message.header.num_required_signatures);
    1 + 64 * signatures + message.serialize().len()
}

struct DualRow {
    label: String,
    legacy: u64,
    batch: u64,
    batch_tx_bytes: Option<usize>,
}

/// One transact dual: N solo instructions in one transaction against one
/// batch instruction, on two identically booted environments.
fn run_transact_dual(shape: EntryShape, n: usize, label: &str) -> Option<DualRow> {
    let spender = Keypair::new_from_array([77u8; 32]);
    let (mut legacy_rpc, tree) = boot_transact_env(&spender, n)?;
    let entries = build_entries(&legacy_rpc, &tree, &spender, n, shape);
    let solo_ixs: Vec<Instruction> = entries
        .iter()
        .cloned()
        .map(|data| solo_transact_ix(&tree, &spender, data))
        .collect();
    let legacy = run_cu(&mut legacy_rpc, &solo_ixs, &[&spender]);

    let (mut batch_rpc, batch_tree) = boot_transact_env(&spender, n).expect("batch env");
    assert_eq!(tree, batch_tree, "deterministic tree address");
    let batch_ix = BatchTransact {
        payer: spender.pubkey(),
        input_tree: tree,
        output_tree: tree,
        signers: vec![],
        entries,
    }
    .instruction();
    let batch_tx_bytes = probe_tx_bytes(&spender.pubkey(), batch_ix.clone());
    let batch = run_cu(&mut batch_rpc, &[batch_ix], &[&spender]);
    Some(DualRow {
        label: label.to_string(),
        legacy,
        batch,
        batch_tx_bytes: Some(batch_tx_bytes),
    })
}

/// The 10% gate: identical state and proofs per dual, CU from the VM.
#[test]
#[ignore = "dual CU; needs SBF + prover. Run via just bench-batch-dual"]
fn dual_cu_same_vk_full_path() {
    let mut rows = Vec::new();
    let Some(compact) = run_transact_dual(
        EntryShape::Compact11,
        2,
        "BatchTransact N=2 vs 2x Transact, (1,1) compact",
    ) else {
        return;
    };
    rows.push(compact);
    rows.push(
        run_transact_dual(
            EntryShape::Wallet23,
            2,
            "BatchTransact N=2 vs 2x Transact, (2,3) wallet shaped",
        )
        .expect("wallet dual n=2"),
    );
    rows.push(
        run_transact_dual(
            EntryShape::Wallet23,
            4,
            "BatchTransact N=4 vs 4x Transact, (2,3) wallet shaped",
        )
        .expect("wallet dual n=4"),
    );

    // NullifierTreeMany N=2 vs 2x single updates.
    let (mut legacy_rpc, authority, tree, queued) = boot_nullifier_env(2).expect("legacy env");
    let updates = plan_nullifier_updates(&legacy_rpc, &tree, &queued, 2);
    let solo_ixs: Vec<Instruction> = updates
        .iter()
        .map(|update| solo_nullifier_ix(&tree, &authority, update))
        .collect();
    let nullifier_legacy = run_cu(&mut legacy_rpc, &solo_ixs, &[&authority]);

    let (mut batch_rpc, authority, batch_tree, _) = boot_nullifier_env(2).expect("batch env");
    assert_eq!(tree, batch_tree, "deterministic tree address");
    let expected_root = updates.last().expect("two updates").new_root;
    let many_ix = BatchUpdateNullifierTreeMany {
        authority: authority.pubkey(),
        tree,
        reimbursement_recipient: authority.pubkey(),
        updates,
    }
    .instruction();
    let nullifier_batch = run_cu(&mut batch_rpc, &[many_ix], &[&authority]);
    assert_eq!(nullifier_root(&batch_rpc, &tree), expected_root);
    rows.push(DualRow {
        label: "NullifierTreeMany N=2 vs 2x single, zkp batch 10".to_string(),
        legacy: nullifier_legacy,
        batch: nullifier_batch,
        batch_tx_bytes: None,
    });

    write_results(&rows);
}

fn write_results(rows: &[DualRow]) {
    let mut md = String::from(
        "# Batch dual CU (LiteSVM + agave batch syscalls)\n\n\
         Policy: ship / recommend only if full-path savings ≥ **10%**. See `docs/batching/`.\n\n\
         Fold-only syscall numbers: [`FOLD_CU.md`](./FOLD_CU.md) (`just bench-batch-fold-cu`).\n\n\
         ## Same-vk multi, full path (measured)\n\n\
         One transaction per leg: N solo instructions vs one batch instruction, CU\n\
         read from the VM. Wallet-shaped entries use the (2,3) circuit with\n\
         synthetic ciphertexts sized to the measured 773-byte wallet entry.\n\
         Nullifier updates use zkp batch 10 (`batch_address-append_40_10.key`).\n\n\
         Batch CU moves a few units between runs because proof bytes are\n\
         random. Treat deltas under 100 CU as the same measurement.\n\n\
         Rows whose batch transaction exceeds 1232 bytes are a 4096 size\n\
         simulation: the CU is measured, the packet does not exist yet.\n\n\
         | Use case | Legacy CU | Batch CU | Delta | Saved | Batch tx bytes | Packet | Gate |\n\
         | --- | ---: | ---: | ---: | ---: | ---: | --- | --- |\n",
    );
    for entry in rows {
        let delta = entry.legacy as i64 - entry.batch as i64;
        let pct = delta as f64 * 100.0 / entry.legacy as f64;
        let verdict = if pct >= 10.0 {
            "**recommend** (≥10%)"
        } else {
            "atomic multi-apply only (<10%)"
        };
        let (bytes, packet) = match entry.batch_tx_bytes {
            Some(bytes) if bytes <= 1232 => (bytes.to_string(), "1232".to_string()),
            Some(bytes) => (bytes.to_string(), "4096 size simulation".to_string()),
            None => ("n/a".to_string(), "1232".to_string()),
        };
        md.push_str(&format!(
            "| {} | {} | {} | {delta} | {pct:.1}% | {bytes} | {packet} | {verdict} |\n",
            entry.label, entry.legacy, entry.batch
        ));
    }
    md.push_str(
        "\nRegenerate: `just bench-batch-dual`.\n\n\
         ## Mixed-key k=2 app plus SPP, no boost (twins removed)\n\n\
         Measured under the experimental `*_BATCH` twins (since deleted). Kept so nobody\n\
         re-implements the same shape for CU.\n\n\
         | Use case | Legacy CU | Batch CU | Delta |\n\
         | --- | ---: | ---: | ---: |\n\
         | Swap take | 269481 | 270878 | -1397 |\n\
         | Swap cancel | 260690 | 262078 | -1388 |\n\
         | Swap make | n/a | n/a | PDA-owned `data_hash` output rejected by SPP circuit |\n\n\
         Batch mixed-key k=2 is slightly higher than legacy: solo app verify is cheap\n\
         relative to SPP, and the RLC still pays n+3k pairing structure.\n",
    );
    fs::write(RESULTS_PATH, &md).expect("write BATCH_CU_RESULTS.md");
    println!("{md}");
}
