#![cfg(feature = "test-only")]

use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use solana_address::Address;
use zolana_batched_merkle_tree::merkle_tree_metadata::TreeType;
use zolana_batched_merkle_tree::{
    constants::NULLIFIER_TREE_INIT_ROOT_40,
    errors::BatchedMerkleTreeError,
    initialize_address_tree::InitAddressTreeAccountsInstructionData,
    merkle_tree::{
        get_merkle_tree_account_size, BatchedMerkleTreeAccount, BatchedMerkleTreeInit,
        FoldedAddressAppendInputs, InstructionDataAddressAppendInputs,
    },
    verify::{CommittedProof, CompressedProof},
};
use zolana_client::{
    spawn_prover, BatchAddressAppendInputs, FoldAppend, NullifierFoldInputs, Proof,
    ProofCompressed, ProverClient,
};
use zolana_hasher::{hash_chain::create_hash_chain_from_array, Poseidon};
use zolana_merkle_tree::indexed::IndexedMerkleTree;

const HEIGHT: u32 = 40;
const NUM_ITERS: usize = 10;
const BLOOM: usize = 4096;
const ZKP: usize = 5;
const ZKP_BATCH_SIZE: u64 = 10;
const ROOT_HISTORY: usize = 20;
const NUM_TXNS: usize = 300;

type NullifierTree<'a> = BatchedMerkleTreeAccount<'a, ROOT_HISTORY, NUM_ITERS, BLOOM, ZKP>;

fn reference_nullifier_tree() -> IndexedMerkleTree<Poseidon, usize> {
    let modulus: BigUint = Fr::MODULUS.into();
    IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(HEIGHT as usize, 0, modulus - 1u32)
        .unwrap()
}

fn test_config() -> InitAddressTreeAccountsInstructionData {
    let mut params = InitAddressTreeAccountsInstructionData::test_default();
    params.root_history_capacity = ROOT_HISTORY as u32;
    params
}

fn init_nullifier_tree<'a>(account_data: &'a mut [u8], pubkey: &Address) -> NullifierTree<'a> {
    let params = test_config();
    BatchedMerkleTreeAccount::init(
        account_data,
        pubkey,
        BatchedMerkleTreeInit {
            root_history_capacity: params.root_history_capacity,
            input_queue_batch_size: params.input_queue_batch_size,
            input_queue_zkp_batch_size: params.input_queue_zkp_batch_size,
            height: params.height,
            tree_type: TreeType::AddressV2,
            address_init_root: Some(NULLIFIER_TREE_INIT_ROOT_40),
        },
    )
    .unwrap()
}

fn load_nullifier_tree<'a>(account_data: &'a mut [u8], pubkey: &Address) -> NullifierTree<'a> {
    BatchedMerkleTreeAccount::address_from_bytes(account_data, pubkey).unwrap()
}

fn random_nullifier(rng: &mut StdRng) -> [u8; 32] {
    let mut bytes: [u8; 32] = rng.gen();
    bytes[0] = 0;
    bytes
}

fn path_to_biguint(path: Vec<[u8; 32]>) -> Vec<BigUint> {
    path.into_iter()
        .map(|node| BigUint::from_bytes_be(&node))
        .collect()
}

struct PreparedUpdate {
    instruction: InstructionDataAddressAppendInputs,
    new_root: [u8; 32],
}

struct NullifierForester {
    reference: IndexedMerkleTree<Poseidon, usize>,
    inserted_into_tree: usize,
    /// Retained by `prepare_pending_batch` so a fold can reuse the same proofs
    /// the sequential path would submit.
    append_proofs: Vec<Proof>,
}

impl NullifierForester {
    fn new() -> Self {
        Self {
            reference: reference_nullifier_tree(),
            inserted_into_tree: 0,
            append_proofs: Vec::new(),
        }
    }

    fn perform_update(&mut self, account: &mut NullifierTree<'_>, queued: &[[u8; 32]]) -> [u8; 32] {
        let metadata = *account.get_metadata();
        let pending = metadata.queue_batches.pending_batch_index as usize;
        let zkp_batch_size = metadata.queue_batches.zkp_batch_size as usize;
        let next_index = metadata.next_index;
        let height = metadata.height;
        let zkp_index = metadata.queue_batches.batches[pending]
            .get_first_ready_zkp_batch()
            .unwrap() as usize;
        let leaves_hash_chain = account.get_hash_chain(pending, zkp_index).unwrap();
        let old_root = account.get_root().unwrap();

        assert_eq!(
            self.reference.root(),
            old_root,
            "reference root diverged from on-chain root before update"
        );

        let batch_values =
            &queued[self.inserted_into_tree..self.inserted_into_tree + zkp_batch_size];
        let (inputs, new_root) = self.build_inputs(
            next_index,
            height,
            leaves_hash_chain,
            old_root,
            batch_values,
        );

        let proof = ProverClient::local()
            .prove_batch_address_append(&inputs)
            .unwrap();
        let compressed = ProofCompressed::try_from(proof).unwrap();
        let instruction_data = InstructionDataAddressAppendInputs {
            new_root,
            old_root,
            zkp_batch_index: zkp_index as u16,
            compressed_proof: CompressedProof {
                a: compressed.a,
                b: compressed.b,
                c: compressed.c,
            },
        };
        let result = account
            .update_tree_from_address_queue(instruction_data)
            .unwrap();
        let event = result.unwrap();
        assert_eq!(event.num_update, 1);
        assert_eq!(event.new_root, new_root);
        self.inserted_into_tree += zkp_batch_size;
        new_root
    }

    fn prepare_pending_batch(
        &mut self,
        account: &NullifierTree<'_>,
        queued: &[[u8; 32]],
    ) -> Vec<PreparedUpdate> {
        let metadata = *account.get_metadata();
        let pending = metadata.queue_batches.pending_batch_index as usize;
        let zkp_batch_size = metadata.queue_batches.zkp_batch_size as usize;
        let height = metadata.height;
        let base_next_index = metadata.next_index;

        let batch = metadata.queue_batches.batches.get(pending).unwrap();
        let num_full = batch.get_current_zkp_batch_index() as usize;
        let already_applied = batch.get_num_inserted_zkps() as usize;

        assert_eq!(
            self.reference.root(),
            account.get_root().unwrap(),
            "reference must be aligned with the on-chain root before preparing"
        );

        let mut prepared = Vec::new();
        for zkp_index in already_applied..num_full {
            let next_index =
                base_next_index + ((zkp_index - already_applied) as u64) * zkp_batch_size as u64;
            let leaves_hash_chain = account.get_hash_chain(pending, zkp_index).unwrap();
            let old_root = self.reference.root();
            let batch_values =
                &queued[self.inserted_into_tree..self.inserted_into_tree + zkp_batch_size];
            let (inputs, new_root) = self.build_inputs(
                next_index,
                height,
                leaves_hash_chain,
                old_root,
                batch_values,
            );

            let proof = ProverClient::local()
                .prove_batch_address_append(&inputs)
                .unwrap();
            self.append_proofs.push(proof);
            let compressed = ProofCompressed::try_from(proof).unwrap();
            let instruction = InstructionDataAddressAppendInputs {
                new_root,
                old_root,
                zkp_batch_index: zkp_index as u16,
                compressed_proof: CompressedProof {
                    a: compressed.a,
                    b: compressed.b,
                    c: compressed.c,
                },
            };
            prepared.push(PreparedUpdate {
                instruction,
                new_root,
            });
            self.inserted_into_tree += zkp_batch_size;
        }
        prepared
    }

    fn build_inputs(
        &mut self,
        next_index: u64,
        height: u32,
        leaves_hash_chain: [u8; 32],
        old_root: [u8; 32],
        batch_values: &[[u8; 32]],
    ) -> (BatchAddressAppendInputs, [u8; 32]) {
        let mut low_element_values = Vec::with_capacity(batch_values.len());
        let mut low_element_indices = Vec::with_capacity(batch_values.len());
        let mut low_element_next_values = Vec::with_capacity(batch_values.len());
        let mut new_element_values = Vec::with_capacity(batch_values.len());
        let mut low_element_proofs = Vec::with_capacity(batch_values.len());
        let mut new_element_proofs = Vec::with_capacity(batch_values.len());

        for (offset, value_bytes) in batch_values.iter().enumerate() {
            let value = BigUint::from_bytes_be(value_bytes);
            let non_inclusion = self.reference.get_non_inclusion_proof(&value).unwrap();
            low_element_values.push(BigUint::from_bytes_be(
                &non_inclusion.leaf_lower_range_value,
            ));
            low_element_indices.push(BigUint::from(non_inclusion.leaf_index as u64));
            low_element_next_values.push(BigUint::from_bytes_be(
                &non_inclusion.leaf_higher_range_value,
            ));
            low_element_proofs.push(path_to_biguint(non_inclusion.merkle_proof));
            new_element_values.push(value.clone());

            self.reference.append(&value).unwrap();
            let new_index = next_index as usize + offset;
            let new_proof = self.reference.get_proof_of_leaf(new_index, true).unwrap();
            new_element_proofs.push(path_to_biguint(new_proof));
        }

        let new_root = self.reference.root();
        let mut start_index_bytes = [0u8; 32];
        start_index_bytes[24..].copy_from_slice(&next_index.to_be_bytes());
        let public_input_hash = create_hash_chain_from_array([
            old_root,
            new_root,
            leaves_hash_chain,
            start_index_bytes,
        ])
        .unwrap();

        (
            BatchAddressAppendInputs {
                public_input_hash: BigUint::from_bytes_be(&public_input_hash),
                old_root: BigUint::from_bytes_be(&old_root),
                new_root: BigUint::from_bytes_be(&new_root),
                hashchain_hash: BigUint::from_bytes_be(&leaves_hash_chain),
                start_index: next_index,
                low_element_values,
                low_element_indices,
                low_element_next_values,
                new_element_values,
                low_element_proofs,
                new_element_proofs,
                tree_height: height,
                batch_size: batch_values.len() as u32,
            },
            new_root,
        )
    }
}

#[test]
fn nullifier_tree_initial_root_matches_reference() {
    let pubkey = Address::new_unique();
    let mut account_data =
        vec![0u8; get_merkle_tree_account_size::<ROOT_HISTORY, NUM_ITERS, BLOOM, ZKP>()];
    let account = init_nullifier_tree(&mut account_data, &pubkey);

    assert_eq!(account.get_root().unwrap(), NULLIFIER_TREE_INIT_ROOT_40);
    assert_eq!(
        reference_nullifier_tree().root(),
        NULLIFIER_TREE_INIT_ROOT_40
    );
}

#[test]
fn nullifier_tree_single_update() {
    spawn_prover().unwrap();
    let mut rng = StdRng::seed_from_u64(0);
    let pubkey = Address::new_unique();
    let mut account_data =
        vec![0u8; get_merkle_tree_account_size::<ROOT_HISTORY, NUM_ITERS, BLOOM, ZKP>()];
    let mut account = init_nullifier_tree(&mut account_data, &pubkey);

    let mut queued = Vec::new();
    for _ in 0..10u64 {
        let nullifier = random_nullifier(&mut rng);
        account.insert_nullifier_into_queue(&nullifier).unwrap();
        queued.push(nullifier);
    }

    let mut forester = NullifierForester::new();
    let new_root = forester.perform_update(&mut account, &queued);
    assert_eq!(account.get_root().unwrap(), new_root);
    assert_eq!(account.get_root().unwrap(), forester.reference.root());
}

fn fill_pending_batch_and_prepare(
    account_data: &mut [u8],
    pubkey: &Address,
    forester: &mut NullifierForester,
    queued: &mut Vec<[u8; 32]>,
    rng: &mut StdRng,
    count: usize,
) -> Vec<PreparedUpdate> {
    for _ in 0..count {
        let nullifier = random_nullifier(rng);
        let mut account = load_nullifier_tree(account_data, pubkey);
        account.insert_nullifier_into_queue(&nullifier).unwrap();
        queued.push(nullifier);
    }
    let account = load_nullifier_tree(account_data, pubkey);
    forester.prepare_pending_batch(&account, queued)
}

#[test]
fn nullifier_tree_fills_root_history_with_random_submit_order() {
    spawn_prover().unwrap();
    let mut rng = StdRng::seed_from_u64(0);
    let pubkey = Address::new_unique();
    let mut account_data =
        vec![0u8; get_merkle_tree_account_size::<ROOT_HISTORY, NUM_ITERS, BLOOM, ZKP>()];
    init_nullifier_tree(&mut account_data, &pubkey);

    let batch_size = test_config().input_queue_batch_size as usize;
    let num_batches = NUM_TXNS / batch_size;
    let zkp_batches_per_batch = batch_size / ZKP_BATCH_SIZE as usize;

    let mut forester = NullifierForester::new();
    let mut queued: Vec<[u8; 32]> = Vec::new();
    let mut updates = 0usize;

    for cycle in 0..num_batches {
        let mut prepared = fill_pending_batch_and_prepare(
            &mut account_data,
            &pubkey,
            &mut forester,
            &mut queued,
            &mut rng,
            batch_size,
        );
        assert_eq!(prepared.len(), zkp_batches_per_batch);

        // The batch filled this cycle covers the queue range one rotation past
        // its previous coverage: start_index = init next_index + cycle * batch_size.
        let account = load_nullifier_tree(&mut account_data, &pubkey);
        let filled_batch = account.queue_batches.batches.get(cycle % 2).unwrap();
        assert_eq!(filled_batch.start_index, 1 + (cycle * batch_size) as u64);

        let expected_new_roots: Vec<[u8; 32]> = prepared.iter().map(|prep| prep.new_root).collect();
        prepared.shuffle(&mut rng);

        let mut applied = 0usize;
        for prep in &prepared {
            let mut account = load_nullifier_tree(&mut account_data, &pubkey);
            let result = account
                .update_tree_from_address_queue(prep.instruction)
                .unwrap();
            if let Some(event) = result {
                assert_eq!(event.first_zkp_batch_index as usize, applied);
                applied += event.num_update as usize;
                assert_eq!(
                    event.new_root,
                    *expected_new_roots.get(applied - 1).unwrap()
                );
            }
        }

        assert_eq!(applied, prepared.len());
        let account = load_nullifier_tree(&mut account_data, &pubkey);
        assert_eq!(
            account.get_root().unwrap(),
            forester.reference.root(),
            "on-chain root diverged from the reference tree"
        );
        updates += prepared.len();
    }

    assert_eq!(updates, num_batches * zkp_batches_per_batch);
    assert!(updates >= ROOT_HISTORY);
    let account = load_nullifier_tree(&mut account_data, &pubkey);
    assert_eq!(account.root_history().len(), ROOT_HISTORY);
    assert_eq!(account.get_root().unwrap(), forester.reference.root());
}

#[test]
fn nullifier_tree_reverse_order_submission_cascades() {
    spawn_prover().unwrap();
    let mut rng = StdRng::seed_from_u64(1);
    let pubkey = Address::new_unique();
    let mut account_data =
        vec![0u8; get_merkle_tree_account_size::<ROOT_HISTORY, NUM_ITERS, BLOOM, ZKP>()];
    let genesis_root = init_nullifier_tree(&mut account_data, &pubkey)
        .get_root()
        .unwrap();

    let batch_size = test_config().input_queue_batch_size as usize;
    let mut forester = NullifierForester::new();
    let mut queued: Vec<[u8; 32]> = Vec::new();
    let prepared = fill_pending_batch_and_prepare(
        &mut account_data,
        &pubkey,
        &mut forester,
        &mut queued,
        &mut rng,
        batch_size,
    );
    let last_index = prepared.len() - 1;

    for (offset, prep) in prepared.iter().rev().enumerate() {
        let mut account = load_nullifier_tree(&mut account_data, &pubkey);
        let result = account
            .update_tree_from_address_queue(prep.instruction)
            .unwrap();
        if offset < last_index {
            assert!(result.is_none());
            assert_eq!(account.get_root().unwrap(), genesis_root);
        } else {
            assert_eq!(result.unwrap().num_update as usize, prepared.len());
        }
    }

    let account = load_nullifier_tree(&mut account_data, &pubkey);
    assert_eq!(account.get_root().unwrap(), forester.reference.root());
}

#[test]
fn nullifier_tree_partial_prefix_waits_then_cascades() {
    spawn_prover().unwrap();
    let mut rng = StdRng::seed_from_u64(2);
    let pubkey = Address::new_unique();
    let mut account_data =
        vec![0u8; get_merkle_tree_account_size::<ROOT_HISTORY, NUM_ITERS, BLOOM, ZKP>()];
    let genesis_root = init_nullifier_tree(&mut account_data, &pubkey)
        .get_root()
        .unwrap();

    let batch_size = test_config().input_queue_batch_size as usize;
    let mut forester = NullifierForester::new();
    let mut queued: Vec<[u8; 32]> = Vec::new();
    let prepared = fill_pending_batch_and_prepare(
        &mut account_data,
        &pubkey,
        &mut forester,
        &mut queued,
        &mut rng,
        batch_size,
    );

    for prep in prepared.iter().skip(1) {
        let mut account = load_nullifier_tree(&mut account_data, &pubkey);
        let result = account
            .update_tree_from_address_queue(prep.instruction)
            .unwrap();
        assert!(result.is_none());
        assert_eq!(account.get_root().unwrap(), genesis_root);
    }

    let mut account = load_nullifier_tree(&mut account_data, &pubkey);
    let result = account
        .update_tree_from_address_queue(prepared.first().unwrap().instruction)
        .unwrap();
    assert_eq!(result.unwrap().num_update as usize, prepared.len());
    assert_eq!(account.get_root().unwrap(), forester.reference.root());
}

#[test]
fn nullifier_tree_duplicate_index_applies_once() {
    spawn_prover().unwrap();
    let mut rng = StdRng::seed_from_u64(3);
    let pubkey = Address::new_unique();
    let mut account_data =
        vec![0u8; get_merkle_tree_account_size::<ROOT_HISTORY, NUM_ITERS, BLOOM, ZKP>()];
    init_nullifier_tree(&mut account_data, &pubkey);

    let batch_size = test_config().input_queue_batch_size as usize;
    let mut forester = NullifierForester::new();
    let mut queued: Vec<[u8; 32]> = Vec::new();
    let prepared = fill_pending_batch_and_prepare(
        &mut account_data,
        &pubkey,
        &mut forester,
        &mut queued,
        &mut rng,
        batch_size,
    );

    let resend = prepared.get(2).unwrap();
    for _ in 0..2 {
        let mut account = load_nullifier_tree(&mut account_data, &pubkey);
        let result = account
            .update_tree_from_address_queue(resend.instruction)
            .unwrap();
        assert!(result.is_none());
    }

    let mut total_applied = 0usize;
    for prep in &prepared {
        let mut account = load_nullifier_tree(&mut account_data, &pubkey);
        let result = account
            .update_tree_from_address_queue(prep.instruction)
            .unwrap();
        total_applied += result.map_or(0, |e| e.num_update as usize);
    }

    assert_eq!(total_applied, prepared.len());
    let account = load_nullifier_tree(&mut account_data, &pubkey);
    assert_eq!(account.get_root().unwrap(), forester.reference.root());
}

#[test]
fn nullifier_tree_resend_applied_proof_is_noop() {
    spawn_prover().unwrap();
    let mut rng = StdRng::seed_from_u64(4);
    let pubkey = Address::new_unique();
    let mut account_data =
        vec![0u8; get_merkle_tree_account_size::<ROOT_HISTORY, NUM_ITERS, BLOOM, ZKP>()];
    init_nullifier_tree(&mut account_data, &pubkey);

    let batch_size = test_config().input_queue_batch_size as usize;
    let mut forester = NullifierForester::new();
    let mut queued: Vec<[u8; 32]> = Vec::new();
    let prepared = fill_pending_batch_and_prepare(
        &mut account_data,
        &pubkey,
        &mut forester,
        &mut queued,
        &mut rng,
        batch_size,
    );

    let prefix = prepared.len() - 2;
    for prep in prepared.iter().take(prefix) {
        let mut account = load_nullifier_tree(&mut account_data, &pubkey);
        let result = account
            .update_tree_from_address_queue(prep.instruction)
            .unwrap();
        assert_eq!(result.unwrap().num_update, 1);
    }

    let prefix_root = {
        let account = load_nullifier_tree(&mut account_data, &pubkey);
        account.get_root().unwrap()
    };

    for prep in prepared.iter().take(prefix) {
        let mut account = load_nullifier_tree(&mut account_data, &pubkey);
        let result = account
            .update_tree_from_address_queue(prep.instruction)
            .unwrap();
        assert!(result.is_none());
        assert_eq!(account.get_root().unwrap(), prefix_root);
    }

    for prep in prepared.iter().skip(prefix) {
        let mut account = load_nullifier_tree(&mut account_data, &pubkey);
        account
            .update_tree_from_address_queue(prep.instruction)
            .unwrap();
    }
    let account = load_nullifier_tree(&mut account_data, &pubkey);
    assert_eq!(account.get_root().unwrap(), forester.reference.root());
}

#[test]
fn nullifier_tree_submit_index_errors() {
    let pubkey = Address::new_unique();
    let mut account_data =
        vec![0u8; get_merkle_tree_account_size::<ROOT_HISTORY, NUM_ITERS, BLOOM, ZKP>()];
    init_nullifier_tree(&mut account_data, &pubkey);

    let mut rng = StdRng::seed_from_u64(5);
    let zkp_batch_size = ZKP_BATCH_SIZE as usize;
    for _ in 0..zkp_batch_size {
        let nullifier = random_nullifier(&mut rng);
        let mut account = load_nullifier_tree(&mut account_data, &pubkey);
        account.insert_nullifier_into_queue(&nullifier).unwrap();
    }

    let dummy = InstructionDataAddressAppendInputs {
        new_root: [0u8; 32],
        old_root: [0u8; 32],
        zkp_batch_index: 0,
        compressed_proof: CompressedProof {
            a: [0u8; 32],
            b: [0u8; 64],
            c: [0u8; 32],
        },
    };

    let mut out_of_range = dummy;
    out_of_range.zkp_batch_index = ZKP as u16;
    let mut account = load_nullifier_tree(&mut account_data, &pubkey);
    assert_eq!(
        account
            .update_tree_from_address_queue(out_of_range)
            .unwrap_err(),
        BatchedMerkleTreeError::CachedTreeUpdateIndexOutOfRange
    );

    let mut not_ready = dummy;
    not_ready.zkp_batch_index = 1;
    let mut account = load_nullifier_tree(&mut account_data, &pubkey);
    assert_eq!(
        account
            .update_tree_from_address_queue(not_ready)
            .unwrap_err(),
        BatchedMerkleTreeError::HashChainNotReady
    );
}

/// A folded run must land the tree in exactly the state the same appends would
/// have reached one at a time, while appending only the span's final root.
///
/// This is the property the fold trades on. The intermediate roots are private
/// to the proof and never enter root history, so the check is that `next_index`,
/// the inserted-batch count, and the final root all match, not that history
/// matches append-by-append.
#[test]
fn nullifier_tree_folded_run_matches_sequential_appends() {
    spawn_prover().unwrap();
    const RUN: u32 = 2;

    let mut rng = StdRng::seed_from_u64(7);
    let pubkey = Address::new_unique();
    let mut account_data =
        vec![0u8; get_merkle_tree_account_size::<ROOT_HISTORY, NUM_ITERS, BLOOM, ZKP>()];
    init_nullifier_tree(&mut account_data, &pubkey);

    let mut forester = NullifierForester::new();
    let mut queued: Vec<[u8; 32]> = Vec::new();
    let prepared = fill_pending_batch_and_prepare(
        &mut account_data,
        &pubkey,
        &mut forester,
        &mut queued,
        &mut rng,
        RUN as usize * ZKP_BATCH_SIZE as usize,
    );
    assert_eq!(
        prepared.len(),
        RUN as usize,
        "expected one update per zkp batch"
    );

    let (old_root, old_next_index, span_end) = {
        let account = load_nullifier_tree(&mut account_data, &pubkey);
        (
            account.get_root().unwrap(),
            account.get_metadata().next_index,
            prepared.last().unwrap().new_root,
        )
    };
    assert_eq!(
        old_root, prepared[0].instruction.old_root,
        "the run must start at the account tree root"
    );

    // Prove the fold over the same appends the sequential path would submit.
    let appends: Vec<FoldAppend> = prepared
        .iter()
        .enumerate()
        .map(|(i, update)| {
            let account = load_nullifier_tree(&mut account_data, &pubkey);
            let pending = account.get_metadata().queue_batches.pending_batch_index as usize;
            FoldAppend {
                proof: forester.append_proofs[i],
                old_root: update.instruction.old_root,
                new_root: update.new_root,
                hashchain_hash: account
                    .get_hash_chain(pending, update.instruction.zkp_batch_index as usize)
                    .unwrap(),
                start_index: old_next_index + i as u64 * ZKP_BATCH_SIZE,
            }
        })
        .collect();

    let fold = ProverClient::local()
        .prove_nullifier_fold(&NullifierFoldInputs {
            tree_height: HEIGHT,
            batch_size: ZKP_BATCH_SIZE as u32,
            appends,
        })
        .unwrap();
    let compressed = ProofCompressed::try_from(fold).unwrap();

    let event = {
        let mut account = load_nullifier_tree(&mut account_data, &pubkey);
        account
            .update_tree_from_address_queue_folded(
                &FoldedAddressAppendInputs {
                    old_root,
                    new_root: span_end,
                    proof: CommittedProof {
                        proof: CompressedProof {
                            a: compressed.a,
                            b: compressed.b,
                            c: compressed.c,
                        },
                        commitment: compressed.commitment.unwrap().commitment,
                        commitment_pok: compressed.commitment.unwrap().commitment_pok,
                    },
                },
                RUN,
            )
            .unwrap()
    };

    assert_eq!(event.num_update, RUN, "the event must report the whole run");
    assert_eq!(event.new_root, span_end);
    assert_eq!(event.old_next_index, old_next_index);

    let account = load_nullifier_tree(&mut account_data, &pubkey);
    let metadata = account.get_metadata();
    assert_eq!(
        metadata.next_index,
        old_next_index + u64::from(RUN) * ZKP_BATCH_SIZE,
        "the tree must advance by the whole span"
    );
    assert_eq!(
        account.get_root().unwrap(),
        span_end,
        "the account root must be the span's final root"
    );
    assert_eq!(
        metadata.queue_batches.batches[metadata.queue_batches.pending_batch_index as usize]
            .get_num_inserted_zkps(),
        u64::from(RUN),
        "every zkp batch in the run must be marked inserted"
    );
    assert_eq!(
        forester.reference.root(),
        span_end,
        "the reference tree the appends were built against must agree"
    );
}

/// Queue nullifiers without proving anything. Enough to finalize hash chains,
/// which is all the fold guards read before they reject.
fn queue_nullifiers(account_data: &mut [u8], pubkey: &Address, rng: &mut StdRng, count: usize) {
    for _ in 0..count {
        let nullifier = random_nullifier(rng);
        let mut account = load_nullifier_tree(account_data, pubkey);
        account.insert_nullifier_into_queue(&nullifier).unwrap();
    }
}

fn folded_inputs(old_root: [u8; 32], new_root: [u8; 32]) -> FoldedAddressAppendInputs {
    FoldedAddressAppendInputs {
        old_root,
        new_root,
        proof: CommittedProof {
            proof: CompressedProof {
                a: [0u8; 32],
                b: [0u8; 64],
                c: [0u8; 32],
            },
            commitment: [0u8; 32],
            commitment_pok: [0u8; 32],
        },
    }
}

/// Every fold guard names its own cause, so a forester can tell a run it sent
/// too early from a run the tree will never accept.
#[test]
fn nullifier_tree_fold_rejects_each_bad_run_by_cause() {
    let mut rng = StdRng::seed_from_u64(11);
    let pubkey = Address::new_unique();
    let mut account_data =
        vec![0u8; get_merkle_tree_account_size::<ROOT_HISTORY, NUM_ITERS, BLOOM, ZKP>()];
    init_nullifier_tree(&mut account_data, &pubkey);

    let root = load_nullifier_tree(&mut account_data, &pubkey)
        .get_root()
        .unwrap();

    // A run of one is a plain append, and no fold key is generated for it.
    let mut account = load_nullifier_tree(&mut account_data, &pubkey);
    assert_eq!(
        account
            .update_tree_from_address_queue_folded(&folded_inputs(root, [1u8; 32]), 1)
            .unwrap_err(),
        BatchedMerkleTreeError::FoldedRunTooShort
    );

    // Nothing is queued, so the run reaches past the finalized zkp batches.
    let mut account = load_nullifier_tree(&mut account_data, &pubkey);
    assert_eq!(
        account
            .update_tree_from_address_queue_folded(&folded_inputs(root, [1u8; 32]), 2)
            .unwrap_err(),
        BatchedMerkleTreeError::FoldedRunNotReady
    );

    queue_nullifiers(
        &mut account_data,
        &pubkey,
        &mut rng,
        3 * ZKP_BATCH_SIZE as usize,
    );

    // A span that does not start at the account tree root costs no pairing.
    let mut account = load_nullifier_tree(&mut account_data, &pubkey);
    assert_eq!(
        account
            .update_tree_from_address_queue_folded(&folded_inputs([9u8; 32], [1u8; 32]), 2)
            .unwrap_err(),
        BatchedMerkleTreeError::FoldedSpanRootMismatch
    );

    // The run length selects the verifying key, so an unlisted length is
    // rejected before any pairing runs.
    let mut account = load_nullifier_tree(&mut account_data, &pubkey);
    assert_eq!(
        account
            .update_tree_from_address_queue_folded(&folded_inputs(root, [1u8; 32]), 3)
            .unwrap_err(),
        BatchedMerkleTreeError::VerifierErrorError(
            zolana_batched_merkle_tree::verify::VerifierError::InvalidBatchSize
        )
    );

    // A supported run with a proof the verifier rejects must not advance the tree.
    let before = account_data.clone();
    let mut account = load_nullifier_tree(&mut account_data, &pubkey);
    assert!(matches!(
        account
            .update_tree_from_address_queue_folded(&folded_inputs(root, [1u8; 32]), 2)
            .unwrap_err(),
        BatchedMerkleTreeError::VerifierErrorError(_)
    ));
    assert_eq!(account_data, before, "a rejected fold must write nothing");
}
