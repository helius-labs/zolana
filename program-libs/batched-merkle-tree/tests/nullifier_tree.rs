#![cfg(feature = "test-only")]

use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use solana_address::Address;
use zolana_batched_merkle_tree::{
    constants::NULLIFIER_TREE_INIT_ROOT_40,
    errors::BatchedMerkleTreeError,
    initialize_address_tree::InitAddressTreeAccountsInstructionData,
    merkle_tree::{
        get_merkle_tree_account_size, BatchedMerkleTreeAccount, InstructionDataAddressAppendInputs,
    },
    verify::CompressedProof,
};
use zolana_client::{spawn_prover, BatchAddressAppendInputs, ProofCompressed, ProverClient};
use zolana_hasher::{hash_chain::create_hash_chain_from_array, Poseidon};
use zolana_merkle_tree::indexed::IndexedMerkleTree;
use zolana_merkle_tree_metadata::{merkle_tree::MerkleTreeMetadata, TreeType};

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
        MerkleTreeMetadata::default(),
        params.root_history_capacity,
        params.input_queue_batch_size,
        params.input_queue_zkp_batch_size,
        params.height,
        TreeType::AddressV2,
        Some(NULLIFIER_TREE_INIT_ROOT_40),
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
}

impl NullifierForester {
    fn new() -> Self {
        Self {
            reference: reference_nullifier_tree(),
            inserted_into_tree: 0,
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
            hash_chain_index: zkp_index as u16,
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
            let compressed = ProofCompressed::try_from(proof).unwrap();
            let instruction = InstructionDataAddressAppendInputs {
                new_root,
                old_root,
                hash_chain_index: zkp_index as u16,
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
    for tx in 0..10u64 {
        let nullifier = random_nullifier(&mut rng);
        account
            .insert_address_into_queue(&nullifier, &(tx + 1))
            .unwrap();
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
    start_slot: u64,
) -> Vec<PreparedUpdate> {
    for i in 0..count {
        let nullifier = random_nullifier(rng);
        let mut account = load_nullifier_tree(account_data, pubkey);
        account
            .insert_address_into_queue(&nullifier, &(start_slot + i as u64))
            .unwrap();
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
    let mut slot = 1u64;

    for _ in 0..num_batches {
        let mut prepared = fill_pending_batch_and_prepare(
            &mut account_data,
            &pubkey,
            &mut forester,
            &mut queued,
            &mut rng,
            batch_size,
            slot,
        );
        slot += batch_size as u64;
        assert_eq!(prepared.len(), zkp_batches_per_batch);

        let expected_new_roots: Vec<[u8; 32]> = prepared.iter().map(|prep| prep.new_root).collect();
        prepared.shuffle(&mut rng);

        let mut applied = 0usize;
        for prep in &prepared {
            let mut account = load_nullifier_tree(&mut account_data, &pubkey);
            let result = account
                .update_tree_from_address_queue(prep.instruction)
                .unwrap();
            match result {
                Some(event) => {
                    assert_eq!(event.first_zkp_batch_index as usize, applied);
                    applied += event.num_update as usize;
                    assert_eq!(
                        event.new_root,
                        *expected_new_roots.get(applied - 1).unwrap()
                    );
                }
                None => {}
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
        1,
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
        1,
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
        1,
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
        1,
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
    for i in 0..zkp_batch_size {
        let nullifier = random_nullifier(&mut rng);
        let mut account = load_nullifier_tree(&mut account_data, &pubkey);
        account
            .insert_address_into_queue(&nullifier, &(i as u64 + 1))
            .unwrap();
    }

    let dummy = InstructionDataAddressAppendInputs {
        new_root: [0u8; 32],
        old_root: [0u8; 32],
        hash_chain_index: 0,
        compressed_proof: CompressedProof {
            a: [0u8; 32],
            b: [0u8; 64],
            c: [0u8; 32],
        },
    };

    let mut out_of_range = dummy;
    out_of_range.hash_chain_index = ZKP as u16;
    let mut account = load_nullifier_tree(&mut account_data, &pubkey);
    assert_eq!(
        account
            .update_tree_from_address_queue(out_of_range)
            .unwrap_err(),
        BatchedMerkleTreeError::ChangelogIndexOutOfRange
    );

    let mut not_ready = dummy;
    not_ready.hash_chain_index = 1;
    let mut account = load_nullifier_tree(&mut account_data, &pubkey);
    assert_eq!(
        account
            .update_tree_from_address_queue(not_ready)
            .unwrap_err(),
        BatchedMerkleTreeError::HashChainNotReady
    );
}
