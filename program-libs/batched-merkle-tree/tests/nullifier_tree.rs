#![cfg(feature = "test-only")]

use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use rand::{rngs::StdRng, Rng, SeedableRng};
use solana_address::Address;
use zolana_batched_merkle_tree::{
    constants::NULLIFIER_TREE_INIT_ROOT_40,
    errors::BatchedMerkleTreeError,
    initialize_address_tree::InitAddressTreeAccountsInstructionData,
    merkle_tree::{
        assert_batch_adress_event, get_merkle_tree_account_size, BatchedMerkleTreeAccount,
        InstructionDataAddressAppendInputs,
    },
    verify::CompressedProof,
};
use zolana_client::{spawn_prover, BatchAddressAppendInputs, ProofCompressed, ProverClient};
use zolana_hasher::{hash_chain::create_hash_chain_from_array, Poseidon};
use zolana_merkle_tree::indexed::IndexedMerkleTree;
use zolana_merkle_tree_metadata::{
    events::MerkleTreeEvent, merkle_tree::MerkleTreeMetadata, TreeType,
};

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

fn has_ready_update(account_data: &mut [u8], pubkey: &Address) -> bool {
    let account = load_nullifier_tree(account_data, pubkey);
    let pending = account.get_metadata().queue_batches.pending_batch_index as usize;
    account.get_metadata().queue_batches.batches[pending]
        .get_first_ready_zkp_batch()
        .is_ok()
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

    fn perform_update(
        &mut self,
        account: &mut NullifierTree<'_>,
        queued: &[[u8; 32]],
    ) -> (MerkleTreeEvent, [u8; 32]) {
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
            compressed_proof: CompressedProof {
                a: compressed.a,
                b: compressed.b,
                c: compressed.c,
            },
        };
        let event = account
            .update_tree_from_address_queue(instruction_data)
            .unwrap();
        self.inserted_into_tree += zkp_batch_size;
        (event, new_root)
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
    let (_event, new_root) = forester.perform_update(&mut account, &queued);
    assert_eq!(account.get_root().unwrap(), new_root);
    assert_eq!(account.get_root().unwrap(), forester.reference.root());
}

#[test]
fn nullifier_tree_fills_root_history_with_randomized_inputs() {
    spawn_prover().unwrap();
    let mut rng = StdRng::seed_from_u64(0);
    let pubkey = Address::new_unique();
    let mut account_data =
        vec![0u8; get_merkle_tree_account_size::<ROOT_HISTORY, NUM_ITERS, BLOOM, ZKP>()];
    init_nullifier_tree(&mut account_data, &pubkey);

    let mut forester = NullifierForester::new();
    let mut queued: Vec<[u8; 32]> = Vec::new();
    let mut updates = 0usize;

    for tx in 0..NUM_TXNS {
        let slot = tx as u64 + 1;
        let nullifier = random_nullifier(&mut rng);
        {
            let mut account = load_nullifier_tree(&mut account_data, &pubkey);
            account
                .insert_address_into_queue(&nullifier, &slot)
                .unwrap();
            assert_eq!(
                account
                    .check_input_queue_non_inclusion(&nullifier)
                    .unwrap_err(),
                BatchedMerkleTreeError::NonInclusionCheckFailed
            );
        }
        queued.push(nullifier);

        while has_ready_update(&mut account_data, &pubkey) {
            let mut pre_data = account_data.clone();
            let pre_account = load_nullifier_tree(&mut pre_data, &pubkey);
            let pre_next_index = pre_account.get_metadata().next_index;
            let pre_sequence_number = pre_account.get_metadata().sequence_number;

            let (event, new_root) = {
                let mut account = load_nullifier_tree(&mut account_data, &pubkey);
                forester.perform_update(&mut account, &queued)
            };
            assert_batch_adress_event(event, new_root, &pre_account, pubkey);

            let account = load_nullifier_tree(&mut account_data, &pubkey);
            assert_eq!(account.get_root().unwrap(), new_root);
            assert_eq!(
                account.get_root().unwrap(),
                forester.reference.root(),
                "on-chain root diverged from the reference tree"
            );
            assert_eq!(
                account.get_metadata().next_index,
                pre_next_index + ZKP_BATCH_SIZE
            );
            assert_eq!(
                account.get_metadata().sequence_number,
                pre_sequence_number + 1
            );
            updates += 1;
        }
    }

    assert_eq!(updates, NUM_TXNS / ZKP_BATCH_SIZE as usize);
    assert!(updates >= ROOT_HISTORY);
    let account = load_nullifier_tree(&mut account_data, &pubkey);
    assert_eq!(account.root_history().len(), ROOT_HISTORY);
    assert_eq!(account.get_root().unwrap(), forester.reference.root());
}
