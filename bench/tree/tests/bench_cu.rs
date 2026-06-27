use ark_bn254::Fr;
use ark_ff::PrimeField;
use borsh::BorshSerialize;
use light_program_profiler::mollusk::{register_profiling_syscalls, take_profiling_entries};
use light_program_profiler::report::{CuBenchmark, ReadmeConfig};
use mollusk_svm::{program::loader_keys::LOADER_V3, result::Check, Mollusk};
use num_bigint::BigUint;
use rand::{rngs::StdRng, Rng, SeedableRng};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_batched_merkle_tree::{
    constants::NULLIFIER_TREE_INIT_ROOT_40,
    merkle_tree::{
        get_merkle_tree_account_size, BatchedMerkleTreeAccount, InstructionDataAddressAppendInputs,
    },
    verify::CompressedProof,
    zero_copy::{CachedTreeUpdate, TreeAccountLayout},
};
use zolana_client::{spawn_prover, BatchAddressAppendInputs, ProofCompressed, ProverClient};
use zolana_hasher::{hash_chain::create_hash_chain_from_array, Poseidon};
use zolana_merkle_tree::indexed::IndexedMerkleTree;
use zolana_merkle_tree_metadata::{merkle_tree::MerkleTreeMetadata, TreeType};
use zolana_tree::{InitAddressTreeAccountsInstructionData, TreeAccount};

const HEIGHT: u8 = 26;
const DISCRIMINATOR: u8 = 7;

const OP_BATCH_ADDRESS_UPDATE: u8 = 5;

const ADDRESS_RH: usize = 120;
const ADDRESS_NUM_ITERS: usize = 10;
const ADDRESS_BLOOM: usize = 575384;
const ADDRESS_ZKP: usize = 120;
const ADDRESS_HEIGHT: u32 = 40;
const ADDRESS_ZKP_BATCH_SIZE: u64 = 10;
const ADDRESS_BATCH_SIZE: u64 = 1200;
const ADDRESS_ROOT_HISTORY_CAPACITY: u32 = 120;

type AddressTree<'a> =
    BatchedMerkleTreeAccount<'a, ADDRESS_RH, ADDRESS_NUM_ITERS, ADDRESS_BLOOM, ADDRESS_ZKP>;

struct AddressUpdateFixture {
    account_data: Vec<u8>,
    instruction_data: Vec<u8>,
    base_next_index: u64,
}

fn path_to_biguint(path: Vec<[u8; 32]>) -> Vec<BigUint> {
    path.into_iter()
        .map(|node| BigUint::from_bytes_be(&node))
        .collect()
}

fn reference_address_tree() -> IndexedMerkleTree<Poseidon, usize> {
    let modulus: BigUint = Fr::MODULUS.into();
    IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(
        ADDRESS_HEIGHT as usize,
        0,
        modulus - 1u32,
    )
    .unwrap()
}

fn append_reference_batch(
    reference: &mut IndexedMerkleTree<Poseidon, usize>,
    batch_values: &[[u8; 32]],
) -> [u8; 32] {
    for value_bytes in batch_values {
        reference
            .append(&BigUint::from_bytes_be(value_bytes))
            .unwrap();
    }
    reference.root()
}

fn build_index0_inputs(
    reference: &mut IndexedMerkleTree<Poseidon, usize>,
    next_index: u64,
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
        let non_inclusion = reference.get_non_inclusion_proof(&value).unwrap();
        low_element_values.push(BigUint::from_bytes_be(
            &non_inclusion.leaf_lower_range_value,
        ));
        low_element_indices.push(BigUint::from(non_inclusion.leaf_index as u64));
        low_element_next_values.push(BigUint::from_bytes_be(
            &non_inclusion.leaf_higher_range_value,
        ));
        low_element_proofs.push(path_to_biguint(non_inclusion.merkle_proof));
        new_element_values.push(value.clone());

        reference.append(&value).unwrap();
        let new_index = next_index as usize + offset;
        let new_proof = reference.get_proof_of_leaf(new_index, true).unwrap();
        new_element_proofs.push(path_to_biguint(new_proof));
    }

    let new_root = reference.root();
    let mut start_index_bytes = [0u8; 32];
    start_index_bytes[24..].copy_from_slice(&next_index.to_be_bytes());
    let public_input_hash =
        create_hash_chain_from_array([old_root, new_root, leaves_hash_chain, start_index_bytes])
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
            tree_height: ADDRESS_HEIGHT,
            batch_size: batch_values.len() as u32,
        },
        new_root,
    )
}

fn build_address_update_fixture(num_batches: usize, seed: u64) -> AddressUpdateFixture {
    spawn_prover().expect("prover server");
    let pubkey = Address::new_unique();
    let zkp = ADDRESS_ZKP_BATCH_SIZE as usize;
    let total = num_batches * zkp;

    let mut account_data = vec![
        0u8;
        get_merkle_tree_account_size::<
            ADDRESS_RH,
            ADDRESS_NUM_ITERS,
            ADDRESS_BLOOM,
            ADDRESS_ZKP,
        >()
    ];
    AddressTree::init(
        &mut account_data,
        &pubkey,
        MerkleTreeMetadata::default(),
        ADDRESS_ROOT_HISTORY_CAPACITY,
        ADDRESS_BATCH_SIZE,
        ADDRESS_ZKP_BATCH_SIZE,
        ADDRESS_HEIGHT,
        TreeType::AddressV2,
        Some(NULLIFIER_TREE_INIT_ROOT_40),
    )
    .unwrap();

    let mut rng = StdRng::seed_from_u64(seed);
    let mut queued: Vec<[u8; 32]> = Vec::with_capacity(total);
    {
        let mut account = AddressTree::address_from_bytes(&mut account_data, &pubkey).unwrap();
        for i in 0..total {
            let mut value: [u8; 32] = rng.gen();
            value[0] = 0;
            account
                .insert_address_into_queue(&value, &(i as u64 + 1))
                .unwrap();
            queued.push(value);
        }
    }

    let base_next_index = AddressTree::address_from_bytes(&mut account_data, &pubkey)
        .unwrap()
        .get_metadata()
        .next_index;

    let mut reference = reference_address_tree();
    assert_eq!(
        reference.root(),
        AddressTree::address_from_bytes(&mut account_data, &pubkey)
            .unwrap()
            .get_root()
            .unwrap(),
        "reference root must match the live tree before building updates"
    );

    let mut cached_updates: Vec<CachedTreeUpdate> = Vec::with_capacity(num_batches);
    let mut index0_ix: Option<InstructionDataAddressAppendInputs> = None;
    for i in 0..num_batches {
        let next_index = base_next_index + (i * zkp) as u64;
        let leaves_hash_chain = AddressTree::address_from_bytes(&mut account_data, &pubkey)
            .unwrap()
            .get_hash_chain(0, i)
            .unwrap();
        let old_root = reference.root();
        let batch_values = queued.get(i * zkp..(i + 1) * zkp).unwrap();
        let new_root = if i == 0 {
            let (inputs, new_root) = build_index0_inputs(
                &mut reference,
                next_index,
                leaves_hash_chain,
                old_root,
                batch_values,
            );
            let proof = ProverClient::local()
                .prove_batch_address_append(&inputs)
                .unwrap();
            let compressed = ProofCompressed::try_from(proof).unwrap();
            index0_ix = Some(InstructionDataAddressAppendInputs {
                new_root,
                old_root,
                zkp_batch_index: 0,
                compressed_proof: CompressedProof {
                    a: compressed.a,
                    b: compressed.b,
                    c: compressed.c,
                },
            });
            new_root
        } else {
            append_reference_batch(&mut reference, batch_values)
        };
        cached_updates.push(CachedTreeUpdate {
            old_root,
            new_root,
            occupied: 1,
        });
    }

    {
        let layout: &mut TreeAccountLayout<
            ADDRESS_RH,
            ADDRESS_NUM_ITERS,
            ADDRESS_BLOOM,
            ADDRESS_ZKP,
        > = wincode::deserialize_mut(&mut account_data).unwrap();
        let update_vec = layout.cached_tree_updates.get_mut(0).unwrap();
        for i in 1..num_batches {
            let cached_update = *cached_updates.get(i).unwrap();
            *update_vec.data.get_mut(i).unwrap() = cached_update;
        }
    }

    let mut instruction_data = vec![OP_BATCH_ADDRESS_UPDATE];
    index0_ix.unwrap().serialize(&mut instruction_data).unwrap();

    AddressUpdateFixture {
        account_data,
        instruction_data,
        base_next_index,
    }
}

fn assert_cascade_applied(account_data: &[u8], expected_next_index: u64) {
    let mut data = account_data.to_vec();
    let account = AddressTree::address_from_bytes(&mut data, &Address::new_unique()).unwrap();
    assert_eq!(
        account.get_metadata().next_index,
        expected_next_index,
        "cascade did not advance next_index as expected"
    );
}

struct Shape {
    label: String,
    opcode: u8,
    n: u16,
    inited: bool,
}

fn shapes() -> Vec<Shape> {
    vec![
        Shape {
            label: "tree init".into(),
            opcode: 0,
            n: 0,
            inited: false,
        },
        Shape {
            label: "deserialize".into(),
            opcode: 1,
            n: 0,
            inited: true,
        },
        Shape {
            label: "utxo append x1".into(),
            opcode: 2,
            n: 1,
            inited: true,
        },
        Shape {
            label: "utxo append x10".into(),
            opcode: 2,
            n: 10,
            inited: true,
        },
        Shape {
            label: "utxo append_batch x10".into(),
            opcode: 4,
            n: 10,
            inited: true,
        },
        Shape {
            label: "nullifier insert x1".into(),
            opcode: 3,
            n: 1,
            inited: true,
        },
        Shape {
            label: "nullifier insert x10".into(),
            opcode: 3,
            n: 10,
            inited: true,
        },
    ]
}

fn inited_tree_bytes(tree_pubkey: Pubkey) -> Vec<u8> {
    let params = InitAddressTreeAccountsInstructionData::default();
    let mut data = vec![0u8; TreeAccount::account_size()];
    {
        let _ = TreeAccount::init(
            &mut data,
            DISCRIMINATOR,
            HEIGHT,
            [1u8; 32],
            tree_pubkey.to_bytes(),
            params,
        )
        .unwrap();
    }
    data
}

#[test]
#[ignore]
fn bench_cu_tree() {
    std::env::set_var(
        "SBF_OUT_DIR",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy"),
    );

    let program_id = Pubkey::new_unique();
    let mut mollusk = Mollusk::default();
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&program_id, "tree_bench", &LOADER_V3);

    let mut bench = CuBenchmark::new(ReadmeConfig {
        title: "Tree -- CU Benchmark".into(),
        description:
            "Compute unit profiling for zolana-tree: account init, zero-copy deserialization, UTXO sparse-merkle-tree append, end-to-end nullifier insert (bloom + hash chain + non-inclusion), and the worst-case address-tree batch update that finalizes 120 cached tree updates in one transaction.\n\nSee `CU_BENCHMARK_NOTES.md` for analysis notes (e.g. why nullifier insert x10 is not 10x x1, and the proof-verify vs cascade-apply split of the batch update)."
                .into(),
        output_path: concat!(env!("CARGO_MANIFEST_DIR"), "/CU_BENCHMARK.md").into(),
        regenerate_command: Some("just bench-tree".into()),
        ..Default::default()
    });

    for shape in shapes() {
        let tree_pubkey = Pubkey::new_unique();
        let data = if shape.inited {
            inited_tree_bytes(tree_pubkey)
        } else {
            vec![0u8; TreeAccount::account_size()]
        };
        let account = Account {
            lamports: 1_000_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        };

        let mut ix_data = Vec::with_capacity(3);
        ix_data.push(shape.opcode);
        ix_data.extend_from_slice(&shape.n.to_le_bytes());

        let instruction = Instruction::new_with_bytes(
            program_id,
            &ix_data,
            vec![AccountMeta::new(tree_pubkey, false)],
        );

        mollusk.process_and_validate_instruction(
            &instruction,
            &[(tree_pubkey, account)],
            &[Check::success()],
        );

        let entries = take_profiling_entries();
        assert!(
            !entries.is_empty(),
            "no profiling entries for shape '{}'; was the program built with --features bench?",
            shape.label
        );
        bench.add_from_entries(&shape.label, entries);
    }

    let num_batches = 120usize;
    let fixture = build_address_update_fixture(num_batches, 0);
    let tree_pubkey = Pubkey::new_unique();
    let account = Account {
        lamports: 1_000_000_000,
        data: fixture.account_data.clone(),
        owner: program_id,
        executable: false,
        rent_epoch: 0,
    };
    let instruction = Instruction::new_with_bytes(
        program_id,
        &fixture.instruction_data,
        vec![AccountMeta::new(tree_pubkey, false)],
    );
    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[(tree_pubkey, account)],
        &[Check::success()],
    );
    let resulting = result
        .get_account(&tree_pubkey)
        .expect("resulting tree account");
    assert_cascade_applied(
        &resulting.data,
        fixture.base_next_index + (num_batches as u64) * ADDRESS_ZKP_BATCH_SIZE,
    );
    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for address tree batch update; was the program built with --features bench?"
    );
    bench.add_from_entries("address tree batch update x120", entries);

    bench.generate().expect("write CU_BENCHMARK.md");
}

#[test]
#[ignore]
fn address_batch_update_executes_under_mollusk() {
    std::env::set_var(
        "SBF_OUT_DIR",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy"),
    );

    let program_id = Pubkey::new_unique();
    let mut mollusk = Mollusk::default();
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&program_id, "tree_bench", &LOADER_V3);

    let num_batches = 1usize;
    let fixture = build_address_update_fixture(num_batches, 0);

    let tree_pubkey = Pubkey::new_unique();
    let account = Account {
        lamports: 1_000_000_000,
        data: fixture.account_data.clone(),
        owner: program_id,
        executable: false,
        rent_epoch: 0,
    };

    let instruction = Instruction::new_with_bytes(
        program_id,
        &fixture.instruction_data,
        vec![AccountMeta::new(tree_pubkey, false)],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[(tree_pubkey, account)],
        &[Check::success()],
    );

    let resulting = result
        .get_account(&tree_pubkey)
        .expect("resulting tree account");
    assert_cascade_applied(
        &resulting.data,
        fixture.base_next_index + (num_batches as u64) * ADDRESS_ZKP_BATCH_SIZE,
    );
}
