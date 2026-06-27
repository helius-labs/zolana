use light_program_profiler::{
    mollusk::{register_profiling_syscalls, take_profiling_entries},
    report::{CuBenchmark, ReadmeConfig},
};
use mollusk_svm::{program::loader_keys::LOADER_V3, result::Check, Mollusk};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

const ADDRESS_BLOOM_FILTER_CAPACITY: u64 = 4_603_072;
const ADDRESS_BLOOM_FILTER_NUM_HASHES: u64 = 10;

struct Shape {
    label: String,
    store_bytes: usize,
    num_hashes: u8,
    values: u16,
}

fn shapes() -> Vec<Shape> {
    let address_store = (ADDRESS_BLOOM_FILTER_CAPACITY / 8) as usize;
    let address_hashes = ADDRESS_BLOOM_FILTER_NUM_HASHES as u8;
    vec![
        Shape {
            label: "address 1 insertion".into(),
            store_bytes: address_store,
            num_hashes: address_hashes,
            values: 1,
        },
        Shape {
            label: "address 10 insertions".into(),
            store_bytes: address_store,
            num_hashes: address_hashes,
            values: 10,
        },
    ]
}

#[test]
#[ignore]
fn bench_cu_bloom_filter() {
    std::env::set_var(
        "SBF_OUT_DIR",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy"),
    );

    let program_id = Pubkey::new_unique();
    let mut mollusk = Mollusk::default();
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&program_id, "bloom_filter_bench", &LOADER_V3);

    let mut bench = CuBenchmark::new(ReadmeConfig {
        title: "Bloom Filter -- CU Benchmark".into(),
        description:
            "Compute unit profiling for light-bloom-filter insert and contains, using the state and address batched-merkle-tree defaults (num hashes and bloom filter capacity)."
                .into(),
        output_path: concat!(env!("CARGO_MANIFEST_DIR"), "/CU_BENCHMARK.md").into(),
        regenerate_command: Some("just bench-bloom-filter".into()),
        ..Default::default()
    });

    for shape in shapes() {
        let store_pubkey = Pubkey::new_unique();
        let store = Account {
            lamports: 1_000_000_000,
            data: vec![0u8; shape.store_bytes],
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        };

        let mut data = Vec::with_capacity(3);
        data.push(shape.num_hashes);
        data.extend_from_slice(&shape.values.to_le_bytes());

        let instruction = Instruction::new_with_bytes(
            program_id,
            &data,
            vec![AccountMeta::new(store_pubkey, false)],
        );

        mollusk.process_and_validate_instruction(
            &instruction,
            &[(store_pubkey, store)],
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

    bench.generate().expect("write CU_BENCHMARK.md");
}
