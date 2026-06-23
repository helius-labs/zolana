use light_program_profiler::mollusk::{register_profiling_syscalls, take_profiling_entries};
use light_program_profiler::report::{CuBenchmark, ReadmeConfig};
use mollusk_svm::{program::loader_keys::LOADER_V3, result::Check, Mollusk};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_tree::{InitAddressTreeAccountsInstructionData, TreeAccount};

const HEIGHT: u8 = 26;
const DISCRIMINATOR: u8 = 7;

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
            "Compute unit profiling for zolana-tree: account init, zero-copy deserialization, UTXO sparse-merkle-tree append, and end-to-end nullifier insert (bloom + hash chain + non-inclusion)."
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

    bench.generate().expect("write CU_BENCHMARK.md");
}
