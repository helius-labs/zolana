#![cfg(not(feature = "localnet"))]

use light_program_profiler::{
    mollusk::{register_profiling_syscalls, take_profiling_entries},
    report::{CuBenchmark, ReadmeConfig},
};
use mollusk_svm::{program::loader_keys::LOADER_V3, result::Check, Mollusk};
use num_bigint::BigUint;
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    prover::field::be, ProofCompressed, ProverClient, PublicInputs, PublicTransfers,
    TransferOutput, TransferP256Inputs, STATE_TREE_HEIGHT,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_hasher::Poseidon;
use zolana_interface::{
    instruction::{
        instruction_data::{
            merge_transact::MERGE_SUPPORTED_INPUT_COUNTS,
            transact::{CircuitId, InterfaceTransfer, ResolvedInterfaceTransfer},
        },
        tag, Deposit, RingTransact, Transact, TransactInterfaceTransferAccounts, TransactIxData,
        TransactSolTransferAccounts,
    },
    pda,
    state::{
        discriminator::RING_CONFIG, nullifier_tree_params, tree_account_size,
        tree_working_capital_lamports, RingConfig,
    },
    verifying_keys::RingP256ProofData,
    NULLIFIER_PDA_SIZE, N_PUBLIC_SLOTS, PROGRAM_ID_PUBKEY, SHIELDED_POOL_PROGRAM_ID,
    SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{
    hash::{owner_hash, sha256},
    pubkey::PublicKey,
    NullifierKey, ShieldedKeypair, SigningKey,
};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{test_blinding, ZolanaProgramTest, RING_TEST_PROGRAM_ID};
use zolana_transaction::{
    instructions::transact::PrivateTxHash, Data, SyncWalletAuthority, Utxo, SOL_MINT,
};

use shielded_pool_tests::support::{
    fixtures::Pool,
    merge::RealMergeProof,
    mollusk,
    transact::{tree_roots, write_ring_config_account},
};
use zolana_test_utils::{
    nullifier_pda::nullifier_pda_addresses,
    prover::spawn_workspace_prover,
    transact::{
        account_tagged_owner_addresses, build_spl_withdrawal, build_transfer_prover_inputs,
        dummy_input, dummy_transfer_output, eddsa_input_utxo, external_data_hash,
        external_data_hash_with_addresses, fe, inline_outputs, new_transact_ix_data,
        nullifier_tree, output_owner_pk_hashes, pack_transact_proof, prove_and_verify_transfer,
        public_sol_field, real_output, set_output_owner_tags, sol_public_slots, spend_input,
        transfer_output, SpendInputArgs, TransferProverInputsArgs,
    },
};

const PLAIN_PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/deploy/shielded_pool_program_plain.so"
);
const PROFILING_SBF_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy");
// SPL Token program cloned from mainnet via `solana program dump` (see the
// `bench-shielded-pool` justfile recipe), loaded into mollusk for the SPL
// deposit's token-transfer CPI.
const SPL_TOKEN_PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/deploy/spl_token.so"
);

fn to_mollusk_pubkey(key: &Pubkey) -> Pubkey {
    Pubkey::new_from_array(key.to_bytes())
}

fn to_mollusk_instruction(ix: &Instruction) -> Instruction {
    Instruction {
        program_id: to_mollusk_pubkey(&ix.program_id),
        accounts: ix
            .accounts
            .iter()
            .map(|m| AccountMeta {
                pubkey: to_mollusk_pubkey(&m.pubkey),
                is_signer: m.is_signer,
                is_writable: m.is_writable,
            })
            .collect(),
        data: ix.data.clone(),
    }
}

fn snapshot_account(pt: &ZolanaProgramTest, key: &Pubkey) -> (Pubkey, Account) {
    let mollusk_key = to_mollusk_pubkey(key);
    let account = match pt.svm.get_account(key) {
        Some(acc) => Account {
            lamports: acc.lamports,
            data: acc.data,
            owner: Pubkey::new_from_array(acc.owner.to_bytes()),
            executable: acc.executable,
            rent_epoch: acc.rent_epoch,
        },
        None => Account {
            lamports: 1_000_000_000,
            data: Vec::new(),
            owner: Pubkey::new_from_array([0u8; 32]),
            executable: false,
            rent_epoch: 0,
        },
    };
    (mollusk_key, account)
}

fn bench_setup() -> (ZolanaProgramTest, Keypair, Pubkey) {
    std::env::set_var("SHIELDED_POOL_PROGRAM_PATH", PLAIN_PROGRAM_PATH);
    let Pool {
        rpc,
        authority,
        tree,
    } = Pool::initialized();
    (rpc, authority, tree)
}

fn deposit_sol_accounts(
    pt: &ZolanaProgramTest,
    ix: &Instruction,
    program_id: &Pubkey,
) -> Vec<(Pubkey, Account)> {
    let mut accounts = Vec::with_capacity(ix.accounts.len());
    for meta in &ix.accounts {
        if meta.pubkey == PROGRAM_ID_PUBKEY {
            accounts.push(mollusk_program_account(program_id));
        } else if meta.pubkey == Pubkey::default() {
            accounts.push(mollusk_svm::program::keyed_account_for_system_program());
        } else {
            accounts.push(snapshot_account(pt, &meta.pubkey));
        }
    }
    accounts
}

fn deposit_spl_accounts(
    pt: &ZolanaProgramTest,
    ix: &Instruction,
    program_id: &Pubkey,
    token_program_account: &(Pubkey, Account),
) -> Vec<(Pubkey, Account)> {
    let token_program = Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID);
    let mut accounts = Vec::with_capacity(ix.accounts.len());
    for meta in &ix.accounts {
        if meta.pubkey == PROGRAM_ID_PUBKEY {
            accounts.push(mollusk_program_account(program_id));
        } else if meta.pubkey == token_program {
            accounts.push(token_program_account.clone());
        } else {
            accounts.push(snapshot_account(pt, &meta.pubkey));
        }
    }
    accounts
}

fn mollusk_program_account(program_id: &Pubkey) -> (Pubkey, Account) {
    let account = mollusk_svm::program::create_program_account_loader_v3(program_id);
    (*program_id, account)
}

#[test]
#[ignore]
fn bench_cu_deposit() {
    std::env::set_var("SBF_OUT_DIR", PROFILING_SBF_DIR);
    std::env::set_var("SHIELDED_POOL_PROGRAM_PATH", PLAIN_PROGRAM_PATH);

    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let token_program_id = Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID);

    let spl_token_elf = std::fs::read(SPL_TOKEN_PROGRAM_PATH).unwrap_or_else(|_| {
        panic!(
            "missing {SPL_TOKEN_PROGRAM_PATH}; run `just bench-shielded-pool` (it clones the \
             SPL Token program from mainnet via `solana program dump`)"
        )
    });

    let mut mollusk = Mollusk::default();
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&program_id, "shielded_pool_program");
    mollusk.add_program_with_loader_and_elf(&token_program_id, &LOADER_V3, &spl_token_elf);

    let token_program_account = (
        token_program_id,
        mollusk_svm::program::create_program_account_loader_v3(&token_program_id),
    );

    let mut bench = CuBenchmark::new(ReadmeConfig {
        title: "Shielded Pool -- CU Benchmark".into(),
        description:
            "Compute unit profiling for feasible shielded-pool instruction families, replayed \
             under mollusk from litesvm-built account state: protocol creation, tree pause, \
             proof-free SOL/SPL shields, all eleven Groth16-proven EdDSA transact shapes \
             (including the 1x8 split shape and the 36x2 consolidation shape, the widest that \
             fits a transaction v1), that same 36x2 consolidation shape on both policy-ring \
             `ring_transact` rails (EdDSA, and P256 -- whose BSB22 commitment adds a Pedersen \
             proof-of-knowledge pairing to verification), both supported `merge_transact` \
             shapes (8x1 and 36x1), and SOL/SPL withdrawals. This target \
             is a pure benchmark: no \
             CI workflow runs the profiling build, so no CU ceilings are enforced here -- a \
             ceiling that never runs would be unfalsifiable. Regression ceilings live in the \
             fast cross_cutting_cu_budget suite, which pins every proofless instruction family \
             per operation."
                .into(),
        output_path: concat!(env!("CARGO_MANIFEST_DIR"), "/CU_BENCHMARK.md").into(),
        regenerate_command: Some("just bench-shielded-pool".into()),
        ..Default::default()
    });

    bench_fixture(
        &mollusk,
        mollusk::protocol_config_fixture(),
        "create protocol config",
        &mut bench,
    );
    bench_fixture(
        &mollusk,
        mollusk::pause_tree_fixture(),
        "pause tree",
        &mut bench,
    );
    bench_deposit_sol(&mollusk, &program_id, &mut bench);
    bench_deposit_sol_batch(&mollusk, &program_id, &mut bench);
    bench_deposit_spl(&mollusk, &program_id, &token_program_account, &mut bench);
    for (n_inputs, n_outputs) in [
        (1, 1),
        (1, 2),
        (2, 2),
        (2, 3),
        (3, 3),
        (4, 3),
        (4, 4),
        (5, 3),
        (5, 4),
        (1, 8),
        (36, 2),
    ] {
        bench_transfer_shape(&mollusk, &program_id, n_inputs, n_outputs, &mut bench);
    }
    for rail in [RingRail::Eddsa, RingRail::P256] {
        bench_ring_transfer_shape(&mollusk, &program_id, rail, 36, 2, &mut bench);
    }
    for input_count in MERGE_SUPPORTED_INPUT_COUNTS {
        bench_merge_shape(&mollusk, &program_id, input_count, &mut bench);
    }
    bench_withdrawal_sol(&mollusk, &program_id, &mut bench);
    bench_withdrawal_spl(&mollusk, &program_id, &token_program_account, &mut bench);

    bench.generate().expect("write CU_BENCHMARK.md");
}

fn bench_fixture(
    mollusk: &Mollusk,
    (_fixture_mollusk, instruction, accounts): (
        mollusk_svm::Mollusk,
        Instruction,
        Vec<(Pubkey, Account)>,
    ),
    name: &str,
    bench: &mut CuBenchmark,
) {
    let instruction = to_mollusk_instruction(&instruction);
    let accounts: Vec<(Pubkey, Account)> = accounts
        .into_iter()
        .map(|(key, account)| {
            (
                to_mollusk_pubkey(&key),
                Account {
                    lamports: account.lamports,
                    data: account.data,
                    owner: to_mollusk_pubkey(&account.owner),
                    executable: account.executable,
                    rent_epoch: account.rent_epoch,
                },
            )
        })
        .collect();
    mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);
    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for '{name}'");
    bench.add_from_entries(name, entries);
}

// Snapshot every account a `transact` instruction references, mapping the
// program account (self-CPI `emit_event`), the system program, and the SPL Token
// program to their mollusk fixtures while snapshotting all PDAs/data accounts
// from the litesvm pre-instruction state the proof is bound to. Nullifier
// nullifier PDAs do not exist before the spend: they are materialized as empty,
// System-owned, zero-lamport accounts the program creates and funds from the
// input tree's working capital.
fn transact_accounts(
    pt: &ZolanaProgramTest,
    ix: &Instruction,
    program_id: &Pubkey,
    token_program_account: Option<&(Pubkey, Account)>,
) -> Vec<(Pubkey, Account)> {
    let data = TransactIxData::deserialize(ix.data.get(1..).expect("tagged transact data"))
        .expect("transact instruction data");
    let input_tree = ix.accounts.get(1).expect("input tree meta").pubkey;
    let nullifiers: Vec<[u8; 32]> = data
        .tail
        .inputs
        .iter()
        .map(|input| input.nullifier_hash)
        .collect();
    nullifier_spend_accounts(
        pt,
        ix,
        program_id,
        input_tree,
        &nullifiers,
        token_program_account,
    )
}

// The account mapping shared by every nullifier-spending instruction, `transact`
// and `merge_transact` alike. Both publish a nullifier per input and create one
// PDA each, so both need the same treatment; only where the nullifier list comes
// from differs, and the caller supplies it.
fn nullifier_spend_accounts(
    pt: &ZolanaProgramTest,
    ix: &Instruction,
    program_id: &Pubkey,
    input_tree: Pubkey,
    nullifiers: &[[u8; 32]],
    token_program_account: Option<&(Pubkey, Account)>,
) -> Vec<(Pubkey, Account)> {
    let token_program = Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID);
    let nullifier_pdas = nullifier_pda_addresses(&input_tree, nullifiers);
    let tree_rent = pt
        .svm
        .minimum_balance_for_rent_exemption(tree_account_size());
    let nullifier_pda_rent = pt
        .svm
        .minimum_balance_for_rent_exemption(NULLIFIER_PDA_SIZE);
    let working_capital = tree_working_capital_lamports(
        nullifier_tree_params().input_queue_batch_size,
        nullifier_pda_rent,
    )
    .expect("tree working capital fits in u64");
    let mut accounts = Vec::with_capacity(ix.accounts.len());
    for meta in &ix.accounts {
        if meta.pubkey == PROGRAM_ID_PUBKEY {
            accounts.push(mollusk_program_account(program_id));
        } else if meta.pubkey == Pubkey::default() {
            accounts.push(mollusk_svm::program::keyed_account_for_system_program());
        } else if nullifier_pdas.contains(&meta.pubkey) {
            accounts.push((
                to_mollusk_pubkey(&meta.pubkey),
                Account {
                    lamports: 0,
                    data: Vec::new(),
                    owner: Pubkey::new_from_array([0u8; 32]),
                    executable: false,
                    rent_epoch: 0,
                },
            ));
        } else if meta.pubkey == input_tree {
            let tree = snapshot_account(pt, &meta.pubkey);
            assert!(
                tree.1.lamports >= tree_rent + working_capital,
                "input tree fixture must hold nullifier PDA working capital"
            );
            accounts.push(tree);
        } else if meta.pubkey == token_program {
            accounts.push(
                token_program_account
                    .cloned()
                    .expect("token program account fixture for SPL settlement"),
            );
        } else {
            accounts.push(snapshot_account(pt, &meta.pubkey));
        }
    }
    accounts
}

fn bench_deposit_sol(mollusk: &Mollusk, program_id: &Pubkey, bench: &mut CuBenchmark) {
    let (mut pt, _authority, tree) = bench_setup();
    let depositor = Keypair::new();
    pt.airdrop(&depositor.pubkey(), 1_000_000_000)
        .expect("airdrop depositor");

    let recipient = ShieldedKeypair::new_p256()
        .expect("recipient keypair")
        .shielded_address()
        .expect("shielded address");
    let seed = test_blinding(3);
    let data = ZolanaProgramTest::wallet_sol_shield_data(1_000_000, &recipient, &seed, 0)
        .expect("wallet deposit data");

    let ix = Deposit {
        tree,
        depositor: depositor.pubkey(),
        deposits: vec![data],
    }
    .instruction()
    .expect("valid SOL deposit");

    let accounts = deposit_sol_accounts(&pt, &ix, program_id);
    let mollusk_ix = to_mollusk_instruction(&ix);

    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for 'deposit sol'; build the profiling .so with --features profile-program"
    );
    bench.add_from_entries("deposit sol", entries);
}

/// Three SOL outputs in one instruction. Compare against `deposit sol` (one
/// output) for the marginal cost of a batch entry: the batch appends once and
/// settles once regardless of entry count.
fn bench_deposit_sol_batch(mollusk: &Mollusk, program_id: &Pubkey, bench: &mut CuBenchmark) {
    let (mut pt, _authority, tree) = bench_setup();
    let depositor = Keypair::new();
    pt.airdrop(&depositor.pubkey(), 1_000_000_000)
        .expect("airdrop depositor");

    let recipient = ShieldedKeypair::new_p256()
        .expect("recipient keypair")
        .shielded_address()
        .expect("shielded address");
    let seed = test_blinding(3);
    let deposits = (0..3)
        .map(|position| {
            ZolanaProgramTest::wallet_sol_shield_data(1_000_000, &recipient, &seed, position)
                .expect("wallet deposit data")
        })
        .collect();

    let ix = Deposit {
        tree,
        depositor: depositor.pubkey(),
        deposits,
    }
    .instruction()
    .expect("valid SOL deposit batch");

    let accounts = deposit_sol_accounts(&pt, &ix, program_id);
    let mollusk_ix = to_mollusk_instruction(&ix);

    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for the batch bench; build the profiling .so with --features profile-program"
    );
    bench.add_from_entries("deposit sol batch 3", entries);
}

fn bench_deposit_spl(
    mollusk: &Mollusk,
    program_id: &Pubkey,
    token_program_account: &(Pubkey, Account),
    bench: &mut CuBenchmark,
) {
    let (mut pt, authority, tree) = bench_setup();

    let mint = pt.create_mint().expect("create_mint");
    pt.ensure_asset_counter(&authority)
        .expect("create_asset_counter");
    pt.create_spl_interface(&authority, &mint)
        .expect("create_spl_interface");

    let depositor = Keypair::new();
    pt.airdrop(&depositor.pubkey(), 1_000_000_000)
        .expect("airdrop depositor");
    let user_token = pt
        .create_token_account(&mint, &depositor.pubkey())
        .expect("user token account");
    pt.mint_to(&mint, &user_token, 1_000_000).expect("mint_to");

    let recipient = ShieldedKeypair::new_p256()
        .expect("recipient keypair")
        .shielded_address()
        .expect("shielded address");
    let seed = test_blinding(7);
    let data =
        ZolanaProgramTest::wallet_spl_shield_data(1_000, &recipient, &seed, 0, &mint, &user_token)
            .expect("wallet deposit data");

    let ix = Deposit {
        tree,
        depositor: depositor.pubkey(),
        deposits: vec![data],
    }
    .instruction()
    .expect("valid SPL deposit");

    let accounts = deposit_spl_accounts(&pt, &ix, program_id, token_program_account);
    let mollusk_ix = to_mollusk_instruction(&ix);

    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for 'deposit spl'; build the profiling .so with --features profile-program"
    );
    bench.add_from_entries("deposit spl", entries);
}

// Every confidential EdDSA circuit shape, spending nothing (all-dummy inputs)
// and settling nothing so the measurement isolates shape-dependent proof
// verification, public-input hashing, and tree application. PR164 constrains
// dummies (AssertDummyTags): every dummy tag must name a transaction
// participant, so output 0 is a real zero-amount output owned by the payer and
// every dummy slot carries the payer's tag.
fn bench_transfer_shape(
    mollusk: &Mollusk,
    program_id: &Pubkey,
    n_inputs: usize,
    n_outputs: usize,
    bench: &mut CuBenchmark,
) {
    let (pt, _authority, tree) = bench_setup();
    spawn_workspace_prover();

    let payer = pt.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let roots = tree_roots(&pt, &tree, 0);
    let (utxo_root, nullifier_root) = roots;
    let zero = [0u8; 32];

    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    let owner_hash = hash_bytes(&payer_bytes).expect("owner hash");
    let mut inputs = Vec::with_capacity(n_inputs);
    let mut nullifiers = Vec::with_capacity(n_inputs);
    for index in 0..n_inputs {
        let (input, nullifier) =
            dummy_input(&[index as u8 + 31; 31], &nf_tree, roots).expect("dummy input");
        inputs.push(input);
        nullifiers.push(nullifier);
    }

    let nullifier_key = NullifierKey::from_secret([21u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let owner = PublicKey::from_ed25519(&payer_bytes);
    let real = real_output(owner, nullifier_pk, SOL_MINT, 0, [23u8; 31]);
    let real_hash = real.hash().expect("real output hash");
    let mut outputs = vec![transfer_output(&real).expect("real transfer output")];
    let mut output_hashes = vec![real_hash];
    for index in 1..n_outputs {
        let (output, hash) = dummy_transfer_output(&[index as u8; 31]).expect("dummy output");
        outputs.push(output);
        output_hashes.push(hash);
    }

    // Real outputs tag by owner; dummy slots reuse the payer's tag (both rules
    // on `set_output_owner_tags`).
    let owner_view_tag = owner.confidential_view_tag().expect("owner view tag");
    let mut view_tags = vec![owner_view_tag];
    view_tags.extend(std::iter::repeat_n(payer_bytes, n_outputs - 1));
    let mut transact_ix_data = new_transact_ix_data(
        nullifiers
            .iter()
            .map(|nullifier| eddsa_input_utxo(*nullifier, 0))
            .collect(),
        Vec::new(),
        inline_outputs(&output_hashes, &view_tags),
    );
    let owner_pk_hashes =
        output_owner_pk_hashes(&transact_ix_data.bound.outputs).expect("output owner pk hashes");
    let mut nullifier_pks = vec![nullifier_pk];
    nullifier_pks.extend(std::iter::repeat_n(zero, n_outputs - 1));
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &nullifier_pks);
    let external_data_hash =
        external_data_hash(&transact_ix_data, &[]).expect("external data hash");
    let mut private_outputs = vec![real_hash];
    private_outputs.extend(std::iter::repeat_n(zero, n_outputs - 1));
    let private_tx =
        PrivateTxHash::new(&vec![zero; n_inputs], &private_outputs, &external_data_hash)
            .hash()
            .expect("private tx hash");
    // The signer run the proof binds: the payer owns every input here, so the
    // unique run is just the payer hash, zero-padded to the n_inputs + 1
    // circuit width. The program derives the same value with `hash_bytes`.
    let mut signer_pk_hashes = vec![owner_hash];
    signer_pk_hashes.extend(std::iter::repeat_n(zero, n_inputs));

    let (public_slot_assets, public_slot_amounts) = sol_public_slots(zero);
    let public_input_hash = PublicInputs {
        nullifiers: &nullifiers,
        output_hashes: &output_hashes,
        utxo_roots: &vec![utxo_root; n_inputs],
        nullifier_tree_roots: &vec![nullifier_root; n_inputs],
        private_tx: &private_tx,
        external_data_hash: &external_data_hash,
        public_transfers: &PublicTransfers {
            assets: public_slot_assets,
            amounts: public_slot_amounts,
        },
        ring_program_id: &zero,
        allow_dummy_inputs: &fe(1),
        signer_pk_hashes: &signer_pk_hashes,
        output_owner_pk_hashes: Some(&owner_pk_hashes),
    }
    .hash()
    .expect("public input hash");
    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs,
        outputs,
        external_data_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        signer_pk_hashes: signer_pk_hashes.clone(),
        public_input_hash,
    });
    let proof = ProverClient::local()
        .prove_transfer(&prover_inputs)
        .unwrap_or_else(|error| panic!("prove transfer {n_inputs}x{n_outputs}: {error}"));
    transact_ix_data.tail.proof = pack_transact_proof(&proof).expect("pack transfer proof");
    transact_ix_data.tail.private_tx_hash = private_tx;

    let ix = Transact {
        payer: payer.pubkey(),
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();

    let accounts = transact_accounts(&pt, &ix, program_id, None);
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    let name = format!("transfer eddsa {n_inputs}x{n_outputs}");
    assert!(!entries.is_empty(), "no profiling entries for '{name}'");
    bench.add_from_entries(&name, entries);
}

/// The proof rail a benched `ring_transact` runs on. Both rails share the
/// account layout, the tree work, and the shape; they differ in the verifying
/// key and in how ownership is authorized.
#[derive(Clone, Copy)]
enum RingRail {
    /// Standard Groth16. Input owners are matched privately against the public
    /// Solana signer run.
    Eddsa,
    /// Ownership authorized inside the proof by a shared P256 signature, whose
    /// emulated-curve gadget adds a BSB22 commitment: verification runs one
    /// extra Pedersen proof-of-knowledge pairing.
    P256,
}

impl RingRail {
    fn label(self) -> &'static str {
        match self {
            Self::Eddsa => "ring",
            Self::P256 => "p256 ring",
        }
    }
}

/// One `ring_transact` shape per policy-ring rail, spending one real
/// zero-value input plus dummies and settling nothing, so the measurement
/// isolates the rail's proof verification, public-input hashing, and tree
/// application from the confidential rail benched above.
///
/// The real input is what the P256 rail requires: `P256Signers` asserts at
/// least one content-bearing P256-owned slot, so an all-dummy witness is
/// unprovable there. It is a default-ring UTXO, which
/// `AssertRingMemberOrFree` accepts beside members of the signing ring, and on
/// the P256 rail that publishes the owner's x-coordinate as
/// `default_owner_tag`. Every output is a dummy tagged with the payer: a real
/// default-ring output would have to publish its owner hash, and these
/// unmarked (`data: None`) slots publish zero.
///
/// The signing `RingConfig` is written at the ring's canonical `ring_auth` PDA
/// and passed as a signer, exactly as the ring program's CPI would: the
/// program reads `ring_program_id` from it and never re-derives the address.
fn bench_ring_transfer_shape(
    mollusk: &Mollusk,
    program_id: &Pubkey,
    rail: RingRail,
    n_inputs: usize,
    n_outputs: usize,
    bench: &mut CuBenchmark,
) {
    assert!(n_inputs > 0, "a ring proof needs at least one real input");
    let (mut pt, _authority, tree) = bench_setup();
    spawn_workspace_prover();

    let payer = pt.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];
    let payer_hash = hash_bytes(&payer_bytes).expect("payer hash");

    let ring_program = Pubkey::new_from_array(RING_TEST_PROGRAM_ID);
    let (ring_config, ring_config_bump) = pda::ring_auth(&ring_program);
    let config = RingConfig {
        discriminator: RING_CONFIG,
        authority: Address::new_from_array(payer_bytes),
        program_id: Address::new_from_array(ring_program.to_bytes()),
        ring_authority_transact_is_enabled: 0,
        paused: 0,
        bump: ring_config_bump,
    };
    write_ring_config_account(
        &mut pt,
        ring_config,
        Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        bytemuck::bytes_of(&config).to_vec(),
    );
    // The program folds `hash_bytes` of the signing config's stored program id
    // into the public `ring_program_id` element, which the circuit requires to
    // be non-zero.
    let ring_field = hash_bytes(&ring_program.to_bytes()).expect("ring program field");

    let p256_keypair = ShieldedKeypair::from_keypair(
        SigningKey::from_p256_bytes(&[7u8; 32]).expect("fixed P256 signing key"),
    )
    .expect("P256 shielded keypair");
    // The eddsa rail spends the payer's own UTXO; the P256 rail spends one
    // owned by the shared P256 authorization key.
    let (owner_public_key, input_owner_pk_hash) = match rail {
        RingRail::Eddsa => (PublicKey::from_ed25519(&payer_bytes), payer_hash),
        // Zero is the sentinel `P256Signers` resolves to the authorization
        // pubkey; a non-zero tag would be read as a Solana signer identity.
        RingRail::P256 => (p256_keypair.signing_pubkey(), zero),
    };

    let blinding = test_blinding(7);
    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let owner_field = owner_hash(&owner_public_key, &nullifier_pk).expect("owner field");
    let utxo = Utxo {
        owner: owner_public_key,
        asset: SOL_MINT,
        amount: 0,
        blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    let event = pt
        .deposit_sol(&tree, &payer, 0, owner_field, blinding)
        .expect("proofless zero deposit");
    let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
    assert_eq!(utxo_hash, event.utxo_hash);

    // The deposit made the UTXO leaf 0, so its inclusion proof binds root
    // history index 1.
    let roots = tree_roots(&pt, &tree, 1);
    let (utxo_root, nullifier_root) = roots;
    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree.append(&utxo_hash).expect("append state leaf");
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(0, true)
        .expect("state proof")
        .to_vec();
    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let nullifier = nullifier_key
        .nullifier(&utxo_hash, &blinding)
        .expect("nullifier");
    let non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
        .expect("non-inclusion proof");

    let mut inputs = vec![spend_input(SpendInputArgs {
        utxo: &utxo,
        owner_field: &owner_field,
        state_path: &state_path,
        state_path_index: 0,
        non_inclusion: &non_inclusion,
        roots,
        nullifier: &nullifier,
        owner_pk_hash: &input_owner_pk_hash,
        nullifier_key: &nullifier_key,
    })
    .expect("real input")];
    let mut nullifiers = vec![nullifier];
    for index in 0..n_inputs - 1 {
        let seed = u8::try_from(index).expect("supported ring input count");
        let (input, dummy_nullifier) = dummy_input(
            &[seed.checked_add(31).expect("dummy input seed"); 31],
            &nf_tree,
            roots,
        )
        .expect("dummy input");
        inputs.push(input);
        nullifiers.push(dummy_nullifier);
    }

    let dummy_outputs: Vec<(TransferOutput, [u8; 32])> = (0..n_outputs)
        .map(|position| {
            let seed = u8::try_from(position).expect("supported ring output count");
            dummy_transfer_output(&[seed.checked_add(1).expect("dummy output seed"); 31])
                .expect("dummy output")
        })
        .collect();
    let output_hashes: Vec<[u8; 32]> = dummy_outputs.iter().map(|(_, hash)| *hash).collect();
    let mut outputs: Vec<TransferOutput> = dummy_outputs.into_iter().map(|(out, _)| out).collect();

    // Every dummy output names the payer, a transaction participant
    // (`AssertMaskedDummyOutputTags`).
    let view_tags = vec![payer_bytes; n_outputs];
    let mut transact_ix_data = new_transact_ix_data(
        nullifiers
            .iter()
            .map(|nullifier| eddsa_input_utxo(*nullifier, 1))
            .collect(),
        Vec::new(),
        inline_outputs(&output_hashes, &view_tags),
    );
    let owner_pk_hashes =
        output_owner_pk_hashes(&transact_ix_data.bound.outputs).expect("output owner pk hashes");
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &vec![zero; n_outputs]);

    let addresses =
        account_tagged_owner_addresses(&transact_ix_data).expect("account-tagged owners");
    let external_data_hash =
        external_data_hash_with_addresses(&transact_ix_data, tag::RING_TRANSACT, &addresses)
            .expect("ring external data hash");
    // The real input contributes its utxo hash; every dummy input and every
    // dummy output contributes zero.
    let mut private_inputs = vec![utxo_hash];
    private_inputs.extend(std::iter::repeat_n(zero, n_inputs - 1));
    let private_tx =
        PrivateTxHash::new(&private_inputs, &vec![zero; n_outputs], &external_data_hash)
            .hash()
            .expect("private tx hash");

    // The signer run the proof binds: the payer alone, zero-padded to the
    // n_inputs + 1 circuit width. The P256 owner authorizes inside the proof,
    // so it never joins the run.
    let mut signer_pk_hashes = vec![payer_hash];
    signer_pk_hashes.extend(std::iter::repeat_n(zero, n_inputs));
    let (public_slot_assets, public_slot_amounts) = sol_public_slots(zero);
    let public_transfers = PublicTransfers {
        assets: public_slot_assets,
        amounts: public_slot_amounts,
    };
    let allow_dummy_inputs = fe(1);
    let utxo_roots = vec![utxo_root; n_inputs];
    let nullifier_tree_roots = vec![nullifier_root; n_inputs];
    // The ring rails publish owner tags only for confidential-marked outputs;
    // these carry no data, so every published slot is zero -- which is what the
    // program folds into its output-owner chain.
    let published_output_owner_pk_hashes = vec![zero; n_outputs];
    let public_inputs = PublicInputs {
        nullifiers: &nullifiers,
        output_hashes: &output_hashes,
        utxo_roots: &utxo_roots,
        nullifier_tree_roots: &nullifier_tree_roots,
        private_tx: &private_tx,
        external_data_hash: &external_data_hash,
        public_transfers: &public_transfers,
        ring_program_id: &ring_field,
        allow_dummy_inputs: &allow_dummy_inputs,
        signer_pk_hashes: &signer_pk_hashes,
        output_owner_pk_hashes: Some(&published_output_owner_pk_hashes),
    };

    let n_in = u8::try_from(n_inputs).expect("supported ring input count");
    let n_out = u8::try_from(n_outputs).expect("supported ring output count");
    let n_slots = N_PUBLIC_SLOTS as u8;
    let (wire_proof, circuit) = match rail {
        RingRail::Eddsa => {
            let public_input_hash = public_inputs.hash().expect("public input hash");
            let mut prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
                inputs,
                outputs,
                external_data_hash,
                private_tx_hash: private_tx,
                public_slot_assets,
                public_slot_amounts,
                signer_pk_hashes: signer_pk_hashes.clone(),
                public_input_hash,
            });
            prover_inputs.ring_program_id = be(&ring_field);
            prover_inputs.published_output_owner_pk_hashes =
                published_output_owner_pk_hashes.iter().map(be).collect();
            let proof = ProverClient::local()
                .prove_transfer_ring(&prover_inputs)
                .unwrap_or_else(|error| {
                    panic!("prove ring transfer {n_inputs}x{n_outputs}: {error}")
                });
            (
                pack_transact_proof(&proof).expect("pack ring proof"),
                CircuitId::RingEddsa(n_in, n_out, n_slots),
            )
        }
        RingRail::P256 => {
            // The shared authorization signs the SHA-256 digest of
            // `private_tx_hash`, which the program recomputes from instruction
            // data; the circuit binds both its Poseidon hash and the 128-bit
            // limbs of the digest itself.
            let message_digest = sha256(&private_tx);
            let (high, low) = message_digest.split_at(16);
            let authorization = SyncWalletAuthority::sign_p256(&p256_keypair, &message_digest)
                .expect("P256 authorization");
            let (pub_x, pub_y) = authorization
                .pubkey
                .coordinates()
                .expect("P256 pubkey coordinates");
            // The real input is default-ring, so the shared owner is published
            // as `default_owner_tag` and the program hashes it into the public
            // input.
            let default_owner_tag = pub_x;
            let default_p256_owner_pk_hash =
                hash_bytes(&default_owner_tag).expect("default P256 owner pk hash");
            let public_input_hash = public_inputs
                .hash_with_p256_authorization(
                    &hash_bytes(&message_digest).expect("P256 message proof input hash"),
                    &default_p256_owner_pk_hash,
                )
                .expect("public input hash");
            let prover_inputs = TransferP256Inputs {
                inputs,
                outputs,
                external_data_hash: be(&external_data_hash),
                private_tx_hash: be(&private_tx),
                p256_pub_x: be(&pub_x),
                p256_pub_y: be(&pub_y),
                p256_sig_r: be(&authorization.sig_r),
                p256_sig_s: be(&authorization.sig_s),
                p256_message_hash_low: BigUint::from_bytes_be(low),
                p256_message_hash_high: BigUint::from_bytes_be(high),
                default_p256_owner_pk_hash: be(&default_p256_owner_pk_hash),
                public_assets: public_slot_assets.map(|asset| be(&asset)),
                public_amounts: public_slot_amounts.map(|amount| be(&amount)),
                ring_program_id: be(&ring_field),
                signer_pk_hashes: signer_pk_hashes.iter().map(be).collect(),
                allow_dummy_inputs: BigUint::from(1u8),
                published_output_owner_pk_hashes: published_output_owner_pk_hashes
                    .iter()
                    .map(be)
                    .collect(),
                public_input_hash: be(&public_input_hash),
            };
            let proof = ProverClient::local()
                .prove_transfer_p256_ring(&prover_inputs)
                .unwrap_or_else(|error| {
                    panic!("prove P256 ring transfer {n_inputs}x{n_outputs}: {error}")
                });
            let (wire_proof, bsb22_commitment) = ProofCompressed::try_from(proof)
                .expect("compress P256 ring proof")
                .into_ring_p256_transact_parts()
                .expect("split P256 ring proof");
            (
                wire_proof,
                CircuitId::RingP256(
                    n_in,
                    n_out,
                    n_slots,
                    RingP256ProofData {
                        bsb22_commitment,
                        default_owner_tag: Some(default_owner_tag),
                    },
                ),
            )
        }
    };
    transact_ix_data.tail.proof = wire_proof;
    transact_ix_data.tail.private_tx_hash = private_tx;
    transact_ix_data.tail.circuit = circuit;

    let ix = RingTransact {
        payer: payer.pubkey(),
        input_tree: tree,
        output_tree: tree,
        ring_program_id: ring_program,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .cpi_instruction();

    let accounts = transact_accounts(&pt, &ix, program_id, None);
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    let name = format!("transfer {} {n_inputs}x{n_outputs}", rail.label());
    assert!(!entries.is_empty(), "no profiling entries for '{name}'");
    bench.add_from_entries(&name, entries);
}

// A merge at one supported shape: the owner collapses one real UTXO plus derived
// dummy slots into a single output. Merge is the other nullifier-spending
// instruction, and it carries the same dominant per-input work as transact -- one
// queue insertion and one PDA per declared input -- so both shapes are benched to
// show what the padding in a narrow merge costs and what the wide circuit costs.
// Each shape needs its own pool: the proof builder deposits the real input and
// reconstructs the state witness from that single leaf, so the tree must be empty.
fn bench_merge_shape(
    mollusk: &Mollusk,
    program_id: &Pubkey,
    input_count: usize,
    bench: &mut CuBenchmark,
) {
    std::env::set_var("SHIELDED_POOL_PROGRAM_PATH", PLAIN_PROGRAM_PATH);
    let mut pool = Pool::initialized();
    spawn_workspace_prover();

    let merge = RealMergeProof { input_count }.build(&mut pool);
    let ix = merge.instruction(&pool);
    let accounts = nullifier_spend_accounts(
        &pool.rpc,
        &ix,
        program_id,
        pool.tree,
        &merge.nullifiers,
        None,
    );
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    let name = format!("merge {input_count}x1");
    assert!(!entries.is_empty(), "no profiling entries for '{name}'");
    bench.add_from_entries(&name, entries);
}

// (2,3) eddsa SOL withdrawal: shield one real UTXO, then spend it to withdraw the
// full amount to an external account. Mirrors `shield_withdraw::shield_then_withdraw_sol`.
fn bench_withdrawal_sol(mollusk: &Mollusk, program_id: &Pubkey, bench: &mut CuBenchmark) {
    let (mut pt, _authority, tree) = bench_setup();
    spawn_workspace_prover();

    const AMOUNT: u64 = 1_000_000_000;
    let payer = pt.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    let blinding = test_blinding(7);
    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo = Utxo {
        owner: PublicKey::from_ed25519(&payer_bytes),
        asset: SOL_MINT,
        amount: AMOUNT,
        blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    let owner_pk_hash = utxo.owner.owner_proof_input_hash().expect("owner pk hash");
    let owner_field = owner_hash(&utxo.owner, &nullifier_pk).expect("owner field");

    let event = pt
        .deposit_sol(&tree, &payer, AMOUNT, owner_field, blinding)
        .expect("proofless deposit");
    let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
    assert_eq!(utxo_hash, event.utxo_hash);

    let (utxo_root, nullifier_root) = tree_roots(&pt, &tree, 1);
    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree.append(&utxo_hash).expect("append state leaf");
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(0, true)
        .expect("state proof")
        .to_vec();

    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let nullifier = nullifier_key
        .nullifier(&utxo_hash, &blinding)
        .expect("nullifier");
    let non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
        .expect("non inclusion proof");

    let roots = (utxo_root, nullifier_root);
    let (dummy_spend_input, dummy_nullifier) =
        dummy_input(&[2u8; 31], &nf_tree, roots).expect("dummy input");
    let payer_spend_input = spend_input(SpendInputArgs {
        utxo: &utxo,
        owner_field: &owner_field,
        state_path: &state_path,
        state_path_index: 0,
        non_inclusion: &non_inclusion,
        roots,
        nullifier: &nullifier,
        owner_pk_hash: &owner_pk_hash,
        nullifier_key: &nullifier_key,
    })
    .expect("real input");

    let recipient = Keypair::new().pubkey();
    pt.airdrop(&recipient, 1_000_000)
        .expect("airdrop recipient");

    let dummy_outputs: Vec<(TransferOutput, [u8; 32])> = [[1u8; 31], [2u8; 31], [3u8; 31]]
        .iter()
        .map(|blinding| dummy_transfer_output(blinding).expect("dummy output"))
        .collect();
    let output_hashes: Vec<[u8; 32]> = dummy_outputs.iter().map(|(_, hash)| *hash).collect();
    let mut outputs: Vec<TransferOutput> = dummy_outputs.into_iter().map(|(out, _)| out).collect();

    // Dummy slots carry the payer's tag (the AssertDummyTags rule; see
    // `set_output_owner_tags`).
    let view_tags = [payer_bytes; 3];
    let mut transact_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(nullifier, 1),
            eddsa_input_utxo(dummy_nullifier, 1),
        ],
        vec![InterfaceTransfer::SolWithdrawal { amount: AMOUNT }],
        inline_outputs(&output_hashes, &view_tags),
    );
    let owner_pk_hashes =
        output_owner_pk_hashes(&transact_ix_data.bound.outputs).expect("output owner pk hashes");
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &[zero, zero, zero]);
    let resolved_transfers = [ResolvedInterfaceTransfer::SolWithdrawal {
        amount: AMOUNT,
        recipient: recipient.to_bytes(),
    }];
    let external_data_hash =
        external_data_hash(&transact_ix_data, &resolved_transfers).expect("external data hash");
    let private_tx =
        PrivateTxHash::new(&[utxo_hash, zero], &[zero, zero, zero], &external_data_hash)
            .hash()
            .expect("private tx hash");
    let public_sol_field = public_sol_field(Some(-(AMOUNT as i64)));
    let (public_slot_assets, public_slot_amounts) = sol_public_slots(public_sol_field);
    // Both inputs are the payer's, so the unique signer run is one entry,
    // zero-padded to the 2 + 1 circuit width.
    let signer_pk_hashes = [owner_pk_hash, zero, zero];

    let public_input_hash = PublicInputs {
        nullifiers: &[nullifier, dummy_nullifier],
        output_hashes: &output_hashes,
        utxo_roots: &[utxo_root, utxo_root],
        nullifier_tree_roots: &[nullifier_root, nullifier_root],
        private_tx: &private_tx,
        external_data_hash: &external_data_hash,
        public_transfers: &PublicTransfers {
            assets: public_slot_assets,
            amounts: public_slot_amounts,
        },
        ring_program_id: &zero,
        allow_dummy_inputs: &fe(1),
        signer_pk_hashes: &signer_pk_hashes,
        output_owner_pk_hashes: Some(&owner_pk_hashes),
    }
    .hash()
    .expect("public input hash");
    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![payer_spend_input, dummy_spend_input],
        outputs,
        external_data_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        signer_pk_hashes: signer_pk_hashes.to_vec(),
        public_input_hash,
    });
    transact_ix_data.tail.proof =
        prove_and_verify_transfer(&prover_inputs, public_input_hash, "withdrawal sol")
            .expect("prove withdrawal sol");
    transact_ix_data.tail.private_tx_hash = private_tx;

    let ix = Transact {
        payer: payer.pubkey(),
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts { recipient },
        )],
        data: transact_ix_data,
    }
    .instruction();

    let accounts = transact_accounts(&pt, &ix, program_id, None);
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for 'withdrawal sol'"
    );
    bench.add_from_entries("withdrawal sol", entries);
}

// (2,3) eddsa SPL withdrawal: shield one real SPL UTXO via the proofless SPL
// deposit, then spend it to withdraw the full token amount from the vault back to
// the user's token account (the program signs the vault->user transfer with its
// `cpi_authority` PDA).
fn bench_withdrawal_spl(
    mollusk: &Mollusk,
    program_id: &Pubkey,
    token_program_account: &(Pubkey, Account),
    bench: &mut CuBenchmark,
) {
    let (mut pt, authority, tree) = bench_setup();
    spawn_workspace_prover();

    const AMOUNT: u64 = 1_000;
    let withdrawal = build_spl_withdrawal(&mut pt, &authority, &tree, AMOUNT, test_blinding(7))
        .expect("build SPL withdrawal");
    let ix = withdrawal.instruction;

    let accounts = transact_accounts(&pt, &ix, program_id, Some(token_program_account));
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for 'withdrawal spl'"
    );
    bench.add_from_entries("withdrawal spl", entries);
}
