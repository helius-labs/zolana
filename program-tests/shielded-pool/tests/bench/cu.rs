#![cfg(not(feature = "localnet"))]

use light_program_profiler::{
    mollusk::{register_profiling_syscalls, take_profiling_entries},
    report::{CuBenchmark, ReadmeConfig},
};
use mollusk_svm::{program::loader_keys::LOADER_V3, result::Check, Mollusk};
use num_bigint::BigUint;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    ProverClient, PublicInputs, PublicTransfers, TransferOutput, STATE_TREE_HEIGHT,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_hasher::Poseidon;
use zolana_interface::{
    instruction::{
        instruction_data::transact::{InterfaceTransfer, ResolvedInterfaceTransfer},
        Deposit, Transact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    },
    PROGRAM_ID_PUBKEY, SHIELDED_POOL_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey, ShieldedKeypair};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{test_blinding, ZolanaProgramTest};
use zolana_transaction::{instructions::transact::PrivateTxHash, Data, Utxo, SOL_MINT};

use shielded_pool_tests::support::{fixtures::Pool, mollusk, transact::tree_roots};
use zolana_test_utils::{
    prover::spawn_workspace_prover,
    transact::{
        build_spl_withdrawal, build_transfer_prover_inputs, derive_test_transfer_output_blindings,
        dummy_input, dummy_transfer_output, eddsa_input_utxo, external_data_hash, fe,
        inline_outputs, new_transact_ix_data, nullifier_tree, output_owner_pk_hashes,
        pack_transact_proof, prove_and_verify_transfer, public_sol_field, real_output,
        set_output_owner_tags, sol_public_slots, spend_input, transfer_output, SpendInputArgs,
        TransferProverInputsArgs,
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
    (rpc, authority, tree.pubkey())
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
             proof-free SOL/SPL shields, all ten Groth16-proven EdDSA transact shapes (including \
             the 1x8 split shape), and SOL/SPL withdrawals. This target is a pure benchmark: no \
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
    ] {
        bench_transfer_shape(&mollusk, &program_id, n_inputs, n_outputs, &mut bench);
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
// from the litesvm pre-instruction state the proof is bound to.
fn transact_accounts(
    pt: &ZolanaProgramTest,
    ix: &Instruction,
    program_id: &Pubkey,
    token_program_account: Option<&(Pubkey, Account)>,
) -> Vec<(Pubkey, Account)> {
    let token_program = Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID);
    let mut accounts = Vec::with_capacity(ix.accounts.len());
    for meta in &ix.accounts {
        if meta.pubkey == PROGRAM_ID_PUBKEY {
            accounts.push(mollusk_program_account(program_id));
        } else if meta.pubkey == Pubkey::default() {
            accounts.push(mollusk_svm::program::keyed_account_for_system_program());
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
    let mut outputs = vec![transfer_output(&real).expect("real transfer output")];
    for index in 1..n_outputs {
        let (output, _) = dummy_transfer_output(&[index as u8; 31]).expect("dummy output");
        outputs.push(output);
    }
    let output_hashes = derive_test_transfer_output_blindings(
        nullifiers.first().expect("transfer shape has an input"),
        &mut outputs,
    )
    .expect("derive output blindings");

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
        output_owner_pk_hashes(&transact_ix_data.outputs).expect("output owner pk hashes");
    let mut nullifier_pks = vec![nullifier_pk];
    nullifier_pks.extend(std::iter::repeat_n(zero, n_outputs - 1));
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &nullifier_pks);
    let external_data_hash =
        external_data_hash(&transact_ix_data, &[]).expect("external data hash");
    let mut private_outputs = vec![output_hashes[0]];
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
    transact_ix_data.proof = pack_transact_proof(&proof).expect("pack transfer proof");
    transact_ix_data.private_tx_hash = private_tx;

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
    let mut outputs: Vec<TransferOutput> = dummy_outputs.into_iter().map(|(out, _)| out).collect();
    let output_hashes = derive_test_transfer_output_blindings(&nullifier, &mut outputs)
        .expect("derive output blindings");

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
        output_owner_pk_hashes(&transact_ix_data.outputs).expect("output owner pk hashes");
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
    transact_ix_data.proof =
        prove_and_verify_transfer(&prover_inputs, public_input_hash, "withdrawal sol")
            .expect("prove withdrawal sol");
    transact_ix_data.private_tx_hash = private_tx;

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
