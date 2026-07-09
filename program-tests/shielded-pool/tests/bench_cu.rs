#![cfg(not(feature = "localnet"))]

use light_program_profiler::{
    mollusk::{register_profiling_syscalls, take_profiling_entries},
    report::{CuBenchmark, ReadmeConfig},
};
use mollusk_solana_account::Account as MolluskAccount;
use mollusk_solana_instruction::{
    AccountMeta as MolluskAccountMeta, Instruction as MolluskInstruction,
};
use mollusk_solana_pubkey::Pubkey as MolluskPubkey;
use mollusk_svm::{program::loader_keys::LOADER_V3, result::Check, Mollusk};
use num_bigint::BigUint;
use rings_client::{TransferOutput, STATE_TREE_HEIGHT};
use rings_hasher::{sha256::Sha256BE, Hasher, Poseidon};
use rings_interface::{
    instruction::{
        Deposit, DepositSplAccounts, Transact, TransactSolWithdrawal, TransactSplWithdrawal,
        TransactWithdrawal,
    },
    pda, PROGRAM_ID_PUBKEY, SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID,
    SPL_TOKEN_PROGRAM_ID,
};
use rings_keypair::{
    constants::BLINDING_LEN,
    hash::{hash_field, owner_hash},
    pubkey::PublicKey,
    NullifierKey, ShieldedKeypair,
};
use rings_merkle_tree::MerkleTree;
use rings_program_test::RingsProgramTest;
use rings_transaction::{
    instructions::transact::{no_address_hashes, private_tx_hash},
    AssetRegistry, Data, Utxo, Wallet, SOL_MINT,
};
use rings_tree::TreeAccount;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

mod common;

#[path = "common/transact.rs"]
mod transact_common;

use transact_common::{
    build_transfer_prover_inputs, build_transfer_prover_inputs_spl, dummy_input,
    dummy_transfer_output, eddsa_input_utxo, external_data_hash, external_data_hash_spl, fe,
    ix_output_ciphertext, new_transact_ix_data, nullifier_tree, output_owner_pk_hashes,
    prove_and_verify_transfer, public_input_hash, public_input_hash_spl, public_sol_field,
    set_output_owner_tags, spend_input, start_prover, SpendInputArgs, TransferProverInputsArgs,
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

fn to_mollusk_pubkey(key: &Pubkey) -> MolluskPubkey {
    MolluskPubkey::new_from_array(key.to_bytes())
}

fn to_mollusk_instruction(ix: &Instruction) -> MolluskInstruction {
    MolluskInstruction {
        program_id: to_mollusk_pubkey(&ix.program_id),
        accounts: ix
            .accounts
            .iter()
            .map(|m| MolluskAccountMeta {
                pubkey: to_mollusk_pubkey(&m.pubkey),
                is_signer: m.is_signer,
                is_writable: m.is_writable,
            })
            .collect(),
        data: ix.data.clone(),
    }
}

fn snapshot_account(pt: &RingsProgramTest, key: &Pubkey) -> (MolluskPubkey, MolluskAccount) {
    let mollusk_key = to_mollusk_pubkey(key);
    let account = match pt.svm.get_account(key) {
        Some(acc) => MolluskAccount {
            lamports: acc.lamports,
            data: acc.data,
            owner: MolluskPubkey::new_from_array(acc.owner.to_bytes()),
            executable: acc.executable,
            rent_epoch: acc.rent_epoch,
        },
        None => MolluskAccount {
            lamports: 1_000_000_000,
            data: Vec::new(),
            owner: MolluskPubkey::new_from_array([0u8; 32]),
            executable: false,
            rent_epoch: 0,
        },
    };
    (mollusk_key, account)
}

fn bench_setup() -> (RingsProgramTest, Keypair, Pubkey) {
    std::env::set_var("SHIELDED_POOL_PROGRAM_PATH", PLAIN_PROGRAM_PATH);
    let mut pt = common::program_test().expect("plain shielded-pool program built for litesvm");
    let authority = Keypair::new();
    pt.create_protocol_config(&authority)
        .expect("create_protocol_config");
    let tree = pt
        .create_tree(common::tree_account_size(), &authority)
        .expect("create_tree");
    (pt, authority, tree.pubkey())
}

fn deposit_sol_accounts(
    pt: &RingsProgramTest,
    ix: &Instruction,
    program_id: &MolluskPubkey,
) -> Vec<(MolluskPubkey, MolluskAccount)> {
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
    pt: &RingsProgramTest,
    ix: &Instruction,
    program_id: &MolluskPubkey,
    token_program_account: &(MolluskPubkey, MolluskAccount),
) -> Vec<(MolluskPubkey, MolluskAccount)> {
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

fn mollusk_program_account(program_id: &MolluskPubkey) -> (MolluskPubkey, MolluskAccount) {
    let account = mollusk_svm::program::create_program_account_loader_v3(program_id);
    (*program_id, account)
}

#[test]
#[ignore]
fn bench_cu_deposit() {
    std::env::set_var("SBF_OUT_DIR", PROFILING_SBF_DIR);

    let program_id = MolluskPubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let token_program_id = MolluskPubkey::new_from_array(SPL_TOKEN_PROGRAM_ID);

    let spl_token_elf = std::fs::read(SPL_TOKEN_PROGRAM_PATH).unwrap_or_else(|_| {
        panic!(
            "missing {SPL_TOKEN_PROGRAM_PATH}; run `just bench-shielded-pool` (it clones the \
             SPL Token program from mainnet via `solana program dump`)"
        )
    });

    let mut mollusk = Mollusk::default();
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&program_id, "shielded_pool_program", &LOADER_V3);
    mollusk.add_program_with_elf_and_loader(&token_program_id, &spl_token_elf, &LOADER_V3);

    let token_program_account = (
        token_program_id,
        mollusk_svm::program::create_program_account_loader_v3(&token_program_id),
    );

    let mut bench = CuBenchmark::new(ReadmeConfig {
        title: "Shielded Pool -- CU Benchmark".into(),
        description:
            "Compute unit profiling for the shielded-pool deposit and transact instructions, \
             replayed under mollusk from litesvm-built account state: proof-free SOL and SPL \
             shields, plus Groth16-proven (2,3) eddsa transact shapes -- a shielded transfer and \
             SOL/SPL withdrawals."
                .into(),
        output_path: concat!(env!("CARGO_MANIFEST_DIR"), "/CU_BENCHMARK.md").into(),
        regenerate_command: Some("just bench-shielded-pool".into()),
        ..Default::default()
    });

    bench_deposit_sol(&mollusk, &program_id, &mut bench);
    bench_deposit_spl(&mollusk, &program_id, &token_program_account, &mut bench);
    bench_transfer(&mollusk, &program_id, &mut bench);
    bench_withdrawal_sol(&mollusk, &program_id, &mut bench);
    bench_withdrawal_spl(&mollusk, &program_id, &token_program_account, &mut bench);

    bench.generate().expect("write CU_BENCHMARK.md");
}

// Snapshot every account a `transact` instruction references, mapping the
// program account (self-CPI `emit_event`), the system program, and the SPL Token
// program to their mollusk fixtures while snapshotting all PDAs/data accounts
// from the litesvm pre-instruction state the proof is bound to.
fn transact_accounts(
    pt: &RingsProgramTest,
    ix: &Instruction,
    program_id: &MolluskPubkey,
    token_program_account: Option<&(MolluskPubkey, MolluskAccount)>,
) -> Vec<(MolluskPubkey, MolluskAccount)> {
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

/// On-chain (utxo, nullifier) tree roots at history index `utxo_index` / 0, as
/// the program reads them in `apply_tree`.
fn tree_roots(pt: &RingsProgramTest, tree: &Pubkey, utxo_index: u16) -> ([u8; 32], [u8; 32]) {
    let mut data = pt.account_data(tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.get_utxo_tree_root(utxo_index).expect("utxo root"),
        account.get_nullifier_tree_root(0).expect("nullifier root"),
    )
}

fn bench_deposit_sol(mollusk: &Mollusk, program_id: &MolluskPubkey, bench: &mut CuBenchmark) {
    let (mut pt, _authority, tree) = bench_setup();
    let depositor = Keypair::new();
    pt.airdrop(&depositor.pubkey(), 1_000_000_000)
        .expect("airdrop depositor");

    let mut recipient = Wallet::new(
        ShieldedKeypair::new().expect("recipient keypair"),
        AssetRegistry::default(),
    )
    .expect("wallet");
    let seed = [3u8; BLINDING_LEN];
    let data = RingsProgramTest::wallet_sol_shield_data(1_000_000, &recipient, &seed, 0)
        .expect("wallet deposit data");
    let _ = &mut recipient;

    let ix = Deposit {
        tree,
        depositor: depositor.pubkey(),
        spl: None,
        view_tag: data.view_tag,
        owner: data.owner,
        blinding: data.blinding,
        public_amount: data.public_amount,
        utxo_data: data.utxo_data.clone(),
        memo: None,
    }
    .instruction();

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

fn bench_deposit_spl(
    mollusk: &Mollusk,
    program_id: &MolluskPubkey,
    token_program_account: &(MolluskPubkey, MolluskAccount),
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

    let mut recipient = Wallet::new(
        ShieldedKeypair::new().expect("recipient keypair"),
        AssetRegistry::default(),
    )
    .expect("wallet");
    let seed = [7u8; BLINDING_LEN];
    let data = RingsProgramTest::wallet_spl_shield_data(1_000, &recipient, &seed, 0)
        .expect("wallet deposit data");
    let _ = &mut recipient;

    let ix = Deposit {
        tree,
        depositor: depositor.pubkey(),
        spl: Some(DepositSplAccounts {
            user_token,
            spl_token_interface: pda::spl_asset_vault(&mint),
            registry: pda::spl_asset_registry(&mint),
            token_program: RingsProgramTest::token_program_id(),
        }),
        view_tag: data.view_tag,
        owner: data.owner,
        blinding: data.blinding,
        public_amount: data.public_amount,
        utxo_data: data.utxo_data.clone(),
        memo: None,
    }
    .instruction();

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

// (2,3) eddsa shielded transfer: two circuit-dummy inputs, three dummy outputs,
// no settlement. Mirrors `transact::transact_sends_valid_proof`.
fn bench_transfer(mollusk: &Mollusk, program_id: &MolluskPubkey, bench: &mut CuBenchmark) {
    let (pt, _authority, tree) = bench_setup();
    start_prover().expect("start prover");

    let payer = pt.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let roots = tree_roots(&pt, &tree, 0);
    let (utxo_root, nullifier_root) = roots;
    let zero = [0u8; 32];

    let nullifiers = [fe(1), fe(2)];
    let dummy_outputs: Vec<(TransferOutput, [u8; 32])> = [[1u8; 31], [2u8; 31], [3u8; 31]]
        .iter()
        .map(|blinding| dummy_transfer_output(blinding).expect("dummy output"))
        .collect();
    let output_hashes: Vec<[u8; 32]> = dummy_outputs.iter().map(|(_, hash)| *hash).collect();
    let mut outputs: Vec<TransferOutput> = dummy_outputs.into_iter().map(|(out, _)| out).collect();

    let mut transact_ix_data = new_transact_ix_data(
        nullifiers
            .iter()
            .map(|nullifier| eddsa_input_utxo(*nullifier, 0))
            .collect(),
        None,
        output_hashes.clone(),
        vec![
            ix_output_ciphertext([1u8; 32]),
            ix_output_ciphertext([2u8; 32]),
        ],
        None,
    );
    let owner_pk_hashes =
        output_owner_pk_hashes(&transact_ix_data.output_ciphertexts, output_hashes.len())
            .expect("output owner pk hashes");
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &[zero, zero, zero]);
    let external_data_hash =
        external_data_hash(&transact_ix_data, &zero).expect("external data hash");
    let private_tx = private_tx_hash(
        &[zero, zero],
        &[zero, zero, zero],
        &no_address_hashes(2),
        &external_data_hash,
    )
    .expect("private tx hash");
    let owner_hash = hash_field(&payer_bytes).expect("owner hash");
    let payer_pubkey_hash = Sha256BE::hash(&payer_bytes).expect("payer hash");

    let public_input_hash = public_input_hash(
        &nullifiers,
        &output_hashes,
        &[utxo_root, utxo_root],
        &[nullifier_root, nullifier_root],
        &private_tx,
        &external_data_hash,
        &zero,
        &payer_pubkey_hash,
        &[owner_hash, owner_hash],
        &owner_pk_hashes,
        &zero,
    );
    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![
            dummy_input(&nullifiers[0], roots, &owner_hash),
            dummy_input(&nullifiers[1], roots, &owner_hash),
        ],
        outputs,
        external_data_hash,
        private_tx_hash: private_tx,
        public_sol_amount: zero,
        payer_pubkey_hash,
        public_input_hash,
    });
    transact_ix_data.proof =
        prove_and_verify_transfer(&prover_inputs, public_input_hash, "transfer")
            .expect("prove transfer");
    transact_ix_data.private_tx_hash = private_tx;

    let ix = Transact {
        payer: payer.pubkey(),
        tree,
        withdrawal: None,
        data: transact_ix_data,
    }
    .instruction();

    let accounts = transact_accounts(&pt, &ix, program_id, None);
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for 'transfer'");
    bench.add_from_entries("transfer", entries);
}

// (2,3) eddsa SOL withdrawal: shield one real UTXO, then spend it to withdraw the
// full amount to an external account. Mirrors `shield_withdraw::shield_then_withdraw_sol`.
fn bench_withdrawal_sol(mollusk: &Mollusk, program_id: &MolluskPubkey, bench: &mut CuBenchmark) {
    let (mut pt, _authority, tree) = bench_setup();
    start_prover().expect("start prover");

    const AMOUNT: u64 = 1_000_000_000;
    let payer = pt.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    let blinding: [u8; 31] = [7u8; 31];
    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo = Utxo {
        owner: PublicKey::from_ed25519(&payer_bytes),
        asset: SOL_MINT,
        amount: AMOUNT,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let owner_pk_hash = utxo.owner.hash().expect("owner pk hash");
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
    let dummy_nullifier = fe(2);
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

    let mut transact_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(nullifier, 1),
            eddsa_input_utxo(dummy_nullifier, 1),
        ],
        Some(-(AMOUNT as i64)),
        output_hashes.clone(),
        vec![
            ix_output_ciphertext([1u8; 32]),
            ix_output_ciphertext([2u8; 32]),
        ],
        None,
    );
    let owner_pk_hashes =
        output_owner_pk_hashes(&transact_ix_data.output_ciphertexts, output_hashes.len())
            .expect("output owner pk hashes");
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &[zero, zero, zero]);
    let external_data_hash =
        external_data_hash(&transact_ix_data, &recipient.to_bytes()).expect("external data hash");
    let private_tx = private_tx_hash(
        &[utxo_hash, zero],
        &[zero, zero, zero],
        &no_address_hashes(2),
        &external_data_hash,
    )
    .expect("private tx hash");
    let public_sol_field = public_sol_field(transact_ix_data.public_sol_amount);
    let payer_pubkey_hash = Sha256BE::hash(&payer_bytes).expect("payer hash");

    let public_input_hash = public_input_hash(
        &[nullifier, dummy_nullifier],
        &output_hashes,
        &[utxo_root, utxo_root],
        &[nullifier_root, nullifier_root],
        &private_tx,
        &external_data_hash,
        &public_sol_field,
        &payer_pubkey_hash,
        &[owner_pk_hash, owner_pk_hash],
        &owner_pk_hashes,
        &zero,
    );
    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![
            payer_spend_input,
            dummy_input(&dummy_nullifier, roots, &owner_pk_hash),
        ],
        outputs,
        external_data_hash,
        private_tx_hash: private_tx,
        public_sol_amount: public_sol_field,
        payer_pubkey_hash,
        public_input_hash,
    });
    transact_ix_data.proof =
        prove_and_verify_transfer(&prover_inputs, public_input_hash, "withdrawal sol")
            .expect("prove withdrawal sol");
    transact_ix_data.private_tx_hash = private_tx;

    let ix = Transact {
        payer: payer.pubkey(),
        tree,
        withdrawal: Some(TransactWithdrawal::Sol(TransactSolWithdrawal { recipient })),
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
    program_id: &MolluskPubkey,
    token_program_account: &(MolluskPubkey, MolluskAccount),
    bench: &mut CuBenchmark,
) {
    let (mut pt, authority, tree) = bench_setup();
    start_prover().expect("start prover");

    const AMOUNT: u64 = 1_000;
    let mint = pt.create_mint().expect("create_mint");
    pt.ensure_asset_counter(&authority)
        .expect("create_asset_counter");
    pt.create_spl_interface(&authority, &mint)
        .expect("create_spl_interface");

    let payer = pt.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    let user_token = pt
        .create_token_account(&mint, &payer.pubkey())
        .expect("user token account");
    pt.mint_to(&mint, &user_token, AMOUNT).expect("mint_to");

    let blinding: [u8; 31] = [7u8; 31];
    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo = Utxo {
        owner: PublicKey::from_ed25519(&payer_bytes),
        asset: solana_address::Address::new_from_array(mint.to_bytes()),
        amount: AMOUNT,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let owner_pk_hash = utxo.owner.hash().expect("owner pk hash");
    let owner_field = owner_hash(&utxo.owner, &nullifier_pk).expect("owner field");

    let data = RingsProgramTest::spl_shield_data(AMOUNT, owner_field, blinding);
    let event = pt
        .deposit_spl(&tree, &payer, &user_token, &mint, &data)
        .expect("proofless spl deposit");
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
    let dummy_nullifier = fe(2);
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

    let vault = pda::spl_asset_vault(&mint);

    let dummy_outputs: Vec<(TransferOutput, [u8; 32])> = [[1u8; 31], [2u8; 31], [3u8; 31]]
        .iter()
        .map(|blinding| dummy_transfer_output(blinding).expect("dummy output"))
        .collect();
    let output_hashes: Vec<[u8; 32]> = dummy_outputs.iter().map(|(_, hash)| *hash).collect();
    let mut outputs: Vec<TransferOutput> = dummy_outputs.into_iter().map(|(out, _)| out).collect();

    let mut transact_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(nullifier, 1),
            eddsa_input_utxo(dummy_nullifier, 1),
        ],
        None,
        output_hashes.clone(),
        vec![
            ix_output_ciphertext([1u8; 32]),
            ix_output_ciphertext([2u8; 32]),
        ],
        None,
    );
    let owner_pk_hashes =
        output_owner_pk_hashes(&transact_ix_data.output_ciphertexts, output_hashes.len())
            .expect("output owner pk hashes");
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &[zero, zero, zero]);
    // SPL withdrawal carries the public amount in `public_spl_amount`; the SOL
    // amount stays `None`.
    transact_ix_data.public_spl_amount = Some(-(AMOUNT as i64));
    let external_data_hash =
        external_data_hash_spl(&transact_ix_data, &user_token.to_bytes(), &vault.to_bytes())
            .expect("external data hash");
    let private_tx = private_tx_hash(
        &[utxo_hash, zero],
        &[zero, zero, zero],
        &no_address_hashes(2),
        &external_data_hash,
    )
    .expect("private tx hash");
    let public_spl_field = public_sol_field(transact_ix_data.public_spl_amount);
    let payer_pubkey_hash = Sha256BE::hash(&payer_bytes).expect("payer hash");

    let public_input_hash = public_input_hash_spl(
        &[nullifier, dummy_nullifier],
        &output_hashes,
        &[utxo_root, utxo_root],
        &[nullifier_root, nullifier_root],
        &private_tx,
        &external_data_hash,
        &public_spl_field,
        &mint.to_bytes(),
        &payer_pubkey_hash,
        &[owner_pk_hash, owner_pk_hash],
        &owner_pk_hashes,
        &zero,
    );
    let prover_inputs = build_transfer_prover_inputs_spl(
        TransferProverInputsArgs {
            inputs: vec![
                payer_spend_input,
                dummy_input(&dummy_nullifier, roots, &owner_pk_hash),
            ],
            outputs,
            external_data_hash,
            private_tx_hash: private_tx,
            public_sol_amount: zero,
            payer_pubkey_hash,
            public_input_hash,
        },
        public_spl_field,
        mint.to_bytes(),
    );
    transact_ix_data.proof =
        prove_and_verify_transfer(&prover_inputs, public_input_hash, "withdrawal spl")
            .expect("prove withdrawal spl");
    transact_ix_data.private_tx_hash = private_tx;

    let ix = Transact {
        payer: payer.pubkey(),
        tree,
        withdrawal: Some(TransactWithdrawal::Spl(TransactSplWithdrawal {
            cpi_authority: Some(Pubkey::new_from_array(SHIELDED_POOL_CPI_AUTHORITY)),
            spl_token_interface: vault,
            recipient: payer.pubkey(),
            user_token_account: user_token,
            token_program: RingsProgramTest::token_program_id(),
        })),
        data: transact_ix_data,
    }
    .instruction();

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
