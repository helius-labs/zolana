#![cfg(not(feature = "localnet"))]

use light_program_profiler::mollusk::{register_profiling_syscalls, take_profiling_entries};
use light_program_profiler::report::{CuBenchmark, ReadmeConfig};
use mollusk_solana_account::Account as MolluskAccount;
use mollusk_solana_instruction::{AccountMeta as MolluskAccountMeta, Instruction as MolluskInstruction};
use mollusk_solana_pubkey::Pubkey as MolluskPubkey;
use mollusk_svm::{program::loader_keys::LOADER_V3, result::Check, Mollusk};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::{Deposit, DepositSplAccounts},
    pda, PROGRAM_ID_PUBKEY, SHIELDED_POOL_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::ZolanaProgramTest;
use zolana_transaction::Wallet;

mod common;

const PLAIN_PROGRAM_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy/shielded_pool_program_plain.so");
const PROFILING_SBF_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy");
// SPL Token program cloned from mainnet via `solana program dump` (see the
// `bench-shielded-pool` justfile recipe), loaded into mollusk for the SPL
// deposit's token-transfer CPI.
const SPL_TOKEN_PROGRAM_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy/spl_token.so");

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

fn snapshot_account(pt: &ZolanaProgramTest, key: &Pubkey) -> (MolluskPubkey, MolluskAccount) {
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

fn bench_setup() -> (ZolanaProgramTest, Keypair, Pubkey) {
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
    pt: &ZolanaProgramTest,
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
    pt: &ZolanaProgramTest,
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
            "Compute unit profiling for the shielded-pool deposit instructions, replayed under \
             mollusk from litesvm-built account state: proof-free SOL and SPL shields."
                .into(),
        output_path: concat!(env!("CARGO_MANIFEST_DIR"), "/CU_BENCHMARK.md").into(),
        regenerate_command: Some("just bench-shielded-pool".into()),
        ..Default::default()
    });

    bench_deposit_sol(&mollusk, &program_id, &mut bench);
    bench_deposit_spl(
        &mollusk,
        &program_id,
        &token_program_account,
        &mut bench,
    );

    bench.generate().expect("write CU_BENCHMARK.md");
}

fn bench_deposit_sol(
    mollusk: &Mollusk,
    program_id: &MolluskPubkey,
    bench: &mut CuBenchmark,
) {
    let (mut pt, _authority, tree) = bench_setup();
    let depositor = Keypair::new();
    pt.airdrop(&depositor.pubkey(), 1_000_000_000)
        .expect("airdrop depositor");

    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");
    let seed = [3u8; BLINDING_LEN];
    let data = ZolanaProgramTest::wallet_sol_shield_data(1_000_000, &recipient, &seed, 0)
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
        program_data_hash: data.program_data_hash,
        program_data: data.program_data.clone(),
        cpi_signer: data.cpi_signer,
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

    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");
    let seed = [7u8; BLINDING_LEN];
    let data = ZolanaProgramTest::wallet_spl_shield_data(1_000, &recipient, &seed, 0)
        .expect("wallet deposit data");
    let _ = &mut recipient;

    let ix = Deposit {
        tree,
        depositor: depositor.pubkey(),
        spl: Some(DepositSplAccounts {
            user_token,
            vault: pda::spl_asset_vault(&mint),
            registry: pda::spl_asset_registry(&mint),
            token_program: ZolanaProgramTest::token_program_id(),
        }),
        view_tag: data.view_tag,
        owner: data.owner,
        blinding: data.blinding,
        public_amount: data.public_amount,
        program_data_hash: data.program_data_hash,
        program_data: data.program_data.clone(),
        cpi_signer: data.cpi_signer,
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
