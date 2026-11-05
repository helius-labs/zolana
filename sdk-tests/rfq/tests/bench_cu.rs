use spr_test_utils::bench::{
    assemble_accounts, keypair_from_payer, prove_transact_timed, proving_time_table,
    system_owned_account, tree_fixture, tx_size_table, BENCH_TREE_ID,
};
use spr_test_utils::utxo::{
    encrypt_transaction_data, get_transaction_viewing_key, prepare_output_blindings,
};
use spr_transaction::utxo::SppProofInputUtxo;

use light_program_profiler::{
    mollusk::{register_profiling_syscalls, take_profiling_entries},
    report::{CuBenchmark, ReadmeConfig},
};
use mollusk_svm::{result::Check, Mollusk};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spr_interface::SHIELDED_POOL_PROGRAM_ID;
use spr_keypair::random_blinding;
use spr_program::instruction::Transact;
use spr_transaction::{
    instructions::transact::{ExternalData, SppProofInputs, SppProofOutputUtxo},
    AssetRegistry, Data, Utxo,
};

const SELL_SOL: u64 = 250_000_000;
const BUY_USDC: u64 = 100_000_000;
const USDC_ASSET_ID: u64 = 2;

const PROFILING_SBF_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/rfq-bench");
const OUTPUT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/BENCHMARK.md");

#[test]
#[ignore = "CU benchmark; slow, needs SBF binaries + prover. Run via just bench-rfq"]
fn bench_cu_rfq() {
    std::env::set_var("SBF_OUT_DIR", PROFILING_SBF_DIR);

    let spp_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);

    let mut mollusk = Mollusk::default();
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&spp_id, "shielded_pool_program");

    let mut bench = CuBenchmark::new(ReadmeConfig {
        title: "RFQ Settlement -- CU Benchmark".into(),
        description:
            "Compute unit profiling for a confidential RFQ settlement, replayed under mollusk. The \
             settlement is a single shielded-pool `transact` co-signed by a maker and a taker that \
             swaps SOL for USDC with no escrow and no custom program: the maker input_utxos one SOL UTXO \
             and receives USDC, the taker input_utxos one USDC UTXO and receives SOL (shape IN2_OUT2, \
             eddsa rail). The shielded-pool program is built with `profile-program`, so its \
             `#[profile]` functions appear in the CU table; the tree account is built directly (the \
             program's `create_tree` init plus the input utxo hashes appended). The section also \
             records the SPP transfer proving time (warm, key already loaded) and the serialized \
             size of the version 1 transaction the settlement is sent as, which states its compute \
             ceilings in the message header and may run to 4096 bytes."
                .into(),
        output_path: OUTPUT_PATH.into(),
        regenerate_command: Some("just bench-rfq".into()),
        ..Default::default()
    });

    spr_test_utils::prover::spawn_workspace_prover(spr_client::IndexerRequirement::Optional);
    bench_settlement(&mut mollusk, &spp_id, &mut bench);

    bench.generate().expect("write BENCHMARK.md");
}

fn bench_settlement(mollusk: &mut Mollusk, spp_id: &Pubkey, bench: &mut CuBenchmark) {
    let tree = spr_interface::pda::tree(BENCH_TREE_ID);
    let maker_payer = Keypair::new();
    let taker_payer = Keypair::new();
    let maker = keypair_from_payer(&maker_payer);
    let taker = keypair_from_payer(&taker_payer);
    let maker_address = maker.shielded_address().expect("maker address");
    let taker_address = taker.shielded_address().expect("taker address");

    let usdc_mint = Address::new_from_array([7u8; 32]);

    let maker_sol_utxo = Utxo {
        owner: maker.signing_pubkey(),
        asset: spr_transaction::Mint::SOL,
        amount: SELL_SOL,
        blinding: random_blinding(),
        ring_program_id: None,
        data: Data::default(),
    };
    let taker_usdc_utxo = Utxo {
        owner: taker.signing_pubkey(),
        asset: spr_transaction::Mint::new(usdc_mint, 2),
        amount: BUY_USDC,
        blinding: random_blinding(),
        ring_program_id: None,
        data: Data::default(),
    };

    let maker_input_utxo: SppProofInputUtxo = spr_test_utils::utxo::wallet(
        maker_sol_utxo,
        &maker.nullifier_key,
        BENCH_TREE_ID,
        0,
        None,
        None,
    )
    .expect("indexed input")
    .into();
    let taker_input_utxo: SppProofInputUtxo = spr_test_utils::utxo::wallet(
        taker_usdc_utxo,
        &taker.nullifier_key,
        BENCH_TREE_ID,
        1,
        None,
        None,
    )
    .expect("indexed input")
    .into();
    let input_utxos = vec![maker_input_utxo, taker_input_utxo];

    let sol_to_taker = SppProofOutputUtxo::new(spr_transaction::Mint::SOL, SELL_SOL, taker_address)
        .expect("sol output");
    let usdc_to_maker = SppProofOutputUtxo::new(
        spr_transaction::Mint::new(usdc_mint, 2),
        BUY_USDC,
        maker_address,
    )
    .expect("usdc output");

    let mut assets = AssetRegistry::default();
    assets
        .insert(USDC_ASSET_ID, usdc_mint)
        .expect("register usdc");

    let mut transaction_outputs = vec![sol_to_taker, usdc_to_maker];
    let blinding_seed = prepare_output_blindings(&input_utxos, &mut transaction_outputs)
        .expect("derive output blindings");
    let transaction_viewing_key =
        get_transaction_viewing_key(&maker, &input_utxos).expect("transaction viewing key");
    let encoded = encrypt_transaction_data(
        &transaction_outputs,
        &transaction_viewing_key,
        BENCH_TREE_ID,
    )
    .expect("encode settlement slots");

    let external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    let payer_address = Address::new_from_array(maker_payer.pubkey().to_bytes());
    let spp_proof_inputs = SppProofInputs {
        input_utxos,
        output_utxos: encoded.output_utxos,
        external_data,
        payer: payer_address,
        blinding_seed,
        output_tree_id: BENCH_TREE_ID,
        cache_accounts: Default::default(),
    };

    let (tree_account, spend_proofs) = tree_fixture(&tree, &spp_proof_inputs);

    let owner_signers = spp_proof_inputs
        .owner_signer_pubkeys()
        .expect("owner signers");
    let (transact, spp_dur) = prove_transact_timed(
        spp_proof_inputs,
        &spend_proofs,
        &[&maker.nullifier_key, &taker.nullifier_key],
    );

    let ix = Transact {
        payer: maker_payer.pubkey(),
        input_trees: vec![tree],
        output_tree: tree,
        owner_signers,
        interface_transfer_accounts: Vec::new(),
        data: transact,
    }
    .instruction();

    let fixtures = vec![
        (tree, tree_account),
        (maker_payer.pubkey(), system_owned_account(100_000_000_000)),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for 'settlement'");
    bench.add_from_entries("settlement", entries);
    bench.add_table("settlement", proving_time_table(spp_dur, None));
    bench.add_table("settlement", tx_size_table(&ix, &maker_payer.pubkey()));
}
