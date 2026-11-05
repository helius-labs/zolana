use spr_test_utils::bench::{
    assemble_accounts, keypair_from_payer, prove_transact_timed, proving_time_table,
    system_owned_account, tree_fixture, tx_size_table, BENCH_TREE_ID,
};
use spr_test_utils::utxo::{
    encrypt_transaction_data, get_transaction_viewing_key, prepare_output_blindings,
};
use spr_transaction::utxo::SppProofInputUtxo;
use std::time::Instant;

use light_program_profiler::{
    mollusk::{register_profiling_syscalls, take_profiling_entries},
    report::{CuBenchmark, ReadmeConfig},
};
use mollusk_svm::{result::Check, Mollusk};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spr_interface::{
    instruction::instruction_data::transact::{OwnerTag, TransactOutput},
    SHIELDED_POOL_PROGRAM_ID,
};
use spr_keypair::{random_blinding, ShieldedKeypair};
use spr_transaction::{
    instructions::transact::{
        ConfidentialTransaction, ExternalData, SppProofInputs, SppProofOutputUtxo,
    },
    Data, Utxo, SOL_ASSET_ID, SOL_MINT,
};
use swap_prover::{CircuitId, PROVER};
use swap_sdk::{
    instructions::{
        cancel::{Cancel, CancelProofInputParams},
        make::{Make, MakeProofInputParams, OrderMarker, SppTxHashes},
        take::{take_blinding_seed, Take, TakeProofInputParams},
        take_verifiable_encryption::{
            TakeVerifiableEncryption, TakeVerifiableEncryptionProofInputParams,
        },
    },
    prover::SwapProverClient,
    shared::input_sum,
    state::{OrderTerms, OrderUtxo},
};

const PROFILING_SBF_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../target/swap-bench");
const OUTPUT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../BENCHMARK.md");

#[test]
#[ignore = "CU benchmark; slow, needs SBF binaries + prover. Run via just bench-swap"]
fn bench_cu_swap() {
    std::env::set_var("SBF_OUT_DIR", PROFILING_SBF_DIR);

    let swap_id = swap_program::ID;
    let spp_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);

    let mut mollusk = Mollusk::default();
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&swap_id, "swap_program");
    mollusk.add_program(&spp_id, "shielded_pool_program");

    let mut bench = CuBenchmark::new(ReadmeConfig {
        title: "Confidential Swap -- CU Benchmark".into(),
        description:
            "Compute unit profiling for the confidential swap make/take/take_verifiable_encryption/cancel \
             instructions, replayed under mollusk. The shielded-pool tree account is built directly (the \
             program's `create_tree` init plus the input utxo hashes appended), and each \
             instruction hashes its public input, verifies its own Groth16 proof, then CPIs SPP \
             `transact` (the `cpi_spp_transact*` row). Only the swap program is profiled; the \
             shielded-pool program is built plain, so the CU its CPI consumes is charged to the \
             `cpi_spp_transact*` row as a black box and its internal functions do not appear \
             here. Each instruction section also records its proving times (SPP transfer proof \
             plus swap circuit proof) and the serialized size of the version 1 transaction these \
             instructions are sent as, which states its compute ceilings in the message header and \
             may run to 4096 bytes."
                .into(),
        output_path: OUTPUT_PATH.into(),
        regenerate_command: Some("just bench-swap".into()),
        ..Default::default()
    });

    spr_test_utils::prover::spawn_workspace_prover(spr_client::IndexerRequirement::Optional);
    PROVER.preload(CircuitId::Make).expect("preload make keys");
    PROVER.preload(CircuitId::Take).expect("preload take keys");
    PROVER
        .preload(CircuitId::TakeVerifiableEncryption)
        .expect("preload take_verifiable_encryption keys");
    PROVER
        .preload(CircuitId::Cancel)
        .expect("preload cancel keys");

    bench_make(&mut mollusk, &spp_id, &mut bench);
    bench_take_derived(&mut mollusk, &spp_id, &mut bench);
    bench_take(&mut mollusk, &spp_id, &mut bench);
    bench_cancel(&mut mollusk, &spp_id, &mut bench);

    bench.generate().expect("write BENCHMARK.md");
}

fn bench_make(mollusk: &mut Mollusk, spp_id: &Pubkey, bench: &mut CuBenchmark) {
    const INPUT_AMOUNT: u64 = 1_000_000;
    const SOURCE_AMOUNT: u64 = 400_000;
    const EXPIRY: u64 = 1_900_000_000;

    let tree = spr_interface::pda::tree(BENCH_TREE_ID);
    let payer = Keypair::new();
    let maker = keypair_from_payer(&payer);

    let input_blinding = random_blinding();
    let input_utxo = Utxo {
        owner: maker.signing_pubkey(),
        asset: spr_transaction::Mint::SOL,
        amount: INPUT_AMOUNT,
        blinding: input_blinding,
        ring_program_id: None,
        data: Data::default(),
    };

    let taker =
        ShieldedKeypair::from_keypair(&Keypair::new_from_array([0x4d; 32])).expect("taker keypair");
    let taker_address = taker.shielded_address().expect("taker address");
    let terms = OrderTerms {
        destination_mint: Address::new_from_array([7u8; 32]),
        destination_amount: 250,
        destination: maker.shielded_address().expect("maker address"),
        taker: Address::new_from_array(taker.signing_pubkey().as_ed25519().expect("taker pubkey")),
        expiry: EXPIRY,
        take_mode: swap_prover::TAKE_MODE_VERIFIABLE,
    };
    let mut order_utxo = OrderUtxo {
        terms,
        blinding: random_blinding(),
        source_mint: spr_transaction::Mint::SOL,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: 2,
    };
    let order_output_utxo = order_utxo
        .output_utxo(taker_address.viewing_pubkey)
        .expect("order output");

    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let input_utxo: SppProofInputUtxo = spr_test_utils::utxo::wallet(
        input_utxo,
        &maker.nullifier_key,
        BENCH_TREE_ID,
        0,
        None,
        None,
    )
    .expect("indexed input")
    .into();
    let input_utxos = vec![
        input_utxo,
        SppProofInputUtxo::dummy(BENCH_TREE_ID).expect("dummy"),
    ];

    let order_utxo_asset = order_output_utxo.asset;
    let leftover =
        input_sum(&input_utxos, &order_utxo_asset.asset) - i128::from(order_output_utxo.amount);
    let change_amount = u64::try_from(leftover).expect("insufficient order balance");
    let change = SppProofOutputUtxo::new(
        order_utxo_asset,
        change_amount,
        maker.shielded_address().expect("maker address"),
    )
    .expect("change output");
    let mut transaction_outputs = vec![change, order_output_utxo];
    let blinding_seed = prepare_output_blindings(&input_utxos, &mut transaction_outputs)
        .expect("derive make output blindings");
    let [change, order_output_utxo]: [_; 2] = transaction_outputs
        .try_into()
        .expect("make transaction has two outputs");
    order_utxo.blinding = order_output_utxo.blinding;

    let order_utxo_hash = order_output_utxo
        .hash(BENCH_TREE_ID)
        .expect("order output hash");
    let marker_message = OrderMarker {
        order_utxo_hash,
        maker_pubkey: payer.pubkey(),
        taker_address,
    }
    .message()
    .expect("marker message");

    let transaction_viewing_key =
        get_transaction_viewing_key(&maker, &input_utxos).expect("make transaction viewing key");

    let encoded = encrypt_transaction_data(
        &[change.clone(), order_output_utxo],
        &transaction_viewing_key,
        BENCH_TREE_ID,
    )
    .expect("encode make slots");

    let external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![marker_message],
    );
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

    let make_proof_inputs = MakeProofInputParams {
        order_utxo,
        change,
        spp_tx_hashes: SppTxHashes::new(&spp_proof_inputs).expect("spp tx hashes"),
    };

    let swap_prover_client = SwapProverClient::new();
    let (transact, spp_dur) =
        prove_transact_timed(spp_proof_inputs, &spend_proofs, &[&maker.nullifier_key]);
    let swap_prove_start = Instant::now();
    let make_proof = swap_prover_client
        .prove_make(
            &make_proof_inputs
                .to_proof_inputs()
                .expect("make proof inputs"),
        )
        .expect("swap make prove");
    let swap_dur = swap_prove_start.elapsed();

    let ix = Make {
        payer: payer.pubkey(),
        tree,
        make_proof: make_proof.into(),
        spp_proof: transact,
    }
    .instruction()
    .expect("make instruction");

    let fixtures = vec![
        (tree, tree_account),
        (payer.pubkey(), system_owned_account(100_000_000_000)),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for 'make'");
    bench.add_from_entries("make", entries);
    bench.add_table(
        "make",
        proving_time_table(spp_dur, Some(("Swap circuit proof", swap_dur))),
    );
    bench.add_table("make", tx_size_table(&ix, &payer.pubkey()));
}

fn bench_take_derived(mollusk: &mut Mollusk, spp_id: &Pubkey, bench: &mut CuBenchmark) {
    const SOURCE_AMOUNT: u64 = 400_000;
    const DESTINATION_AMOUNT: u64 = 250;
    const EXPIRY: u64 = 1_900_000_000;

    let tree = spr_interface::pda::tree(BENCH_TREE_ID);
    let taker_payer = Keypair::new();
    let taker = keypair_from_payer(&taker_payer);
    let taker_address = taker.shielded_address().expect("taker address");
    let maker =
        ShieldedKeypair::from_keypair(&Keypair::new_from_array([0x51; 32])).expect("maker keypair");
    let maker_address = maker.shielded_address().expect("maker address");

    let terms = OrderTerms {
        destination_mint: SOL_MINT,
        destination_amount: DESTINATION_AMOUNT,
        destination: maker_address,
        taker: Address::new_from_array(taker.signing_pubkey().as_ed25519().expect("taker pubkey")),
        expiry: EXPIRY,
        take_mode: swap_prover::TAKE_MODE_DERIVED,
    };
    let order_utxo = OrderUtxo {
        terms,
        blinding: random_blinding(),
        source_mint: spr_transaction::Mint::SOL,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: SOL_ASSET_ID,
    };

    let taker_in_blinding = random_blinding();
    let source_output_blinding = random_blinding();

    let taker_in = order_utxo.destination_output(taker_address, taker_in_blinding);
    let source_output = order_utxo.source_output(taker_address, source_output_blinding);
    let destination_output = order_utxo.destination_output(maker_address, random_blinding());

    let order_input_utxo = order_utxo
        .to_input_utxo(BENCH_TREE_ID, 0)
        .expect("order input_utxo");
    let taker_utxo = Utxo {
        owner: taker.signing_pubkey(),
        asset: spr_transaction::Mint::SOL,
        amount: DESTINATION_AMOUNT,
        blinding: taker_in_blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    let taker_input_utxo: SppProofInputUtxo = spr_test_utils::utxo::wallet(
        taker_utxo,
        &taker.nullifier_key,
        BENCH_TREE_ID,
        1,
        None,
        None,
    )
    .expect("indexed input")
    .into();

    let payer_address = Address::new_from_array(taker_payer.pubkey().to_bytes());
    let input_utxos = vec![order_input_utxo, taker_input_utxo];
    let mut transaction_outputs = vec![source_output, destination_output];
    let blinding_seed = take_blinding_seed(&order_utxo.blinding).expect("take blinding seed");
    let first_nullifier = input_utxos.first().expect("order input").nullifier();
    let seed = spr_transaction::derive_output_blinding_seed(&first_nullifier, &blinding_seed)
        .expect("take seed");
    spr_test_utils::utxo::assign_output_blindings(
        &mut transaction_outputs,
        &first_nullifier,
        &seed,
    )
    .expect("derive take output blindings");
    let [source_output, destination_output]: [_; 2] = transaction_outputs
        .try_into()
        .expect("take transaction has two outputs");
    let transaction_viewing_key =
        get_transaction_viewing_key(&taker, &input_utxos).expect("take transaction viewing key");

    let encoded = encrypt_transaction_data(
        &[source_output.clone(), destination_output.clone()],
        &transaction_viewing_key,
        BENCH_TREE_ID,
    )
    .expect("encode take slots");

    let mut external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    external_data.expiry_unix_ts = order_utxo.terms.expiry;
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

    let take_proof_inputs = TakeProofInputParams {
        order_utxo,
        taker_in,
        source_output,
        destination_output,
        private_tx_blinding: spp_proof_inputs
            .private_tx_blinding()
            .expect("private tx blinding"),
        input_tree_id: BENCH_TREE_ID,
        output_tree_id: BENCH_TREE_ID,
    };

    let swap_prover_client = SwapProverClient::new();
    let (transact, spp_dur) = prove_transact_timed(
        spp_proof_inputs,
        &spend_proofs,
        &[
            &spr_keypair::NullifierKey::from_secret([0; 31]),
            &taker.nullifier_key,
        ],
    );
    let swap_prove_start = Instant::now();
    let take_proof = swap_prover_client
        .prove_take(
            &take_proof_inputs
                .to_proof_inputs()
                .expect("take proof inputs"),
        )
        .expect("swap take prove");
    let swap_dur = swap_prove_start.elapsed();

    let ix = Take {
        payer: taker_payer.pubkey(),
        tree,
        take_proof: take_proof.into(),
        spp_proof: transact,
    }
    .instruction()
    .expect("take instruction");

    let fixtures = vec![
        (tree, tree_account),
        (taker_payer.pubkey(), system_owned_account(100_000_000_000)),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for 'take'");
    bench.add_from_entries("take", entries);
    bench.add_table(
        "take",
        proving_time_table(spp_dur, Some(("Swap circuit proof", swap_dur))),
    );
    bench.add_table("take", tx_size_table(&ix, &taker_payer.pubkey()));
}

fn bench_take(mollusk: &mut Mollusk, spp_id: &Pubkey, bench: &mut CuBenchmark) {
    const SOURCE_AMOUNT: u64 = 400_000;
    const DESTINATION_AMOUNT: u64 = 250;
    const EXPIRY: u64 = 1_900_000_000;

    let tree = spr_interface::pda::tree(BENCH_TREE_ID);
    let taker_payer = Keypair::new();
    let taker = keypair_from_payer(&taker_payer);
    let taker_address = taker.shielded_address().expect("taker address");
    let maker =
        ShieldedKeypair::from_keypair(&Keypair::new_from_array([0x51; 32])).expect("maker keypair");
    let maker_address = maker.shielded_address().expect("maker address");

    let terms = OrderTerms {
        destination_mint: SOL_MINT,
        destination_amount: DESTINATION_AMOUNT,
        destination: maker_address,
        taker: Address::new_from_array(taker.signing_pubkey().as_ed25519().expect("taker pubkey")),
        expiry: EXPIRY,
        take_mode: swap_prover::TAKE_MODE_VERIFIABLE,
    };
    let order_utxo = OrderUtxo {
        terms,
        blinding: random_blinding(),
        source_mint: spr_transaction::Mint::SOL,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: SOL_ASSET_ID,
    };

    let taker_in_blinding = random_blinding();
    let destination_output_blinding = random_blinding();
    let source_output_blinding = random_blinding();

    let taker_in = order_utxo.destination_output(taker_address, taker_in_blinding);
    let source_output = order_utxo.source_output(taker_address, source_output_blinding);
    let destination_output =
        order_utxo.destination_output(maker_address, destination_output_blinding);
    let order_input_utxo = order_utxo
        .to_input_utxo(BENCH_TREE_ID, 0)
        .expect("order input_utxo");
    let taker_utxo = Utxo {
        owner: taker.signing_pubkey(),
        asset: spr_transaction::Mint::SOL,
        amount: DESTINATION_AMOUNT,
        blinding: taker_in_blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    let taker_input_utxo: SppProofInputUtxo = spr_test_utils::utxo::wallet(
        taker_utxo,
        &taker.nullifier_key,
        BENCH_TREE_ID,
        1,
        None,
        None,
    )
    .expect("indexed input")
    .into();

    let payer_address = Address::new_from_array(taker_payer.pubkey().to_bytes());
    let destination_view_tag = maker_address
        .signing_pubkey
        .confidential_view_tag()
        .expect("maker view tag");
    let input_utxos = vec![order_input_utxo, taker_input_utxo];
    let mut transaction_outputs = vec![source_output, destination_output];
    let blinding_seed = prepare_output_blindings(&input_utxos, &mut transaction_outputs)
        .expect("derive verifiable take output blindings");
    let [source_output, destination_output]: [_; 2] = transaction_outputs
        .try_into()
        .expect("take transaction has two outputs");
    let destination_ciphertext = order_utxo
        .destination_ciphertext(&destination_output)
        .expect("destination ciphertext");
    let transaction_viewing_key =
        get_transaction_viewing_key(&taker, &input_utxos).expect("take transaction viewing key");

    let mut encoded = encrypt_transaction_data(
        std::slice::from_ref(&source_output),
        &transaction_viewing_key,
        BENCH_TREE_ID,
    )
    .expect("encode take source slot");
    let destination_utxo_hash = destination_output
        .hash(BENCH_TREE_ID)
        .expect("take output hash");
    encoded.outputs.push(TransactOutput {
        utxo_hash: destination_utxo_hash,
        owner_tag: OwnerTag::Inline(destination_view_tag),
        data: Some(destination_ciphertext),
    });
    encoded.resolved_owner_tags.push(destination_view_tag);
    encoded.output_utxos.push(destination_output.clone());

    let mut external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    external_data.expiry_unix_ts = order_utxo.terms.expiry;
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

    let take_proof_inputs = TakeVerifiableEncryptionProofInputParams {
        order_utxo,
        taker_in,
        source_output,
        destination_output,
        private_tx_blinding: spp_proof_inputs
            .private_tx_blinding()
            .expect("private tx blinding"),
        input_tree_id: BENCH_TREE_ID,
        output_tree_id: BENCH_TREE_ID,
    };

    let swap_prover_client = SwapProverClient::new();
    let (transact, spp_dur) = prove_transact_timed(
        spp_proof_inputs,
        &spend_proofs,
        &[
            &spr_keypair::NullifierKey::from_secret([0; 31]),
            &taker.nullifier_key,
        ],
    );
    let swap_prove_start = Instant::now();
    let take_proof = swap_prover_client
        .prove_take_verifiable_encryption(
            &take_proof_inputs
                .to_proof_inputs()
                .expect("take proof inputs"),
        )
        .expect("swap take prove");
    let swap_dur = swap_prove_start.elapsed();

    let ix = TakeVerifiableEncryption {
        payer: taker_payer.pubkey(),
        tree,
        take_proof: take_proof
            .try_into()
            .expect("tve proof carries a BSB22 commitment"),
        spp_proof: transact,
    }
    .instruction()
    .expect("take_verifiable_encryption instruction");

    let fixtures = vec![
        (tree, tree_account),
        (taker_payer.pubkey(), system_owned_account(100_000_000_000)),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for 'take_verifiable_encryption'"
    );
    bench.add_from_entries("take_verifiable_encryption", entries);
    bench.add_table(
        "take_verifiable_encryption",
        proving_time_table(spp_dur, Some(("Swap circuit proof", swap_dur))),
    );
    bench.add_table(
        "take_verifiable_encryption",
        tx_size_table(&ix, &taker_payer.pubkey()),
    );
}

fn bench_cancel(mollusk: &mut Mollusk, spp_id: &Pubkey, bench: &mut CuBenchmark) {
    const SOURCE_AMOUNT: u64 = 400_000;
    const ORDER_EXPIRY: u64 = 1_000_000;
    const SPP_RELAYER_DEADLINE: u64 = u64::MAX;

    let tree = spr_interface::pda::tree(BENCH_TREE_ID);
    let maker_payer = Keypair::new();
    let maker = keypair_from_payer(&maker_payer);
    let maker_address = maker.shielded_address().expect("maker address");
    let taker =
        ShieldedKeypair::from_keypair(&Keypair::new_from_array([0x4d; 32])).expect("taker keypair");
    let taker_viewing_pubkey = taker
        .shielded_address()
        .expect("taker address")
        .viewing_pubkey;
    let terms = OrderTerms {
        destination_mint: Address::new_from_array([7u8; 32]),
        destination_amount: 250,
        destination: maker_address,
        taker: Address::new_from_array(taker.signing_pubkey().as_ed25519().expect("taker pubkey")),
        expiry: ORDER_EXPIRY,
        take_mode: swap_prover::TAKE_MODE_VERIFIABLE,
    };
    let order_utxo = OrderUtxo {
        terms,
        blinding: random_blinding(),
        source_mint: spr_transaction::Mint::SOL,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: 2,
    };
    let source_output_blinding = random_blinding();

    let source_output = order_utxo.source_output(maker_address, source_output_blinding);

    let order_input_utxo = order_utxo
        .to_input_utxo(BENCH_TREE_ID, 0)
        .expect("order input_utxo");

    let payer_address = Address::new_from_array(maker_payer.pubkey().to_bytes());
    let mut cancel =
        ConfidentialTransaction::from_proof_inputs_compact(vec![order_input_utxo], payer_address)
            .and_then(|cancel| cancel.with_output_tree_id(BENCH_TREE_ID))
            .expect("cancel transaction");
    cancel
        .add_output_utxo(source_output)
        .expect("cancel source output");
    let mut spp_proof_inputs = cancel.encrypt(&maker).expect("encrypt cancel");
    spp_proof_inputs.external_data.expiry_unix_ts = SPP_RELAYER_DEADLINE;
    // Declared outputs keep their slots, so slot 0 is the blinded source output.
    let source_output = spp_proof_inputs
        .output_utxos
        .first()
        .cloned()
        .expect("cancel source output slot");

    let (tree_account, spend_proofs) = tree_fixture(&tree, &spp_proof_inputs);

    let cancel_proof_inputs = CancelProofInputParams {
        order_utxo: order_utxo.clone(),
        taker_viewing_pubkey,
        source_output,
        private_tx_blinding: spp_proof_inputs
            .private_tx_blinding()
            .expect("private tx blinding"),
        input_tree_id: BENCH_TREE_ID,
        output_tree_id: BENCH_TREE_ID,
    };

    let swap_prover_client = SwapProverClient::new();
    let (transact, spp_dur) = prove_transact_timed(
        spp_proof_inputs,
        &spend_proofs,
        &[&spr_keypair::NullifierKey::from_secret([0; 31])],
    );
    let swap_prove_start = Instant::now();
    let cancel_proof = swap_prover_client
        .prove_cancel(
            &cancel_proof_inputs
                .to_proof_inputs()
                .expect("cancel proof inputs"),
        )
        .expect("swap cancel prove");
    let swap_dur = swap_prove_start.elapsed();

    let maker_signer = Pubkey::new_from_array(
        maker_address
            .signing_pubkey
            .as_ed25519()
            .expect("maker ed25519"),
    );
    let ix = Cancel {
        maker: maker_signer,
        payer: maker_payer.pubkey(),
        tree,
        cancel_proof: cancel_proof.into(),
        order_expiry: order_utxo.terms.expiry,
        spp_proof: transact,
    }
    .instruction()
    .expect("cancel instruction");

    mollusk.sysvars.clock.unix_timestamp = ORDER_EXPIRY as i64 + 1;

    let fixtures = vec![
        (tree, tree_account),
        (maker_payer.pubkey(), system_owned_account(100_000_000_000)),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for 'cancel'");
    bench.add_from_entries("cancel", entries);
    bench.add_table(
        "cancel",
        proving_time_table(spp_dur, Some(("Swap circuit proof", swap_dur))),
    );
    bench.add_table("cancel", tx_size_table(&ix, &maker_payer.pubkey()));
}
