use spr_test_utils::bench::{
    assemble_accounts, keypair_from_payer, prove_transact_timed, proving_time_table,
    system_owned_account, tree_fixture, tx_size_table, BENCH_TREE_ID,
};
use spr_test_utils::utxo::{
    assign_output_blindings, encrypt_transaction_data, get_transaction_viewing_key,
};
use spr_transaction::utxo::SppProofInputUtxo;
use std::time::Instant;

use dynamic_swap_program::{
    instructions::create_escrow::EscrowOpenProof,
    state::{
        discriminator::{ESCROW, PAIR},
        Escrow, Pair,
    },
};
use dynamic_swap_prover::ProofInputUtxo;
use dynamic_swap_sdk::{
    escrow_authority_pda, escrow_pda,
    instructions::{
        create_escrow::{CreateEscrow, EscrowOpenProofInputParams},
        create_pair::CreatePair,
        settle::{settle_blinding_seed, Settle, SettleProofInputParams},
        update_price::UpdatePrice,
    },
    pair_pda,
    prover::DynamicSwapProverClient,
    shared::pad_spp_outputs,
    state::{EscrowTerms, EscrowUtxo, Reservation},
    SettleProof,
};
use light_program_profiler::{
    mollusk::{register_profiling_syscalls, take_profiling_entries},
    report::{CuBenchmark, ReadmeConfig},
};
use mollusk_svm::{result::Check, Mollusk};
use solana_account::Account;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spr_interface::SHIELDED_POOL_PROGRAM_ID;
use spr_keypair::random_blinding;
use spr_program::ShieldedPda;
use spr_transaction::{
    instructions::transact::{asset_field, ExternalData, SppProofInputs, SppProofOutputUtxo},
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    },
    AssetRegistry, Data, Utxo, SOL_MINT,
};

const PROFILING_SBF_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../target/dynamic-swap-bench"
);
const OUTPUT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../BENCHMARK.md");

const SOURCE_ASSET_ID: u64 = 2;
const DESTINATION_ASSET_ID: u64 = 1;
const PRICE: u64 = 5;

// The dynamic-swap program's own PDA state accounts are built directly from
// their `Pod` structs rather than by running the instructions that create
// them: each bench only needs the world "as if" those calls already happened,
// as the tree fixture holds the input UTXOs without replaying a deposit.
fn dynamic_swap_account(bytes: Vec<u8>, program_id: &Pubkey) -> Account {
    Account {
        lamports: 1_000_000_000,
        data: bytes,
        owner: *program_id,
        executable: false,
        rent_epoch: 0,
    }
}

fn pair_fixture(state: Pair, program_id: &Pubkey) -> Account {
    dynamic_swap_account(bytemuck::bytes_of(&state).to_vec(), program_id)
}

fn escrow_fixture(state: Escrow, program_id: &Pubkey) -> Account {
    dynamic_swap_account(bytemuck::bytes_of(&state).to_vec(), program_id)
}

#[test]
#[ignore = "CU benchmark; slow, needs SBF binaries + prover. Run via just bench-dynamic-swap"]
fn bench_cu_dynamic_swap() {
    std::env::set_var("SBF_OUT_DIR", PROFILING_SBF_DIR);

    let dynamic_swap_id = dynamic_swap_program::ID;
    let spp_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);

    let mut mollusk = Mollusk::default();
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&dynamic_swap_id, "dynamic_swap_program");
    mollusk.add_program(&spp_id, "shielded_pool_program");

    let mut bench = CuBenchmark::new(ReadmeConfig {
        title: "Dynamic Swap -- CU Benchmark".into(),
        description: "Compute unit profiling for the dynamic-swap create_pair/update_price/\
             create_escrow/settle instructions, replayed under mollusk. Every PDA account (Pair, \
             Escrow) and the shielded-pool tree account are built directly, as if the prior \
             instruction chain already ran -- only the ONE instruction under \
             measurement is actually replayed. Only the dynamic-swap program is profiled; the \
             shielded-pool program is built plain, so the CU its CPI consumes is charged to the \
             `cpi_spp_transact*` row as a black box and its internal functions do not appear \
             here. update_price never verifies a proof or CPI into SPP at all \
             (the whole point of keeping it cheap); create_escrow and settle each verify their own \
             Groth16 proof and then CPI SPP `transact`, which verifies its own. Each \
             proof-carrying instruction's section also records its proving times (SPP transfer \
             proof plus the dynamic-swap circuit proof) and the serialized size of the version 1 \
             transaction these instructions are sent as, which states its compute ceilings in the \
             message header and may run to 4096 bytes."
            .into(),
        output_path: OUTPUT_PATH.into(),
        regenerate_command: Some("just bench-dynamic-swap".into()),
        ..Default::default()
    });

    spr_test_utils::prover::spawn_workspace_prover(spr_client::IndexerRequirement::Optional);

    bench_create_pair(&mut mollusk, &spp_id, &dynamic_swap_id, &mut bench);
    bench_update_price(&mut mollusk, &spp_id, &dynamic_swap_id, &mut bench);
    bench_create_escrow(&mut mollusk, &spp_id, &dynamic_swap_id, &mut bench);
    bench_settle(&mut mollusk, &spp_id, &dynamic_swap_id, &mut bench);

    bench.generate().expect("write BENCHMARK.md");
}

fn bench_create_pair(
    mollusk: &mut Mollusk,
    spp_id: &Pubkey,
    _dynamic_swap_id: &Pubkey,
    bench: &mut CuBenchmark,
) {
    let authority = Keypair::new();
    let pair = pair_pda(&authority.pubkey(), SOURCE_ASSET_ID, DESTINATION_ASSET_ID);

    let ix = CreatePair {
        payer: authority.pubkey(),
        pair,
        price: PRICE,
        source_asset_id: SOURCE_ASSET_ID,
        destination_asset_id: DESTINATION_ASSET_ID,
        authority_owner_hash: [9u8; 32],
        source_asset: [0u8; 32],
        destination_asset: [0u8; 32],
        escrow_authority_nullifier_pubkey: [9u8; 32],
    }
    .instruction()
    .expect("create_pair instruction");

    let fixtures = vec![
        (authority.pubkey(), system_owned_account(100_000_000_000)),
        (pair, system_owned_account(0)),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for 'create_pair'"
    );
    bench.add_from_entries("create_pair", entries);
    bench.add_table("create_pair", tx_size_table(&ix, &authority.pubkey()));
}

fn bench_update_price(
    mollusk: &mut Mollusk,
    spp_id: &Pubkey,
    dynamic_swap_id: &Pubkey,
    bench: &mut CuBenchmark,
) {
    let authority = Keypair::new();
    let pair = pair_pda(&authority.pubkey(), SOURCE_ASSET_ID, DESTINATION_ASSET_ID);
    let pair_state = Pair {
        discriminator: PAIR,
        bump: 255,
        _pad: [0u8; 6],
        authority: Address::new_from_array(authority.pubkey().to_bytes()),
        source_asset_id: SOURCE_ASSET_ID,
        destination_asset_id: DESTINATION_ASSET_ID,
        price: PRICE,
        authority_owner_hash: [9u8; 32],
        source_asset: [0u8; 32],
        destination_asset: [0u8; 32],
        escrow_authority_nullifier_pubkey: [9u8; 32],
    };

    let ix = UpdatePrice {
        authority: authority.pubkey(),
        pair,
        price: PRICE * 2,
    }
    .instruction()
    .expect("update_price instruction");

    let fixtures = vec![
        (authority.pubkey(), system_owned_account(1_000_000_000)),
        (pair, pair_fixture(pair_state, dynamic_swap_id)),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for 'update_price'"
    );
    bench.add_from_entries("update_price", entries);
    bench.add_table("update_price", tx_size_table(&ix, &authority.pubkey()));
}

fn bench_create_escrow(
    mollusk: &mut Mollusk,
    spp_id: &Pubkey,
    dynamic_swap_id: &Pubkey,
    bench: &mut CuBenchmark,
) {
    const FUNDING_AMOUNT: u64 = 1_000_000_000;
    const ORDER_AMOUNT: u64 = 100_000_000;
    const MAX_PRICE: u64 = PRICE;
    const CREATED_AT: u64 = 1_000;

    let authority_solana = Keypair::new();
    let authority_keypair = keypair_from_payer(&authority_solana);
    let user_solana = Keypair::new();
    let user_keypair = keypair_from_payer(&user_solana);
    let source_asset = Address::new_from_array([2u8; 32]);

    let pair = pair_pda(
        &authority_solana.pubkey(),
        SOURCE_ASSET_ID,
        DESTINATION_ASSET_ID,
    );
    let escrow_owner =
        ShieldedPda::from_viewing_key(escrow_authority_pda(&pair), &authority_keypair.viewing_key)
            .expect("escrow authority identity");
    let tree = spr_interface::pda::tree(BENCH_TREE_ID);

    let source_utxo = Utxo {
        owner: user_keypair.signing_pubkey(),
        asset: spr_transaction::Mint::new(source_asset, SOURCE_ASSET_ID),
        amount: ORDER_AMOUNT,
        blinding: random_blinding(),
        ring_program_id: None,
        data: Data::default(),
    };
    let source_in: SppProofInputUtxo = spr_test_utils::utxo::wallet(
        source_utxo,
        &user_keypair.nullifier_key,
        BENCH_TREE_ID,
        0,
        None,
        None,
    )
    .expect("indexed input")
    .into();

    // The maker funds the reservation with a destination-asset UTXO owned by
    // the escrow authority, which signs the data-bearing outputs through CPI.
    let escrow_address = escrow_owner
        .shielded_address()
        .expect("escrow authority shielded address");
    let maker_funding_utxo = Utxo {
        owner: escrow_address.signing_pubkey,
        asset: spr_transaction::Mint::SOL,
        amount: FUNDING_AMOUNT,
        blinding: random_blinding(),
        ring_program_id: None,
        data: Data::default(),
    };
    let maker_funding: SppProofInputUtxo = spr_test_utils::utxo::wallet(
        maker_funding_utxo,
        escrow_owner.as_ref(),
        BENCH_TREE_ID,
        1,
        None,
        None,
    )
    .expect("indexed input")
    .into();

    let recipient_owner_hash = user_keypair.owner_hash().expect("user owner hash");
    let escrow_terms = EscrowTerms {
        recipient_owner_hash,
        max_price: MAX_PRICE,
    };
    let input_utxos = vec![source_in.clone(), maker_funding.clone()];
    // The circuit derives the seed and the private transaction blinding from
    // this root seed, so both must come from it here too.
    let blinding_seed = random_blinding();
    let first_nullifier = input_utxos.first().expect("first input").nullifier;
    let output_blinding_seed = derive_output_blinding_seed(&first_nullifier, &blinding_seed)
        .expect("output blinding seed");
    let private_tx_blinding =
        derive_private_tx_blinding(&first_nullifier, &blinding_seed).expect("private tx blinding");
    // The final reservation blinding rides in the order UTXO's encrypted note.
    let reservation_blinding =
        derive_transact_output_blinding(&first_nullifier, &output_blinding_seed, 1)
            .expect("reservation blinding");
    let escrow_utxo = EscrowUtxo {
        terms: escrow_terms,
        created_at: CREATED_AT,
        asset: spr_transaction::Mint::new(source_asset, SOURCE_ASSET_ID),
        order_amount: ORDER_AMOUNT,
        blinding: random_blinding(),
    };
    let mut order_out = escrow_utxo
        .output_utxo(&escrow_owner, &reservation_blinding)
        .expect("order_out");
    order_out.blinding =
        derive_transact_output_blinding(&first_nullifier, &output_blinding_seed, 0)
            .expect("order blinding");
    let order_utxo_hash = order_out.hash(BENCH_TREE_ID).expect("order_utxo hash");

    let reserved = ORDER_AMOUNT * MAX_PRICE;
    let reservation = Reservation {
        asset: spr_transaction::Mint::SOL,
        amount: reserved,
        blinding: reservation_blinding,
    };
    let reservation_out = reservation
        .output_utxo(&escrow_owner, order_utxo_hash)
        .expect("reservation_out");

    let mut maker_change = SppProofOutputUtxo::new(
        spr_transaction::Mint::SOL,
        FUNDING_AMOUNT - reserved,
        escrow_address,
    )
    .expect("maker_change");
    maker_change.blinding =
        derive_transact_output_blinding(&first_nullifier, &output_blinding_seed, 2)
            .expect("maker change blinding");

    // Output 1 (reservation_out) is spent only by the program itself (settle),
    // so its ciphertext is dropped.
    const RESERVATION_OUTPUT_INDEX: usize = 1;
    let mut assets = AssetRegistry::default();
    assets
        .insert(SOURCE_ASSET_ID, source_asset)
        .expect("register source asset");
    let viewing_key =
        get_transaction_viewing_key(&user_keypair, &input_utxos).expect("transaction viewing key");
    let encoded = encrypt_transaction_data(
        &[
            order_out.clone(),
            reservation_out.clone(),
            maker_change.clone(),
        ],
        &viewing_key,
        BENCH_TREE_ID,
    )
    .expect("encode outputs");
    let mut outputs = encoded.outputs;
    outputs
        .get_mut(RESERVATION_OUTPUT_INDEX)
        .expect("reservation output index in range")
        .data = None;
    let external_data = ExternalData::new(
        *viewing_key.pubkey().as_bytes(),
        encoded.salt,
        outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    let spp_proof_inputs = SppProofInputs {
        input_utxos,
        output_utxos: pad_spp_outputs(
            encoded.output_utxos,
            &first_nullifier,
            &output_blinding_seed,
        )
        .expect("pad create_escrow outputs"),
        external_data,
        payer: authority_solana.pubkey(),
        blinding_seed,
        output_tree_id: BENCH_TREE_ID,
        cache_accounts: Default::default(),
    };

    let (tree_account, spend_proofs) = tree_fixture(&tree, &spp_proof_inputs);

    let (transact, spp_dur) = prove_transact_timed(
        spp_proof_inputs,
        &spend_proofs,
        &[&user_keypair.nullifier_key, escrow_owner.as_ref()],
    );

    let escrow_authority_owner_hash = escrow_address
        .owner_hash()
        .expect("escrow authority owner hash");
    let source_asset_field = asset_field(&source_asset).expect("source asset field");
    let destination_asset_field = asset_field(&SOL_MINT).expect("destination asset field");
    let proof_inputs = EscrowOpenProofInputParams {
        source_in: source_in.clone(),
        maker_funding: maker_funding.clone(),
        order_out: order_out.clone(),
        reservation_out: reservation_out.clone(),
        maker_change: maker_change.clone(),
        max_price: MAX_PRICE,
        escrow_authority_owner_hash,
        source_asset: source_asset_field,
        destination_asset: destination_asset_field,
        created_at: CREATED_AT,
        order_amount: ORDER_AMOUNT,
        private_tx_blinding,
        output_tree_id: BENCH_TREE_ID,
    }
    .to_proof_inputs()
    .expect("escrow_open proof inputs");
    let circuit_start = Instant::now();
    let order_proof = DynamicSwapProverClient::new()
        .prove_escrow_open(&proof_inputs)
        .expect("prove escrow_open");
    let circuit_dur = circuit_start.elapsed();

    let escrow = escrow_pda(&user_solana.pubkey());
    let ix = CreateEscrow {
        authority: authority_solana.pubkey(),
        owner: user_solana.pubkey(),
        pair,
        escrow,
        tree,
        proof: EscrowOpenProof {
            proof_a: order_proof.proof_a,
            proof_b: order_proof.proof_b,
            proof_c: order_proof.proof_c,
        },
        created_at: CREATED_AT,
        transact,
    }
    .instruction()
    .expect("create_escrow instruction");

    let pair_state = Pair {
        discriminator: PAIR,
        bump: 255,
        _pad: [0u8; 6],
        authority: Address::new_from_array(authority_solana.pubkey().to_bytes()),
        source_asset_id: SOURCE_ASSET_ID,
        destination_asset_id: DESTINATION_ASSET_ID,
        price: PRICE,
        authority_owner_hash: [9u8; 32],
        source_asset: source_asset_field,
        destination_asset: destination_asset_field,
        escrow_authority_nullifier_pubkey: escrow_owner
            .nullifier_pubkey()
            .expect("escrow authority nullifier pubkey"),
    };

    // `created_at` must land within `CREATED_AT_SLOT_TOLERANCE` of the real
    // current slot.
    mollusk.sysvars.clock.slot = CREATED_AT;

    let fixtures = vec![
        (
            authority_solana.pubkey(),
            system_owned_account(100_000_000_000),
        ),
        (user_solana.pubkey(), system_owned_account(1_000_000_000)),
        (pair, pair_fixture(pair_state, dynamic_swap_id)),
        (escrow, system_owned_account(0)),
        (tree, tree_account),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for 'create_escrow'"
    );
    bench.add_from_entries("create_escrow", entries);
    bench.add_table(
        "create_escrow",
        proving_time_table(spp_dur, Some(("Dynamic-swap circuit proof", circuit_dur))),
    );
    bench.add_table(
        "create_escrow",
        tx_size_table(&ix, &authority_solana.pubkey()),
    );
}

fn bench_settle(
    mollusk: &mut Mollusk,
    spp_id: &Pubkey,
    dynamic_swap_id: &Pubkey,
    bench: &mut CuBenchmark,
) {
    const ORDER_AMOUNT: u64 = 100_000_000;
    const MAX_PRICE: u64 = 10;
    const EXECUTION_PRICE: u64 = 5;
    const CREATED_AT: u64 = 1_000;

    let authority_solana = Keypair::new();
    let authority_keypair = keypair_from_payer(&authority_solana);
    let authority_owner_hash = authority_keypair
        .owner_hash()
        .expect("authority owner hash");
    let user_solana = Keypair::new();
    let user_keypair = keypair_from_payer(&user_solana);
    let recipient_owner_hash = user_keypair.owner_hash().expect("user owner hash");
    let source_asset = Address::new_from_array([2u8; 32]);

    let pair = pair_pda(
        &authority_solana.pubkey(),
        SOURCE_ASSET_ID,
        DESTINATION_ASSET_ID,
    );
    let escrow_owner =
        ShieldedPda::from_viewing_key(escrow_authority_pda(&pair), &authority_keypair.viewing_key)
            .expect("escrow authority identity");
    let tree = spr_interface::pda::tree(BENCH_TREE_ID);

    let escrow_terms = EscrowTerms {
        recipient_owner_hash,
        max_price: MAX_PRICE,
    };
    let escrow_utxo = EscrowUtxo {
        terms: escrow_terms,
        created_at: CREATED_AT,
        asset: spr_transaction::Mint::new(source_asset, SOURCE_ASSET_ID),
        order_amount: ORDER_AMOUNT,
        blinding: random_blinding(),
    };
    let order_in = escrow_utxo
        .to_input_utxo(&escrow_owner, BENCH_TREE_ID, 0)
        .expect("order_in");
    let order_in_hash = ProofInputUtxo::try_from(&order_in)
        .expect("order_in proof utxo")
        .hash()
        .expect("order_in hash");

    let reserved = ORDER_AMOUNT * MAX_PRICE;
    let reservation = Reservation {
        asset: spr_transaction::Mint::SOL,
        amount: reserved,
        blinding: random_blinding(),
    };
    let reservation_in = reservation
        .to_input_utxo(&escrow_owner, order_in_hash, BENCH_TREE_ID, 1)
        .expect("reservation_in");
    let reservation_in_hash = ProofInputUtxo::try_from(&reservation_in)
        .expect("reservation_in proof utxo")
        .hash()
        .expect("reservation_in hash");

    let owed = ORDER_AMOUNT * EXECUTION_PRICE;
    let remainder = reserved - owed;

    let authority_address = authority_keypair
        .shielded_address()
        .expect("authority shielded address");
    let recipient_out = SppProofOutputUtxo::new(
        spr_transaction::Mint::SOL,
        owed,
        user_keypair.shielded_address().expect("user address"),
    )
    .expect("recipient_out");
    let maker_counter =
        SppProofOutputUtxo::new(spr_transaction::Mint::SOL, remainder, authority_address)
            .expect("maker_counter");
    let maker_source = SppProofOutputUtxo::new(
        spr_transaction::Mint::new(source_asset, SOURCE_ASSET_ID),
        ORDER_AMOUNT,
        authority_address,
    )
    .expect("maker_source");

    let input_utxos = vec![order_in.clone(), reservation_in.clone()];
    let blinding_seed =
        settle_blinding_seed(&order_in.utxo.blinding, &reservation_in.utxo.blinding)
            .expect("settlement blinding seed");
    let settle_first_nullifier = input_utxos.first().expect("first input").nullifier;
    let output_blinding_seed = derive_output_blinding_seed(&settle_first_nullifier, &blinding_seed)
        .expect("output blinding seed");
    let private_tx_blinding = derive_private_tx_blinding(&settle_first_nullifier, &blinding_seed)
        .expect("private tx blinding");
    let mut transaction_outputs = vec![recipient_out, maker_counter, maker_source];
    assign_output_blindings(
        &mut transaction_outputs,
        &settle_first_nullifier,
        &output_blinding_seed,
    )
    .expect("derive settle output blindings");
    let [recipient_out, maker_counter, maker_source]: [_; 3] = transaction_outputs
        .try_into()
        .expect("settle transaction has three outputs");

    // maker_counter (output index 1) returns to the maker and is tracked
    // off-chain, so its ciphertext is dropped.
    const MAKER_COUNTER_INDEX: usize = 1;
    let mut assets = AssetRegistry::default();
    assets
        .insert(SOURCE_ASSET_ID, source_asset)
        .expect("register source asset");
    let viewing_key = get_transaction_viewing_key(&authority_keypair, &input_utxos)
        .expect("transaction viewing key");
    let encoded = encrypt_transaction_data(
        &[
            recipient_out.clone(),
            maker_counter.clone(),
            maker_source.clone(),
        ],
        &viewing_key,
        BENCH_TREE_ID,
    )
    .expect("encode outputs");
    let mut outputs = encoded.outputs;
    outputs
        .get_mut(MAKER_COUNTER_INDEX)
        .expect("maker_counter output index in range")
        .data = None;
    let external_data = ExternalData::new(
        *viewing_key.pubkey().as_bytes(),
        encoded.salt,
        outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    let spp_proof_inputs = SppProofInputs {
        input_utxos,
        output_utxos: pad_spp_outputs(
            encoded.output_utxos,
            &settle_first_nullifier,
            &output_blinding_seed,
        )
        .expect("pad settle outputs"),
        external_data,
        payer: authority_solana.pubkey(),
        blinding_seed,
        output_tree_id: BENCH_TREE_ID,
        cache_accounts: Default::default(),
    };

    let (tree_account, spend_proofs) = tree_fixture(&tree, &spp_proof_inputs);

    let (transact, spp_dur) =
        prove_transact_timed(spp_proof_inputs, &spend_proofs, &[escrow_owner.as_ref()]);

    let proof_inputs = SettleProofInputParams {
        order_in: order_in.clone(),
        reservation_in: reservation_in.clone(),
        recipient_out: recipient_out.clone(),
        maker_counter: maker_counter.clone(),
        maker_source: maker_source.clone(),
        execution_price: EXECUTION_PRICE,
        max_price: MAX_PRICE,
        created_at: CREATED_AT,
        order_amount: ORDER_AMOUNT,
        escrow_utxo_hash: order_in_hash,
        reservation_utxo_hash: reservation_in_hash,
        recipient_owner_hash,
        authority_owner_hash,
        private_tx_blinding,
        output_tree_id: BENCH_TREE_ID,
    }
    .to_proof_inputs()
    .expect("escrow_settle proof inputs");
    let circuit_start = Instant::now();
    let order_proof = DynamicSwapProverClient::new()
        .prove_escrow_settle(&proof_inputs)
        .expect("prove escrow_settle");
    let circuit_dur = circuit_start.elapsed();

    let ix = Settle {
        caller: authority_solana.pubkey(),
        pair,
        escrow: escrow_pda(&user_solana.pubkey()),
        rent_recipient: user_solana.pubkey(),
        tree,
        proof: SettleProof {
            proof_a: order_proof.proof_a,
            proof_b: order_proof.proof_b,
            proof_c: order_proof.proof_c,
        },
        transact,
    }
    .instruction()
    .expect("settle instruction");

    let pair_state = Pair {
        discriminator: PAIR,
        bump: 255,
        _pad: [0u8; 6],
        authority: Address::new_from_array(authority_solana.pubkey().to_bytes()),
        source_asset_id: SOURCE_ASSET_ID,
        destination_asset_id: DESTINATION_ASSET_ID,
        price: EXECUTION_PRICE,
        authority_owner_hash,
        source_asset: [0u8; 32],
        destination_asset: [0u8; 32],
        escrow_authority_nullifier_pubkey: escrow_owner
            .nullifier_pubkey()
            .expect("escrow authority nullifier pubkey"),
    };
    let escrow_state = Escrow {
        discriminator: ESCROW,
        bump: 255,
        _pad: [0u8; 6],
        pair: Address::new_from_array(pair.to_bytes()),
        escrow_utxo_hash: order_in_hash,
        reservation_utxo_hash: reservation_in_hash,
        owner: Address::new_from_array(user_solana.pubkey().to_bytes()),
        created_at: CREATED_AT,
        execution_price: EXECUTION_PRICE,
    };

    let fixtures = vec![
        (
            authority_solana.pubkey(),
            system_owned_account(100_000_000_000),
        ),
        (user_solana.pubkey(), system_owned_account(1_000_000_000)),
        (pair, pair_fixture(pair_state, dynamic_swap_id)),
        (
            escrow_pda(&user_solana.pubkey()),
            escrow_fixture(escrow_state, dynamic_swap_id),
        ),
        (tree, tree_account),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for 'settle'");
    bench.add_from_entries("settle", entries);
    bench.add_table(
        "settle",
        proving_time_table(spp_dur, Some(("Dynamic-swap circuit proof", circuit_dur))),
    );
    bench.add_table("settle", tx_size_table(&ix, &authority_solana.pubkey()));
}
