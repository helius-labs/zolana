use std::time::{Duration, Instant};

use light_program_profiler::{
    mollusk::{register_profiling_syscalls, take_profiling_entries},
    report::{CuBenchmark, ReadmeConfig, SectionTable},
};
use mollusk_solana_account::Account as MolluskAccount;
use mollusk_solana_instruction::{
    AccountMeta as MolluskAccountMeta, Instruction as MolluskInstruction,
};
use mollusk_solana_pubkey::Pubkey as MolluskPubkey;
use mollusk_svm::{program::loader_keys::LOADER_V3, result::Check, Mollusk};
use num_bigint::BigUint;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use swap_prover::{preload, CircuitId};
use swap_sdk::{
    instructions::{
        cancel::{Cancel, CancelProofInputParams},
        make::{Make, MakeProofInputParams, OrderMarker, SppTxHashes},
        take::{Take, TakeProofInputParams},
        take_verifiable_encryption::{
            TakeVerifiableEncryption, TakeVerifiableEncryptionProofInputParams,
        },
    },
    prover::SwapProverClient,
    shared::input_sum,
    state::{OrderTerms, OrderUtxo},
};
use zolana_client::{
    MerkleContext, MerkleProof, NonInclusionProof, ProverClient, SpendProof, NULLIFIER_TREE_HEIGHT,
    STATE_TREE_HEIGHT,
};
use zolana_hasher::Poseidon;
use zolana_interface::{
    instruction::instruction_data::transact::{OwnerTag, TransactIxData, TransactOutput},
    state::{
        address_tree_params, discriminator::TREE_ACCOUNT_DISCRIMINATOR, tree_account_size,
        STATE_HEIGHT,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, ShieldedKeypair, ViewingKey};
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};
use zolana_transaction::{
    instructions::{
        transact::{
            encrypt_transaction_data, get_transaction_viewing_key,
            spp_proof_inputs::BN254_MODULUS_DEC, ExternalData, SppProofInputs, SppProofOutputUtxo,
        },
        types::SppProofInputUtxo,
    },
    AssetRegistry, Data, Utxo, SOL_ASSET_ID, SOL_MINT,
};
use zolana_tree::TreeAccount;

const PROFILING_SBF_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../target/swap-bench");
const OUTPUT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../BENCHMARK.md");
const PROVER_KEYS_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../prover/server/proving-keys"
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
            .map(|meta| MolluskAccountMeta {
                pubkey: to_mollusk_pubkey(&meta.pubkey),
                is_signer: meta.is_signer,
                is_writable: meta.is_writable,
            })
            .collect(),
        data: ix.data.clone(),
    }
}

fn mollusk_program_account(program_id: &MolluskPubkey) -> (MolluskPubkey, MolluskAccount) {
    let account = mollusk_svm::program::create_program_account_loader_v3(program_id);
    (*program_id, account)
}

fn system_owned_account(lamports: u64) -> MolluskAccount {
    MolluskAccount {
        lamports,
        data: Vec::new(),
        owner: MolluskPubkey::new_from_array([0u8; 32]),
        executable: false,
        rent_epoch: 0,
    }
}

fn build_tree_fixture(
    tree: &Pubkey,
    leaves: &[[u8; 32]],
) -> (MolluskAccount, [u8; 32], [u8; 32], u16) {
    let mut tree_account_bytes = vec![0u8; tree_account_size()];
    let root_index = leaves.len() as u16;
    let (utxo_root, nullifier_root) = {
        let mut account = TreeAccount::init(
            &mut tree_account_bytes,
            TREE_ACCOUNT_DISCRIMINATOR,
            STATE_HEIGHT as u8,
            [1u8; 32],
            tree.to_bytes(),
            address_tree_params(),
        )
        .expect("init tree account");
        for leaf in leaves {
            account.utxo_tree().append(*leaf);
        }
        (
            account.get_utxo_tree_root(root_index).expect("utxo root"),
            account.get_nullifier_tree_root(0).expect("nullifier root"),
        )
    };
    let fixture = MolluskAccount {
        lamports: 1_000_000_000_000,
        data: tree_account_bytes,
        owner: MolluskPubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        executable: false,
        rent_epoch: 0,
    };
    (fixture, utxo_root, nullifier_root, root_index)
}

fn local_state_tree(leaves: &[[u8; 32]]) -> MerkleTree<Poseidon> {
    let mut tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    for leaf in leaves {
        tree.append(leaf).expect("append state leaf");
    }
    tree
}

fn nullifier_tree() -> IndexedMerkleTree<Poseidon, usize> {
    let modulus_minus_one =
        BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10).expect("parse bn254 modulus") - 1u32;
    IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(
        NULLIFIER_TREE_HEIGHT,
        0,
        modulus_minus_one,
    )
    .expect("nullifier tree")
}

fn build_spend_proofs(
    tree: &Pubkey,
    state_tree: &MerkleTree<Poseidon>,
    nf_tree: &IndexedMerkleTree<Poseidon, usize>,
    commitments: &[zolana_transaction::instructions::types::InputUtxoContext],
    utxo_root: [u8; 32],
    nullifier_root: [u8; 32],
    root_index: u16,
) -> Vec<SpendProof> {
    let merkle_context = MerkleContext {
        tree_type: 0,
        tree: Address::new_from_array(tree.to_bytes()),
    };
    commitments
        .iter()
        .enumerate()
        .map(|(leaf_index, commitment)| {
            let state_path = state_tree
                .get_proof_of_leaf(leaf_index, true)
                .expect("state proof")
                .to_vec();
            let nf = nf_tree
                .get_non_inclusion_proof(&BigUint::from_bytes_be(&commitment.nullifier))
                .expect("non inclusion proof");
            SpendProof {
                state: MerkleProof {
                    leaf: commitment.utxo_hash,
                    merkle_context: merkle_context.clone(),
                    path: state_path,
                    leaf_index: leaf_index as u64,
                    root: utxo_root,
                    root_seq: 0,
                    root_index,
                },
                nullifier: NonInclusionProof {
                    leaf: commitment.nullifier,
                    merkle_context: merkle_context.clone(),
                    path: nf.merkle_proof.to_vec(),
                    low_element: nf.leaf_lower_range_value,
                    low_element_index: nf.leaf_index as u64,
                    high_element: nf.leaf_higher_range_value,
                    high_element_index: 0,
                    root: nullifier_root,
                    root_seq: 0,
                    root_index: 0,
                },
            }
        })
        .collect()
}

fn assemble_accounts(
    ix: &Instruction,
    spp_id: &MolluskPubkey,
    fixtures: &[(Pubkey, MolluskAccount)],
) -> Vec<(MolluskPubkey, MolluskAccount)> {
    let spp = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    ix.accounts
        .iter()
        .map(|meta| {
            if meta.pubkey == spp {
                mollusk_program_account(spp_id)
            } else if meta.pubkey == Pubkey::default() {
                mollusk_svm::program::keyed_account_for_system_program()
            } else if let Some((_, account)) = fixtures.iter().find(|(key, _)| *key == meta.pubkey)
            {
                (to_mollusk_pubkey(&meta.pubkey), account.clone())
            } else {
                (
                    to_mollusk_pubkey(&meta.pubkey),
                    system_owned_account(1_000_000_000),
                )
            }
        })
        .collect()
}

fn keypair_from_payer(payer: &Keypair) -> ShieldedKeypair {
    let seed: [u8; 32] = payer.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    ShieldedKeypair::from_ed25519(&seed, ViewingKey::new()).expect("keypair from payer")
}

fn prove_transact_timed(
    proof_inputs: SppProofInputs,
    spend_proofs: &[SpendProof],
    prover: &ProverClient,
) -> (TransactIxData, Duration) {
    prover
        .prove_transact(proof_inputs.clone(), spend_proofs)
        .expect("warm prove transact");
    let start = Instant::now();
    let transact = prover
        .prove_transact(proof_inputs, spend_proofs)
        .expect("prove transact");
    (transact, start.elapsed())
}

fn start_prover() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::env::set_var("ZOLANA_PROVER_KEYS_DIR", PROVER_KEYS_DIR);
    });
    zolana_client::spawn_prover().expect("spawn prover");
}

fn proving_time_table(spp: Duration, swap: Duration) -> SectionTable {
    SectionTable {
        title: "Proving Time".into(),
        headers: vec![
            "SPP transfer proof".into(),
            "Swap circuit proof".into(),
            "Total".into(),
        ],
        rows: vec![vec![
            format!("{} ms", spp.as_millis()),
            format!("{} ms", swap.as_millis()),
            format!("{} ms", (spp + swap).as_millis()),
        ]],
    }
}

fn tx_size_table(ix: &Instruction, payer: &Pubkey) -> SectionTable {
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);

    let message = Message::new(&[compute.clone(), ix.clone()], Some(payer));
    let legacy = bincode::serialize(&Transaction::new_unsigned(message))
        .expect("serialize legacy")
        .len();

    let alt = AddressLookupTableAccount {
        key: Address::new_from_array([250u8; 32]),
        addresses: ix
            .accounts
            .iter()
            .filter(|meta| !meta.is_signer)
            .map(|meta| Address::new_from_array(meta.pubkey.to_bytes()))
            .chain(std::iter::once(Address::new_from_array(
                ix.program_id.to_bytes(),
            )))
            .collect(),
    };
    let v0_message = v0::Message::try_compile(
        payer,
        &[compute, ix.clone()],
        std::slice::from_ref(&alt),
        Default::default(),
    )
    .expect("compile v0 message");
    let versioned = VersionedMessage::V0(v0_message);
    let signature_count = versioned.header().num_required_signatures as usize;
    let tx = VersionedTransaction {
        signatures: vec![Default::default(); signature_count],
        message: versioned,
    };
    let v0_alt = bincode::serialize(&tx).expect("serialize v0").len();

    SectionTable {
        title: "Transaction Size".into(),
        headers: vec![
            "Instruction Data".into(),
            "Accounts".into(),
            "Legacy Tx".into(),
            "v0 + ALT Tx".into(),
        ],
        rows: vec![vec![
            format!("{} bytes", ix.data.len()),
            ix.accounts.len().to_string(),
            format!("{} bytes", legacy),
            format!("{} bytes", v0_alt),
        ]],
    }
}

#[test]
#[ignore = "CU benchmark; slow, needs SBF binaries + prover. Run via just bench-swap"]
fn bench_cu_swap() {
    std::env::set_var("SBF_OUT_DIR", PROFILING_SBF_DIR);

    let swap_id = MolluskPubkey::new_from_array(*swap_program::ID.as_array());
    let spp_id = MolluskPubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);

    let mut mollusk = Mollusk::default();
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&swap_id, "swap_program", &LOADER_V3);
    mollusk.add_program(&spp_id, "shielded_pool_program", &LOADER_V3);

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
             plus swap circuit proof) and its serialized transaction size: the instruction \
             prefixed with a compute-budget limit ix, as a legacy transaction and as a v0 \
             transaction with every non-signer account and the program id in one address lookup \
             table (Solana's packet limit is 1232 bytes)."
                .into(),
        output_path: OUTPUT_PATH.into(),
        regenerate_command: Some("just bench-swap".into()),
        ..Default::default()
    });

    start_prover();
    preload(CircuitId::Make).expect("preload make keys");
    preload(CircuitId::Take).expect("preload take keys");
    preload(CircuitId::TakeVerifiableEncryption).expect("preload take_verifiable_encryption keys");
    preload(CircuitId::Cancel).expect("preload cancel keys");

    bench_make(&mut mollusk, &spp_id, &mut bench);
    bench_take_derived(&mut mollusk, &spp_id, &mut bench);
    bench_take(&mut mollusk, &spp_id, &mut bench);
    bench_cancel(&mut mollusk, &spp_id, &mut bench);

    bench.generate().expect("write BENCHMARK.md");
}

fn bench_make(mollusk: &mut Mollusk, spp_id: &MolluskPubkey, bench: &mut CuBenchmark) {
    const INPUT_AMOUNT: u64 = 1_000_000;
    const SOURCE_AMOUNT: u64 = 400_000;
    const EXPIRY: u64 = 1_900_000_000;

    let tree = Keypair::new().pubkey();
    let payer = Keypair::new();
    let maker = keypair_from_payer(&payer);

    let input_blinding = random_blinding();
    let input_utxo = Utxo {
        owner: maker.signing_pubkey(),
        asset: SOL_MINT,
        amount: INPUT_AMOUNT,
        blinding: input_blinding,
        zone_program_id: None,
        data: Data::default(),
    };

    let taker = ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([0x4d; 32]))
        .expect("taker keypair");
    let taker_address = taker.shielded_address().expect("taker address");
    let terms = OrderTerms {
        destination_mint: Address::new_from_array([7u8; 32]),
        destination_amount: 250,
        destination: maker.shielded_address().expect("maker address"),
        taker: Address::new_from_array(taker.signing_pubkey().as_ed25519().expect("taker pubkey")),
        expiry: EXPIRY,
        take_mode: swap_prover::TAKE_MODE_VERIFIABLE,
    };
    let order_utxo = OrderUtxo {
        terms,
        blinding: random_blinding(),
        source_mint: SOL_MINT,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: 2,
    };
    let order_output_utxo = order_utxo
        .output_utxo(taker_address.viewing_pubkey)
        .expect("order output");

    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let spend = SppProofInputUtxo::new(input_utxo, &maker);
    let input_utxos = vec![spend, SppProofInputUtxo::new_dummy()];
    let assets = AssetRegistry::default();

    let order_utxo_asset = order_output_utxo.asset;
    let leftover =
        input_sum(&input_utxos, &order_utxo_asset) - i128::from(order_output_utxo.amount);
    let change_amount = u64::try_from(leftover).expect("insufficient order balance");
    let change = SppProofOutputUtxo::new(
        order_utxo_asset,
        change_amount,
        maker.shielded_address().expect("maker address"),
    )
    .expect("change output");

    let order_utxo_hash = order_output_utxo.hash().expect("order output hash");
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
        &assets,
        &transaction_viewing_key,
    )
    .expect("encode make slots");

    let external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![marker_message],
    );
    let spp_proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        payer_address,
    );

    let commitments = spp_proof_inputs
        .input_utxo_hashes()
        .expect("input commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|input| input.utxo_hash).collect();
    let (tree_account, utxo_root, nullifier_root, root_index) = build_tree_fixture(&tree, &leaves);
    let state_tree = local_state_tree(&leaves);
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let nf_tree = nullifier_tree();
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let spend_proofs = build_spend_proofs(
        &tree,
        &state_tree,
        &nf_tree,
        &commitments,
        utxo_root,
        nullifier_root,
        root_index,
    );

    let make_proof_inputs = MakeProofInputParams {
        order_utxo,
        change,
        spp_tx_hashes: SppTxHashes::new(&spp_proof_inputs).expect("spp tx hashes"),
    };

    let prover = ProverClient::local();
    let swap_prover_client = SwapProverClient::new();
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &prover);
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
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for 'make'");
    bench.add_from_entries("make", entries);
    bench.add_table("make", proving_time_table(spp_dur, swap_dur));
    bench.add_table("make", tx_size_table(&ix, &payer.pubkey()));
}

fn bench_take_derived(mollusk: &mut Mollusk, spp_id: &MolluskPubkey, bench: &mut CuBenchmark) {
    const SOURCE_AMOUNT: u64 = 400_000;
    const DESTINATION_AMOUNT: u64 = 250;
    const EXPIRY: u64 = 1_900_000_000;

    let tree = Keypair::new().pubkey();
    let taker_payer = Keypair::new();
    let taker = keypair_from_payer(&taker_payer);
    let taker_address = taker.shielded_address().expect("taker address");
    let maker = ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([0x51; 32]))
        .expect("maker keypair");
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
        source_mint: SOL_MINT,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: SOL_ASSET_ID,
    };

    let taker_in_blinding = random_blinding();
    let source_output_blinding = random_blinding();

    let taker_in = order_utxo.destination_output(taker_address, taker_in_blinding);
    let source_output = order_utxo.source_output(taker_address, source_output_blinding);
    let destination_output = order_utxo
        .derived_destination_output(maker_address)
        .expect("destination output");

    let order_input_utxo = order_utxo.to_input_utxo().expect("order spend");
    let taker_utxo = Utxo {
        owner: taker.signing_pubkey(),
        asset: SOL_MINT,
        amount: DESTINATION_AMOUNT,
        blinding: taker_in_blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let taker_spend = SppProofInputUtxo::new(taker_utxo, &taker);

    let payer_address = Address::new_from_array(taker_payer.pubkey().to_bytes());
    let assets = AssetRegistry::default();
    let input_utxos = vec![order_input_utxo, taker_spend];
    let transaction_viewing_key =
        get_transaction_viewing_key(&taker, &input_utxos).expect("take transaction viewing key");

    let encoded = encrypt_transaction_data(
        &[source_output.clone(), destination_output.clone()],
        &assets,
        &transaction_viewing_key,
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
    let spp_proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        payer_address,
    );

    let commitments = spp_proof_inputs
        .input_utxo_hashes()
        .expect("input commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|input| input.utxo_hash).collect();
    let (tree_account, utxo_root, nullifier_root, root_index) = build_tree_fixture(&tree, &leaves);
    let state_tree = local_state_tree(&leaves);
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let nf_tree = nullifier_tree();
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let spend_proofs = build_spend_proofs(
        &tree,
        &state_tree,
        &nf_tree,
        &commitments,
        utxo_root,
        nullifier_root,
        root_index,
    );

    let take_proof_inputs = TakeProofInputParams {
        order_utxo,
        taker_in,
        source_output,
        destination_output,
        external_data_hash: spp_proof_inputs
            .external_data
            .hash()
            .expect("external data hash"),
    };

    let prover = ProverClient::local();
    let swap_prover_client = SwapProverClient::new();
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &prover);
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
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for 'take'");
    bench.add_from_entries("take", entries);
    bench.add_table("take", proving_time_table(spp_dur, swap_dur));
    bench.add_table("take", tx_size_table(&ix, &taker_payer.pubkey()));
}

fn bench_take(mollusk: &mut Mollusk, spp_id: &MolluskPubkey, bench: &mut CuBenchmark) {
    const SOURCE_AMOUNT: u64 = 400_000;
    const DESTINATION_AMOUNT: u64 = 250;
    const EXPIRY: u64 = 1_900_000_000;

    let tree = Keypair::new().pubkey();
    let taker_payer = Keypair::new();
    let taker = keypair_from_payer(&taker_payer);
    let taker_address = taker.shielded_address().expect("taker address");
    let maker = ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([0x51; 32]))
        .expect("maker keypair");
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
        source_mint: SOL_MINT,
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
    let destination_ciphertext = order_utxo
        .destination_ciphertext(&destination_output)
        .expect("destination ciphertext");

    let order_input_utxo = order_utxo.to_input_utxo().expect("order spend");
    let taker_utxo = Utxo {
        owner: taker.signing_pubkey(),
        asset: SOL_MINT,
        amount: DESTINATION_AMOUNT,
        blinding: taker_in_blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let taker_spend = SppProofInputUtxo::new(taker_utxo, &taker);

    let payer_address = Address::new_from_array(taker_payer.pubkey().to_bytes());
    let assets = AssetRegistry::default();
    let destination_view_tag = maker_address
        .signing_pubkey
        .confidential_view_tag()
        .expect("maker view tag");
    let input_utxos = vec![order_input_utxo, taker_spend];
    let transaction_viewing_key =
        get_transaction_viewing_key(&taker, &input_utxos).expect("take transaction viewing key");

    let mut encoded = encrypt_transaction_data(
        std::slice::from_ref(&source_output),
        &assets,
        &transaction_viewing_key,
    )
    .expect("encode take source slot");
    let destination_utxo_hash = destination_output.hash().expect("take output hash");
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
    let spp_proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        payer_address,
    );

    let commitments = spp_proof_inputs
        .input_utxo_hashes()
        .expect("input commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|input| input.utxo_hash).collect();
    let (tree_account, utxo_root, nullifier_root, root_index) = build_tree_fixture(&tree, &leaves);
    let state_tree = local_state_tree(&leaves);
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let nf_tree = nullifier_tree();
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let spend_proofs = build_spend_proofs(
        &tree,
        &state_tree,
        &nf_tree,
        &commitments,
        utxo_root,
        nullifier_root,
        root_index,
    );

    let take_proof_inputs = TakeVerifiableEncryptionProofInputParams {
        order_utxo,
        taker_in,
        source_output,
        destination_output,
        external_data_hash: spp_proof_inputs
            .external_data
            .hash()
            .expect("external data hash"),
    };

    let prover = ProverClient::local();
    let swap_prover_client = SwapProverClient::new();
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &prover);
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
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for 'take_verifiable_encryption'"
    );
    bench.add_from_entries("take_verifiable_encryption", entries);
    bench.add_table(
        "take_verifiable_encryption",
        proving_time_table(spp_dur, swap_dur),
    );
    bench.add_table(
        "take_verifiable_encryption",
        tx_size_table(&ix, &taker_payer.pubkey()),
    );
}

fn bench_cancel(mollusk: &mut Mollusk, spp_id: &MolluskPubkey, bench: &mut CuBenchmark) {
    const SOURCE_AMOUNT: u64 = 400_000;
    const ORDER_EXPIRY: u64 = 1_000_000;
    const SPP_RELAYER_DEADLINE: u64 = u64::MAX;

    let tree = Keypair::new().pubkey();
    let maker_payer = Keypair::new();
    let maker = keypair_from_payer(&maker_payer);
    let maker_address = maker.shielded_address().expect("maker address");
    let taker = ShieldedKeypair::from_solana_keypair(&Keypair::new_from_array([0x4d; 32]))
        .expect("taker keypair");
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
        source_mint: SOL_MINT,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: 2,
    };
    let source_output_blinding = random_blinding();

    let source_output = order_utxo.source_output(maker_address, source_output_blinding);

    let order_input_utxo = order_utxo.to_input_utxo().expect("order spend");

    let payer_address = Address::new_from_array(maker_payer.pubkey().to_bytes());
    let assets = AssetRegistry::default();
    let input_utxos = vec![order_input_utxo];
    let transaction_viewing_key =
        get_transaction_viewing_key(&maker, &input_utxos).expect("cancel transaction viewing key");

    let encoded = encrypt_transaction_data(
        std::slice::from_ref(&source_output),
        &assets,
        &transaction_viewing_key,
    )
    .expect("encode cancel slots");

    let mut external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    external_data.expiry_unix_ts = SPP_RELAYER_DEADLINE;
    let spp_proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        payer_address,
    );

    let commitments = spp_proof_inputs
        .input_utxo_hashes()
        .expect("input commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|input| input.utxo_hash).collect();
    let (tree_account, utxo_root, nullifier_root, root_index) = build_tree_fixture(&tree, &leaves);
    let state_tree = local_state_tree(&leaves);
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let nf_tree = nullifier_tree();
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let spend_proofs = build_spend_proofs(
        &tree,
        &state_tree,
        &nf_tree,
        &commitments,
        utxo_root,
        nullifier_root,
        root_index,
    );

    let cancel_proof_inputs = CancelProofInputParams {
        order_utxo: order_utxo.clone(),
        taker_viewing_pubkey,
        source_output,
        external_data_hash: spp_proof_inputs
            .external_data
            .hash()
            .expect("external data hash"),
    };

    let prover = ProverClient::local();
    let swap_prover_client = SwapProverClient::new();
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &prover);
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
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for 'cancel'");
    bench.add_from_entries("cancel", entries);
    bench.add_table("cancel", proving_time_table(spp_dur, swap_dur));
    bench.add_table("cancel", tx_size_table(&ix, &maker_payer.pubkey()));
}
