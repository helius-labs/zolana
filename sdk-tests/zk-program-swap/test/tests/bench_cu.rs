use std::time::{Duration, Instant};

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
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use swap_prover::{preload, CircuitId};
use swap_sdk::{
    cancel, create_swap, escrow_authority_pda, fill, fill_verifiable_encryption,
    instructions::{
        cancel::{CancelSharedInputs, EscrowCancel},
        create_swap::{CreateSharedInputs, EscrowCreate},
        fill::{EscrowFill, FillSharedInputs},
        fill_verifiable_encryption::{
            EscrowFillVerifiableEncryption, FillVerifiableEncryptionSharedInputs,
        },
    },
    order::{marker_output, BlindingField, Escrow, OrderTerms, SOL_ASSET_ID},
    prover::{
        cancel_proof_ix, create_proof_ix, fill_proof_ix, fill_verifiable_encryption_proof_ix,
        pack_transact_proof,
    },
};
use zolana_client::{
    assemble, MerkleContext, MerkleProof, NonInclusionProof, ProverClient, ProverInputs,
    SpendProof, Transaction as TxBuilder, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_hasher::Poseidon;
use zolana_interface::{
    state::{
        address_tree_params, discriminator::TREE_ACCOUNT_DISCRIMINATOR, tree_account_size,
        STATE_HEIGHT,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};
use zolana_transaction::{
    instructions::{
        transact::{signed_transaction::BN254_MODULUS_DEC, SignedTransaction},
        types::SpendUtxo,
    },
    utxo::Blinding,
    AssetRegistry, Data, Utxo, SOL_MINT,
};
use zolana_tree::TreeAccount;

// Dedicated dir for the profiling build so it never clobbers the plain
// `target/deploy/swap_program.so` that validator tests load -- the profiling
// build calls a profiler syscall the test validator does not register.
const PROFILING_SBF_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../target/swap-bench");
const OUTPUT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../CU_BENCHMARK.md");
const PROVER_KEYS_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../prover/server/proving-keys"
);
// The escrow-authority PDA the swap program signs for is never assigned this
// index by the SDK builders (they run against the real program); the bench
// mirrors `Fill`/`Cancel::instruction`, which stamp signer index 2 on the escrow
// input so SPP selects the escrow-authority account as its eddsa signer.
const ESCROW_AUTHORITY_SIGNER_INDEX: u8 = 2;

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

// Build the shielded-pool tree account exactly as the program's `create_tree`
// does (`TreeAccount::init` with the canonical params), then append the input
// utxo hashes directly so their state-inclusion proofs verify against the
// account's utxo root. The nullifier sub-tree stays empty. Returns the mollusk
// fixture plus the utxo/nullifier roots and the utxo root-history index the
// appends advanced to (one per leaf, from the empty root at index 0).
fn build_tree_fixture(
    tree: &Pubkey,
    leaves: &[[u8; 32]],
) -> (MolluskAccount, [u8; 32], [u8; 32], u16) {
    let mut data = vec![0u8; tree_account_size()];
    let root_index = leaves.len() as u16;
    let (utxo_root, nullifier_root) = {
        let mut account = TreeAccount::init(
            &mut data,
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
        data,
        owner: MolluskPubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        executable: false,
        rent_epoch: 0,
    };
    (fixture, utxo_root, nullifier_root, root_index)
}

// A local append-only tree mirroring the on-chain utxo tree, used only to read
// back merkle inclusion proofs (the on-chain SMT stores subtrees, not proofs).
fn local_state_tree(leaves: &[[u8; 32]]) -> MerkleTree<Poseidon> {
    let mut tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    for leaf in leaves {
        tree.append(leaf).expect("append state leaf");
    }
    tree
}

// An empty indexed nullifier tree matching the on-chain initial state (single
// [0, BN254_MODULUS-1] range element), so a fresh nullifier's non-inclusion proof
// carries the low/high adjacency the program checks.
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

// Build the `SpendProof` (state inclusion + nullifier non-inclusion) the SDK
// `assemble` consumes for each real input, from the local trees. Every input
// proves against the same final utxo root at `root_index`; the nullifier root
// stays at history index 0.
fn build_spend_proofs(
    tree: &Pubkey,
    state_tree: &MerkleTree<Poseidon>,
    nf_tree: &IndexedMerkleTree<Poseidon, usize>,
    commitments: &[zolana_transaction::instructions::types::InputCommitment],
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

// Map the swap instruction's account metas onto mollusk fixtures: the SPP program
// (self-CPI target) to its program account, the system program to mollusk's
// builtin, the tree/payer to the built fixtures, and everything else (the
// escrow-authority PDA the program signs for) to an empty system-owned account.
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

// Derive the SPP-signing party's shielded keypair from its Solana keypair seed,
// so its ed25519 signing pubkey is the SPP payer (eddsa signer index 0).
fn keypair_from_payer(payer: &Keypair) -> ShieldedKeypair {
    let seed: [u8; 32] = payer.to_bytes()[..32]
        .try_into()
        .expect("ed25519 seed is the first 32 bytes");
    ShieldedKeypair::from_ed25519(&seed, ViewingKey::new()).expect("keypair from payer")
}

fn spp_program_meta() -> AccountMeta {
    AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false)
}

// Prove the SPP transfer, timing steady-state proving rather than the prover
// server's first-request per-shape key load: assemble once, prove once to warm the
// shape, then time a second prove. `preload` only warms the in-process swap gnark
// circuits, not the SPP server's transfer keys, so this warm-up is what makes the
// SPP column deterministic across runs.
fn prove_transact_timed(
    signed: SignedTransaction,
    spend_proofs: &[SpendProof],
    prover: &ProverClient,
) -> (
    zolana_interface::instruction::instruction_data::transact::TransactIxData,
    Duration,
) {
    let assembled = assemble(signed, spend_proofs).expect("assemble transfer");
    let inputs = match &assembled.prover_inputs {
        ProverInputs::Eddsa(inputs) => inputs,
        ProverInputs::P256(_) => panic!("swap lifecycle uses the eddsa rail"),
    };
    prover.prove_transfer(inputs).expect("warm prove transfer");
    let start = Instant::now();
    let proof = prover.prove_transfer(inputs).expect("prove transfer");
    let dur = start.elapsed();
    let transact = assembled.with_proof(pack_transact_proof(&proof).expect("pack proof"));
    (transact, dur)
}

fn start_prover() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::env::set_var("ZOLANA_PROVER_KEYS_DIR", PROVER_KEYS_DIR);
    });
    zolana_client::spawn_prover().expect("spawn prover");
}

struct ProvingTime {
    label: &'static str,
    spp: Duration,
    swap: Duration,
}

#[test]
#[ignore]
fn bench_cu_swap() {
    std::env::set_var("SBF_OUT_DIR", PROFILING_SBF_DIR);

    let swap_id = MolluskPubkey::new_from_array(*swap_program::SWAP_PROGRAM_ID.as_array());
    let spp_id = MolluskPubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);

    let mut mollusk = Mollusk::default();
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&swap_id, "swap_program", &LOADER_V3);
    mollusk.add_program(&spp_id, "shielded_pool_program", &LOADER_V3);

    let mut bench = CuBenchmark::new(ReadmeConfig {
        title: "Confidential Swap -- CU Benchmark".into(),
        description:
            "Compute unit profiling for the confidential swap create/fill/fill_verifiable_encryption/cancel \
             instructions, replayed under mollusk. The shielded-pool tree account is built directly (the \
             program's `create_tree` init plus the input utxo hashes appended), and each \
             instruction hashes its public input, verifies its own Groth16 proof, then CPIs SPP \
             `transact` (the `cpi_spp_transact*` row). Only the swap program is profiled; the \
             shielded-pool program is built plain, so the CU its CPI consumes is charged to the \
             `cpi_spp_transact*` row as a black box and its internal functions do not appear \
             here. Proving times for both rails are appended below."
                .into(),
        output_path: OUTPUT_PATH.into(),
        regenerate_command: Some("just bench-swap".into()),
        ..Default::default()
    });

    // Warm the SPP prover so `create swap`'s SPP time is not inflated by the
    // server's lazy first-request key load.
    start_prover();
    preload(CircuitId::Create).expect("preload create keys");
    preload(CircuitId::Fill).expect("preload fill keys");
    preload(CircuitId::FillVerifiableEncryption).expect("preload fill_verifiable_encryption keys");
    preload(CircuitId::Cancel).expect("preload cancel keys");

    let mut timings: Vec<ProvingTime> = Vec::new();
    bench_create(&mut mollusk, &spp_id, &mut bench, &mut timings);
    bench_fill_derived(&mut mollusk, &spp_id, &mut bench, &mut timings);
    bench_fill(&mut mollusk, &spp_id, &mut bench, &mut timings);
    bench_cancel(&mut mollusk, &spp_id, &mut bench, &mut timings);

    bench.generate().expect("write CU_BENCHMARK.md");
    append_proving_times(OUTPUT_PATH, &timings).expect("append proving times");
}

// create_swap: 1 real input (maker source SOL) -> change + escrow + marker (2x3).
fn bench_create(
    mollusk: &mut Mollusk,
    spp_id: &MolluskPubkey,
    bench: &mut CuBenchmark,
    timings: &mut Vec<ProvingTime>,
) {
    const INPUT_AMOUNT: u64 = 1_000_000;
    const SOURCE_AMOUNT: u64 = 400_000;
    const EXPIRY: u64 = 1_900_000_000;

    let tree = Keypair::new().pubkey();
    let payer = Keypair::new();
    let maker = keypair_from_payer(&payer);

    let input_blinding: Blinding = [3u8; 31];
    let input_utxo = Utxo {
        owner: maker.signing_pubkey(),
        asset: SOL_MINT,
        amount: INPUT_AMOUNT,
        blinding: input_blinding,
        zone_program_id: None,
        data: Data::default(),
    };

    let taker = ShieldedKeypair::from_seed_ed25519(&[0x4d; 32]).expect("taker keypair");
    let taker_address = taker.shielded_address().expect("taker address");
    let taker_pk_fe = taker
        .signing_pubkey()
        .owner_pk_field()
        .expect("taker pk_fe");
    let terms = OrderTerms {
        source_asset_id: SOL_ASSET_ID,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: 2,
        destination_mint: Address::new_from_array([7u8; 32]),
        destination_amount: 250,
        maker_owner_hash: maker.owner_hash().expect("maker address"),
        maker_viewing_pk: *maker.viewing_pubkey().as_bytes(),
        expiry: EXPIRY,
        taker_pk_fe,
        fill_mode: swap_prover::FILL_MODE_VERIFIABLE,
    };
    let escrow_blinding: Blinding = [7u8; 31];
    let escrow = Escrow {
        terms: terms.clone(),
        blinding: escrow_blinding,
        source_mint: SOL_MINT,
    }
    .output(taker_address.viewing_pubkey)
    .expect("escrow output");
    let marker = marker_output(taker_address);

    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let spend = SpendUtxo::from_keypair(input_utxo, &maker);
    let tx = TxBuilder::new(
        maker.shielded_address().expect("maker address"),
        vec![spend],
        payer_address,
    );
    let assets = AssetRegistry::default();
    let signed = EscrowCreate { tx, escrow, marker }
        .sign(&maker, &assets)
        .expect("escrow create sign");

    let commitments = signed.input_commitments().expect("input commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|c| c.utxo_hash).collect();
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

    let spend = signed.inputs.first().expect("input");
    let nullifier_pubkey = spend.nullifier_key.pubkey().expect("nullifier pubkey");
    let source_input_hash = spend
        .utxo
        .hash(
            &nullifier_pubkey,
            &spend.data_hash.unwrap_or([0u8; 32]),
            &spend.zone_data_hash.unwrap_or([0u8; 32]),
        )
        .expect("source input hash");
    let change_output = signed.outputs.first().expect("change output");
    let change_amount = change_output.amount;
    let change_blinding = change_output.blinding.to_field();
    let external_data_hash = signed.external_data.hash().expect("external data hash");

    let create_inputs = CreateSharedInputs {
        terms,
        escrow_blinding,
        taker_address,
        source_input_hash,
        change_amount,
        change_blinding,
        external_data_hash,
    };

    let prover = ProverClient::local();
    let (transact, spp_dur) = prove_transact_timed(signed, &spend_proofs, &prover);
    let t1 = Instant::now();
    let create_result = create_inputs
        .create_proof_inputs(SOL_MINT)
        .expect("create proof inputs")
        .prove()
        .expect("swap create prove");
    let swap_dur = t1.elapsed();

    let spp_accounts = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new(tree, false),
        spp_program_meta(),
    ];
    let mut maker_address = [0u8; 65];
    maker_address[0..32].copy_from_slice(&maker.owner_hash().expect("maker owner hash"));
    maker_address[32..65].copy_from_slice(maker.viewing_pubkey().as_bytes());
    let ix = create_swap(
        payer.pubkey(),
        spp_accounts,
        create_proof_ix(&create_result.proof),
        SOL_ASSET_ID,
        maker_address,
        transact,
    );

    let fixtures = vec![
        (tree, tree_account),
        (payer.pubkey(), system_owned_account(100_000_000_000)),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for 'create swap'"
    );
    bench.add_from_entries("create swap", entries);
    timings.push(ProvingTime {
        label: "create swap",
        spp: spp_dur,
        swap: swap_dur,
    });
}

// fill (derived blinding): escrow + taker destination inputs -> source (to taker)
// + destination (to maker, blinding derived from the escrow blinding) (2x2).
// Permissionless: any opening holder fills; the maker recomputes the derived
// blinding without a ciphertext.
fn bench_fill_derived(
    mollusk: &mut Mollusk,
    spp_id: &MolluskPubkey,
    bench: &mut CuBenchmark,
    timings: &mut Vec<ProvingTime>,
) {
    const SOURCE_AMOUNT: u64 = 400_000;
    const DESTINATION_AMOUNT: u64 = 250;
    const EXPIRY: u64 = 1_900_000_000;

    let tree = Keypair::new().pubkey();
    let taker_payer = Keypair::new();
    let taker = keypair_from_payer(&taker_payer);
    let taker_recipient = taker.shielded_address().expect("taker address");
    let taker_address = taker.owner_hash().expect("taker owner hash");
    let maker = ShieldedKeypair::from_seed_ed25519(&[0x51; 32]).expect("maker keypair");
    let maker_recipient = maker.shielded_address().expect("maker address");

    let taker_pk_fe = taker
        .signing_pubkey()
        .owner_pk_field()
        .expect("taker pk_fe");
    let terms = OrderTerms {
        source_asset_id: SOL_ASSET_ID,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: SOL_ASSET_ID,
        destination_mint: SOL_MINT,
        destination_amount: DESTINATION_AMOUNT,
        maker_owner_hash: maker.owner_hash().expect("maker owner hash"),
        maker_viewing_pk: *maker.viewing_pubkey().as_bytes(),
        expiry: EXPIRY,
        taker_pk_fe,
        fill_mode: swap_prover::FILL_MODE_DERIVED,
    };

    let escrow_blinding: Blinding = [7u8; 31];
    let taker_in_blinding: Blinding = [13u8; 31];
    let source_output_blinding: Blinding = [31u8; 31];

    let build_shared = |external_data_hash: [u8; 32]| FillSharedInputs {
        terms: terms.clone(),
        escrow_blinding,
        taker_address,
        taker_in_blinding,
        source_output_blinding,
        external_data_hash,
        maker_recipient,
        taker_recipient,
    };

    let fill_shared = build_shared([0u8; 32]);
    let source_output = fill_shared.source_output(SOL_MINT);
    let destination_output = fill_shared
        .destination_output(SOL_MINT)
        .expect("destination output");

    let escrow_input = Escrow {
        terms: terms.clone(),
        blinding: escrow_blinding,
        source_mint: SOL_MINT,
    }
    .spend()
    .expect("escrow spend");
    let taker_utxo = Utxo {
        owner: taker.signing_pubkey(),
        asset: SOL_MINT,
        amount: DESTINATION_AMOUNT,
        blinding: taker_in_blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let taker_spend = SpendUtxo::from_keypair(taker_utxo, &taker);

    let payer_address = Address::new_from_array(taker_payer.pubkey().to_bytes());
    let tx = TxBuilder::new(
        taker_recipient,
        vec![escrow_input, taker_spend],
        payer_address,
    )
    .with_expiry(terms.expiry);
    let assets = AssetRegistry::default();
    let signed = EscrowFill {
        tx,
        source_output,
        destination_output,
    }
    .sign(&taker, &assets)
    .expect("escrow fill sign");

    let commitments = signed.input_commitments().expect("input commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|c| c.utxo_hash).collect();
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

    let external_data_hash = signed.external_data.hash().expect("external data hash");
    let fill_shared = build_shared(external_data_hash);

    let prover = ProverClient::local();
    let (mut transact, spp_dur) = prove_transact_timed(signed, &spend_proofs, &prover);
    if let Some(escrow_input) = transact.inputs.get_mut(0) {
        escrow_input.eddsa_signer_index = ESCROW_AUTHORITY_SIGNER_INDEX;
    }
    let t1 = Instant::now();
    let fill_result = fill_shared
        .fill_proof_inputs(SOL_MINT, SOL_MINT)
        .prove()
        .expect("swap fill prove");
    let swap_dur = t1.elapsed();

    let spp_accounts = vec![
        AccountMeta::new(taker_payer.pubkey(), true),
        AccountMeta::new(tree, false),
        AccountMeta::new_readonly(escrow_authority_pda(), false),
        spp_program_meta(),
    ];
    let ix = fill(
        taker_payer.pubkey(),
        spp_accounts,
        fill_proof_ix(&fill_result.proof),
        transact,
    );

    let fixtures = vec![
        (tree, tree_account),
        (taker_payer.pubkey(), system_owned_account(100_000_000_000)),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for 'fill'");
    bench.add_from_entries("fill", entries);
    timings.push(ProvingTime {
        label: "fill",
        spp: spp_dur,
        swap: swap_dur,
    });
}

// fill: escrow + taker destination inputs -> source (to taker) + destination (to
// maker, verifiably encrypted) (2x2). The escrow is spent via the opening; the
// swap program signs for the escrow-authority PDA via invoke_signed.
fn bench_fill(
    mollusk: &mut Mollusk,
    spp_id: &MolluskPubkey,
    bench: &mut CuBenchmark,
    timings: &mut Vec<ProvingTime>,
) {
    const SOURCE_AMOUNT: u64 = 400_000;
    const DESTINATION_AMOUNT: u64 = 250;
    const EXPIRY: u64 = 1_900_000_000;

    let tree = Keypair::new().pubkey();
    let taker_payer = Keypair::new();
    let taker = keypair_from_payer(&taker_payer);
    let taker_recipient = taker.shielded_address().expect("taker address");
    let maker = ShieldedKeypair::from_seed_ed25519(&[0x51; 32]).expect("maker keypair");
    let maker_recipient = maker.shielded_address().expect("maker address");

    let taker_pk_fe = taker
        .signing_pubkey()
        .owner_pk_field()
        .expect("taker pk_fe");
    let terms = OrderTerms {
        source_asset_id: SOL_ASSET_ID,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: SOL_ASSET_ID,
        destination_mint: SOL_MINT,
        destination_amount: DESTINATION_AMOUNT,
        maker_owner_hash: maker.owner_hash().expect("maker owner hash"),
        maker_viewing_pk: *maker.viewing_pubkey().as_bytes(),
        expiry: EXPIRY,
        taker_pk_fe,
        fill_mode: swap_prover::FILL_MODE_VERIFIABLE,
    };

    let escrow_blinding: Blinding = [7u8; 31];
    let taker_in_blinding: Blinding = [13u8; 31];
    let destination_output_blinding: Blinding = [21u8; 31];
    let source_output_blinding: Blinding = [31u8; 31];

    let build_shared = |external_data_hash: [u8; 32]| FillVerifiableEncryptionSharedInputs {
        terms: terms.clone(),
        escrow_blinding,
        taker_in_blinding,
        destination_output_blinding,
        source_output_blinding,
        external_data_hash,
        maker_recipient,
        taker_recipient,
    };

    let fill_shared = build_shared([0u8; 32]);
    let destination_ciphertext = fill_shared
        .fill_proof_inputs(SOL_MINT, SOL_MINT)
        .expect("fill proof inputs")
        .destination_ciphertext()
        .expect("destination ciphertext");
    let source_output = fill_shared.source_output(SOL_MINT);
    let destination_output = fill_shared.destination_output(SOL_MINT);

    let escrow_input = Escrow {
        terms: terms.clone(),
        blinding: escrow_blinding,
        source_mint: SOL_MINT,
    }
    .spend()
    .expect("escrow spend");
    let taker_utxo = Utxo {
        owner: taker.signing_pubkey(),
        asset: SOL_MINT,
        amount: DESTINATION_AMOUNT,
        blinding: taker_in_blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let taker_spend = SpendUtxo::from_keypair(taker_utxo, &taker);

    let payer_address = Address::new_from_array(taker_payer.pubkey().to_bytes());
    let tx = TxBuilder::new(
        taker_recipient,
        vec![escrow_input, taker_spend],
        payer_address,
    )
    .with_expiry(terms.expiry);
    let assets = AssetRegistry::default();
    let signed = EscrowFillVerifiableEncryption {
        tx,
        source_output,
        destination_output,
        destination_ciphertext,
        destination_view_tag: maker_recipient
            .signing_pubkey
            .confidential_view_tag()
            .expect("maker view tag"),
        destination_recipient_viewing_pk: maker_recipient.viewing_pubkey,
    }
    .sign(&taker, &assets)
    .expect("escrow fill sign");

    let commitments = signed.input_commitments().expect("input commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|c| c.utxo_hash).collect();
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

    let external_data_hash = signed.external_data.hash().expect("external data hash");
    let fill_shared = build_shared(external_data_hash);

    let prover = ProverClient::local();
    let (mut transact, spp_dur) = prove_transact_timed(signed, &spend_proofs, &prover);
    if let Some(escrow_input) = transact.inputs.get_mut(0) {
        escrow_input.eddsa_signer_index = ESCROW_AUTHORITY_SIGNER_INDEX;
    }
    let t1 = Instant::now();
    let fill_result = fill_shared
        .fill_proof_inputs(SOL_MINT, SOL_MINT)
        .expect("fill proof inputs")
        .prove()
        .expect("swap fill prove");
    let swap_dur = t1.elapsed();

    let spp_accounts = vec![
        AccountMeta::new(taker_payer.pubkey(), true),
        AccountMeta::new(tree, false),
        AccountMeta::new_readonly(escrow_authority_pda(), false),
        spp_program_meta(),
    ];
    let ix = fill_verifiable_encryption(
        taker_payer.pubkey(),
        spp_accounts,
        fill_verifiable_encryption_proof_ix(&fill_result.proof),
        transact,
    );

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
        "no profiling entries for 'fill_verifiable_encryption'"
    );
    bench.add_from_entries("fill_verifiable_encryption", entries);
    timings.push(ProvingTime {
        label: "fill_verifiable_encryption",
        spp: spp_dur,
        swap: swap_dur,
    });
}

// cancel: escrow input -> source output back to the maker (1x1), after the order
// expiry. The SPP transact carries a future relayer deadline; the committed order
// expiry rides the cancel ix and proof, checked on-chain as `now > order_expiry`.
fn bench_cancel(
    mollusk: &mut Mollusk,
    spp_id: &MolluskPubkey,
    bench: &mut CuBenchmark,
    timings: &mut Vec<ProvingTime>,
) {
    const SOURCE_AMOUNT: u64 = 400_000;
    const ORDER_EXPIRY: u64 = 1_000_000;
    const SPP_RELAYER_DEADLINE: u64 = u64::MAX;

    let tree = Keypair::new().pubkey();
    let maker_payer = Keypair::new();
    let maker = keypair_from_payer(&maker_payer);
    let maker_recipient = maker.shielded_address().expect("maker address");
    let taker = ShieldedKeypair::from_seed_ed25519(&[0x4d; 32]).expect("taker keypair");
    let taker_viewing_pk = taker
        .shielded_address()
        .expect("taker address")
        .viewing_pubkey;
    let taker_pk_fe = taker
        .signing_pubkey()
        .owner_pk_field()
        .expect("taker pk_fe");

    let terms = OrderTerms {
        source_asset_id: SOL_ASSET_ID,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: 2,
        destination_mint: Address::new_from_array([7u8; 32]),
        destination_amount: 250,
        maker_owner_hash: maker.owner_hash().expect("maker owner hash"),
        maker_viewing_pk: *maker.viewing_pubkey().as_bytes(),
        expiry: ORDER_EXPIRY,
        taker_pk_fe,
        fill_mode: swap_prover::FILL_MODE_VERIFIABLE,
    };
    let escrow_blinding: Blinding = [7u8; 31];
    let source_output_blinding: Blinding = [19u8; 31];

    let build_inputs = |external_data_hash: [u8; 32]| CancelSharedInputs {
        terms: terms.clone(),
        escrow_blinding,
        taker_viewing_pk,
        source_output_blinding,
        external_data_hash,
        maker_recipient,
    };
    let cancel_inputs = build_inputs([0u8; 32]);
    let source_output = cancel_inputs.source_output(SOL_MINT);

    let escrow_input = Escrow {
        terms: terms.clone(),
        blinding: escrow_blinding,
        source_mint: SOL_MINT,
    }
    .spend()
    .expect("escrow spend");

    let payer_address = Address::new_from_array(maker_payer.pubkey().to_bytes());
    let tx = TxBuilder::new(maker_recipient, vec![escrow_input], payer_address)
        .with_expiry(SPP_RELAYER_DEADLINE);
    let assets = AssetRegistry::default();
    let signed = EscrowCancel { tx, source_output }
        .sign(&maker, &assets)
        .expect("escrow cancel sign");

    let commitments = signed.input_commitments().expect("input commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|c| c.utxo_hash).collect();
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

    let external_data_hash = signed.external_data.hash().expect("external data hash");
    let cancel_inputs = build_inputs(external_data_hash);

    let prover = ProverClient::local();
    let (mut transact, spp_dur) = prove_transact_timed(signed, &spend_proofs, &prover);
    if let Some(escrow_input) = transact.inputs.get_mut(0) {
        escrow_input.eddsa_signer_index = ESCROW_AUTHORITY_SIGNER_INDEX;
    }
    let t1 = Instant::now();
    let cancel_result = cancel_inputs
        .cancel_proof_inputs(SOL_MINT)
        .expect("cancel proof inputs")
        .prove()
        .expect("swap cancel prove");
    let swap_dur = t1.elapsed();

    let maker_signer = Pubkey::new_from_array(
        cancel_inputs
            .maker_recipient
            .signing_pubkey
            .as_ed25519()
            .expect("maker ed25519"),
    );
    let spp_accounts = vec![
        AccountMeta::new(maker_payer.pubkey(), true),
        AccountMeta::new(tree, false),
        AccountMeta::new_readonly(escrow_authority_pda(), false),
        spp_program_meta(),
    ];
    let ix = cancel(
        maker_payer.pubkey(),
        maker_signer,
        spp_accounts,
        cancel_proof_ix(&cancel_result.proof),
        terms.expiry,
        transact,
    );

    // The swap program requires `now > order_expiry`; SPP requires its own
    // relayer deadline (u64::MAX) to be in the future. Sit the clock between them.
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
    timings.push(ProvingTime {
        label: "cancel",
        spp: spp_dur,
        swap: swap_dur,
    });
}

fn append_proving_times(path: &str, timings: &[ProvingTime]) -> std::io::Result<()> {
    use std::io::Write;

    if timings.is_empty() {
        return Ok(());
    }
    let mut f = std::fs::OpenOptions::new().append(true).open(path)?;
    writeln!(f, "## Proving Times\n")?;
    writeln!(
        f,
        "| {:<12} | {:>18} | {:>18} | {:>8} |",
        "Instruction", "SPP transfer proof", "Swap circuit proof", "Total"
    )?;
    writeln!(
        f,
        "| {:-<12} | {:-<18} | {:-<18} | {:-<8} |",
        "", "", "", ""
    )?;
    for t in timings {
        let total = t.spp + t.swap;
        writeln!(
            f,
            "| {:<12} | {:>18} | {:>18} | {:>8} |",
            t.label,
            format!("{} ms", t.spp.as_millis()),
            format!("{} ms", t.swap.as_millis()),
            format!("{} ms", total.as_millis()),
        )?;
    }
    Ok(())
}
