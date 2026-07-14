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
        create_swap::{input_sum, CreateSwap, CreateSwapProofInputParams, OrderMarker},
        fill::{Fill, FillProofInputParams},
        fill_verifiable_encryption::{
            FillVerifiableEncryption, FillVerifiableEncryptionProofInputParams,
        },
    },
    order::{OrderTerms, OrderUtxo, Recipient, SOL_ASSET_ID},
    prover::{prove_transact, SwapProverClient},
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
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};
use zolana_transaction::{
    instructions::{
        transact::{
            encrypt_transaction_data, get_transaction_viewing_key,
            spp_proof_inputs::BN254_MODULUS_DEC, ExternalData, OutputUtxo, SppProofInputs,
        },
        types::SppProofInputUtxo,
    },
    utxo::Blinding,
    AssetRegistry, Data, Utxo, SOL_MINT,
};
use zolana_tree::TreeAccount;

// Dedicated dir for the profiling build so it never clobbers the plain
// `target/deploy/swap_program.so` that validator tests load -- the profiling
// build calls a profiler syscall the test validator does not register.
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

// Prove the SPP transfer, timing steady-state proving rather than the prover
// server's first-request per-shape key load: prove once to warm the shape, then
// time a second prove. `preload` only warms the in-process swap gnark circuits,
// not the SPP server's transfer keys, so this warm-up is what makes the SPP
// column deterministic across runs.
fn prove_transact_timed(
    proof_inputs: SppProofInputs,
    spend_proofs: &[SpendProof],
    prover: &ProverClient,
) -> (TransactIxData, Duration) {
    prove_transact(proof_inputs.clone(), spend_proofs, prover).expect("warm prove transact");
    let start = Instant::now();
    let transact = prove_transact(proof_inputs, spend_proofs, prover).expect("prove transact");
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

// Serialized on-chain transaction size for a single swap instruction, prefixed
// with a compute-budget limit ix (as the real client sends it). `legacy` is the
// plain v0-less transaction; `v0 + ALT` compiles a v0 message that sinks every
// non-signer account plus the program id into one address lookup table, the
// layout that lets these proof-carrying instructions fit under the 1232-byte
// packet limit.
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
            .filter(|m| !m.is_signer)
            .map(|m| Address::new_from_array(m.pubkey.to_bytes()))
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

    // Warm the SPP prover so `create swap`'s SPP time is not inflated by the
    // server's lazy first-request key load.
    start_prover();
    preload(CircuitId::Create).expect("preload create keys");
    preload(CircuitId::Fill).expect("preload fill keys");
    preload(CircuitId::FillVerifiableEncryption).expect("preload fill_verifiable_encryption keys");
    preload(CircuitId::Cancel).expect("preload cancel keys");

    bench_create(&mut mollusk, &spp_id, &mut bench);
    bench_fill_derived(&mut mollusk, &spp_id, &mut bench);
    bench_fill(&mut mollusk, &spp_id, &mut bench);
    bench_cancel(&mut mollusk, &spp_id, &mut bench);

    bench.generate().expect("write BENCHMARK.md");
}

// create_swap: 1 real input (maker source SOL) -> change + escrow + marker (2x3).
fn bench_create(mollusk: &mut Mollusk, spp_id: &MolluskPubkey, bench: &mut CuBenchmark) {
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
    let terms = OrderTerms {
        destination_mint: Address::new_from_array([7u8; 32]),
        destination_amount: 250,
        destination: maker.shielded_address().expect("maker address"),
        taker: Address::new_from_array(taker.signing_pubkey().as_ed25519().expect("taker pubkey")),
        expiry: EXPIRY,
        fill_mode: swap_prover::FILL_MODE_VERIFIABLE,
    };
    let escrow_utxo_hash = OrderUtxo {
        terms,
        blinding: [7u8; 31],
        source_mint: SOL_MINT,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: 2,
    };
    let escrow = escrow_utxo_hash
        .output_utxo(taker_address.viewing_pubkey)
        .expect("escrow output");

    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let spend = SppProofInputUtxo::new(input_utxo, &maker);
    let input_utxos = vec![spend, SppProofInputUtxo::new_dummy()];
    let assets = AssetRegistry::default();

    let escrow_asset = escrow.asset;
    let leftover = input_sum(&input_utxos, &escrow_asset) - i128::from(escrow.amount);
    let change_amount = u64::try_from(leftover).expect("insufficient escrow balance");
    let change = OutputUtxo::new(
        escrow_asset,
        change_amount,
        maker.shielded_address().expect("maker address"),
    )
    .expect("change output");
    let change_blinding = change.blinding;

    let escrow_output_hash = escrow.hash().expect("escrow output hash");
    let marker_message = OrderMarker {
        escrow_utxo_hash: escrow_output_hash,
        maker_pubkey: payer.pubkey(),
        taker_address,
    }
    .message()
    .expect("marker message");

    let transaction_viewing_key =
        get_transaction_viewing_key(&maker, &input_utxos).expect("create transaction viewing key");

    let encoded = encrypt_transaction_data(&[change, escrow], &assets, &transaction_viewing_key)
        .expect("encode create slots");

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

    let spend = spp_proof_inputs.input_utxos.first().expect("input");
    let source_input_hash = spend.hash().expect("source input hash");
    let external_data_hash = spp_proof_inputs
        .external_data
        .hash()
        .expect("external data hash");

    let create_inputs = CreateSwapProofInputParams {
        escrow: escrow_utxo_hash,
        taker_address,
        source_input_hash,
        change_amount,
        change_blinding,
        external_data_hash,
    };

    let prover = ProverClient::local();
    let swap_prover_client = SwapProverClient::new_ffi();
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &prover);
    let t1 = Instant::now();
    let create_result = swap_prover_client
        .prove_create_swap(&create_inputs)
        .expect("swap create prove");
    let swap_dur = t1.elapsed();

    let ix = CreateSwap {
        payer: payer.pubkey(),
        tree,
        create_swap_proof: create_result.proof.into(),
        spp_proof: transact,
    }
    .instruction()
    .expect("create swap instruction");

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
    bench.add_table("create swap", proving_time_table(spp_dur, swap_dur));
    bench.add_table("create swap", tx_size_table(&ix, &payer.pubkey()));
}

// fill (derived blinding): escrow + taker destination inputs -> source (to taker)
// + destination (to maker, blinding derived from the escrow blinding) (2x2).
// Permissionless: any opening holder fills; the maker recomputes the derived
// blinding without a ciphertext.
fn bench_fill_derived(mollusk: &mut Mollusk, spp_id: &MolluskPubkey, bench: &mut CuBenchmark) {
    const SOURCE_AMOUNT: u64 = 400_000;
    const DESTINATION_AMOUNT: u64 = 250;
    const EXPIRY: u64 = 1_900_000_000;

    let tree = Keypair::new().pubkey();
    let taker_payer = Keypair::new();
    let taker = keypair_from_payer(&taker_payer);
    let taker_recipient = taker.shielded_address().expect("taker address");
    let maker = ShieldedKeypair::from_seed_ed25519(&[0x51; 32]).expect("maker keypair");
    let maker_recipient = maker.shielded_address().expect("maker address");

    let terms = OrderTerms {
        destination_mint: SOL_MINT,
        destination_amount: DESTINATION_AMOUNT,
        destination: maker_recipient,
        taker: Address::new_from_array(taker.signing_pubkey().as_ed25519().expect("taker pubkey")),
        expiry: EXPIRY,
        fill_mode: swap_prover::FILL_MODE_DERIVED,
    };
    let escrow = OrderUtxo {
        terms,
        blinding: [7u8; 31],
        source_mint: SOL_MINT,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: SOL_ASSET_ID,
    };

    let taker_in_blinding: Blinding = [13u8; 31];
    let source_output_blinding: Blinding = [31u8; 31];

    let taker_in = Recipient {
        address: taker_recipient,
        amount: DESTINATION_AMOUNT,
        blinding: taker_in_blinding,
        mint: SOL_MINT,
    }
    .output();
    let fill_shared = FillProofInputParams {
        escrow: escrow.clone(),
        taker_in,
        source_output_blinding,
        external_data_hash: [0u8; 32],
        maker_recipient,
        taker_recipient,
    };
    let source_output = fill_shared.source_output();
    let destination_output = fill_shared
        .destination_output()
        .expect("destination output");

    let escrow_input = escrow.into_input_utxo().expect("escrow spend");
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
    let input_utxos = vec![escrow_input, taker_spend];
    let transaction_viewing_key =
        get_transaction_viewing_key(&taker, &input_utxos).expect("fill transaction viewing key");

    let encoded = encrypt_transaction_data(
        &[source_output, destination_output],
        &assets,
        &transaction_viewing_key,
    )
    .expect("encode fill slots");

    let mut external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    external_data.expiry_unix_ts = escrow.terms.expiry;
    let spp_proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        payer_address,
    );

    let commitments = spp_proof_inputs
        .input_utxo_hashes()
        .expect("input commitments");
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

    let external_data_hash = spp_proof_inputs
        .external_data
        .hash()
        .expect("external data hash");
    let fill_shared = FillProofInputParams {
        external_data_hash,
        ..fill_shared
    };

    let prover = ProverClient::local();
    let swap_prover_client = SwapProverClient::new_ffi();
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &prover);
    let t1 = Instant::now();
    let fill_result = swap_prover_client
        .prove_fill(&fill_shared)
        .expect("swap fill prove");
    let swap_dur = t1.elapsed();

    let ix = Fill {
        payer: taker_payer.pubkey(),
        tree,
        fill_proof: fill_result.proof.into(),
        spp_proof: transact,
    }
    .instruction()
    .expect("fill instruction");

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
    bench.add_table("fill", proving_time_table(spp_dur, swap_dur));
    bench.add_table("fill", tx_size_table(&ix, &taker_payer.pubkey()));
}

// fill: escrow + taker destination inputs -> source (to taker) + destination (to
// maker, verifiably encrypted) (2x2). The escrow is spent via the opening; the
// swap program signs for the escrow-authority PDA via invoke_signed.
fn bench_fill(mollusk: &mut Mollusk, spp_id: &MolluskPubkey, bench: &mut CuBenchmark) {
    const SOURCE_AMOUNT: u64 = 400_000;
    const DESTINATION_AMOUNT: u64 = 250;
    const EXPIRY: u64 = 1_900_000_000;

    let tree = Keypair::new().pubkey();
    let taker_payer = Keypair::new();
    let taker = keypair_from_payer(&taker_payer);
    let taker_recipient = taker.shielded_address().expect("taker address");
    let maker = ShieldedKeypair::from_seed_ed25519(&[0x51; 32]).expect("maker keypair");
    let maker_recipient = maker.shielded_address().expect("maker address");

    let terms = OrderTerms {
        destination_mint: SOL_MINT,
        destination_amount: DESTINATION_AMOUNT,
        destination: maker_recipient,
        taker: Address::new_from_array(taker.signing_pubkey().as_ed25519().expect("taker pubkey")),
        expiry: EXPIRY,
        fill_mode: swap_prover::FILL_MODE_VERIFIABLE,
    };
    let escrow = OrderUtxo {
        terms,
        blinding: [7u8; 31],
        source_mint: SOL_MINT,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: SOL_ASSET_ID,
    };

    let taker_in_blinding: Blinding = [13u8; 31];
    let destination_output_blinding: Blinding = [21u8; 31];
    let source_output_blinding: Blinding = [31u8; 31];

    let fill_shared = FillVerifiableEncryptionProofInputParams {
        escrow: escrow.clone(),
        taker_in_blinding,
        destination_output_blinding,
        source_output_blinding,
        external_data_hash: [0u8; 32],
        maker_recipient,
        taker_recipient,
    };
    let destination_ciphertext = fill_shared
        .into_proof_inputs()
        .expect("fill proof inputs")
        .destination_ciphertext()
        .expect("destination ciphertext");
    let source_output = fill_shared.source_output();
    let destination_output = fill_shared.destination_output();

    let escrow_input = escrow.into_input_utxo().expect("escrow spend");
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
    let destination_view_tag = maker_recipient
        .signing_pubkey
        .confidential_view_tag()
        .expect("maker view tag");
    let input_utxos = vec![escrow_input, taker_spend];
    let transaction_viewing_key =
        get_transaction_viewing_key(&taker, &input_utxos).expect("fill transaction viewing key");

    let mut encoded = encrypt_transaction_data(&[source_output], &assets, &transaction_viewing_key)
        .expect("encode fill source slot");
    let destination_utxo_hash = destination_output.hash().expect("fill output hash");
    encoded.outputs.push(TransactOutput {
        utxo_hash: destination_utxo_hash,
        owner_tag: OwnerTag::Inline(destination_view_tag),
        data: Some(destination_ciphertext),
    });
    encoded.resolved_owner_tags.push(destination_view_tag);
    encoded.output_utxos.push(destination_output);

    let mut external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    external_data.expiry_unix_ts = escrow.terms.expiry;
    let spp_proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        payer_address,
    );

    let commitments = spp_proof_inputs
        .input_utxo_hashes()
        .expect("input commitments");
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

    let external_data_hash = spp_proof_inputs
        .external_data
        .hash()
        .expect("external data hash");
    let fill_shared = FillVerifiableEncryptionProofInputParams {
        external_data_hash,
        ..fill_shared
    };

    let prover = ProverClient::local();
    let swap_prover_client = SwapProverClient::new_ffi();
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &prover);
    let t1 = Instant::now();
    let fill_result = swap_prover_client
        .prove_fill_verifiable_encryption(&fill_shared)
        .expect("swap fill prove");
    let swap_dur = t1.elapsed();

    let ix = FillVerifiableEncryption {
        payer: taker_payer.pubkey(),
        tree,
        fill_proof: fill_result.proof.into(),
        spp_proof: transact,
    }
    .instruction()
    .expect("fill_verifiable_encryption instruction");

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
    bench.add_table(
        "fill_verifiable_encryption",
        proving_time_table(spp_dur, swap_dur),
    );
    bench.add_table(
        "fill_verifiable_encryption",
        tx_size_table(&ix, &taker_payer.pubkey()),
    );
}

// cancel: escrow input -> source output back to the maker (1x1), after the order
// expiry. The SPP transact carries a future relayer deadline; the committed order
// expiry rides the cancel ix and proof, checked on-chain as `now > order_expiry`.
fn bench_cancel(mollusk: &mut Mollusk, spp_id: &MolluskPubkey, bench: &mut CuBenchmark) {
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
    let terms = OrderTerms {
        destination_mint: Address::new_from_array([7u8; 32]),
        destination_amount: 250,
        destination: maker_recipient,
        taker: Address::new_from_array(taker.signing_pubkey().as_ed25519().expect("taker pubkey")),
        expiry: ORDER_EXPIRY,
        fill_mode: swap_prover::FILL_MODE_VERIFIABLE,
    };
    let escrow = OrderUtxo {
        terms,
        blinding: [7u8; 31],
        source_mint: SOL_MINT,
        source_amount: SOURCE_AMOUNT,
        destination_asset_id: 2,
    };
    let source_output_blinding: Blinding = [19u8; 31];

    let cancel_inputs = CancelProofInputParams {
        escrow: escrow.clone(),
        taker_viewing_pk,
        source_output_blinding,
        external_data_hash: [0u8; 32],
        maker_recipient,
    };
    let source_output = cancel_inputs.source_output();

    let escrow_input = escrow.into_input_utxo().expect("escrow spend");

    let payer_address = Address::new_from_array(maker_payer.pubkey().to_bytes());
    let assets = AssetRegistry::default();
    let input_utxos = vec![escrow_input];
    let transaction_viewing_key =
        get_transaction_viewing_key(&maker, &input_utxos).expect("cancel transaction viewing key");

    let encoded = encrypt_transaction_data(&[source_output], &assets, &transaction_viewing_key)
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

    let external_data_hash = spp_proof_inputs
        .external_data
        .hash()
        .expect("external data hash");
    let cancel_inputs = CancelProofInputParams {
        external_data_hash,
        ..cancel_inputs
    };

    let prover = ProverClient::local();
    let swap_prover_client = SwapProverClient::new_ffi();
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &prover);
    let t1 = Instant::now();
    let cancel_result = swap_prover_client
        .prove_cancel(&cancel_inputs)
        .expect("swap cancel prove");
    let swap_dur = t1.elapsed();

    let maker_signer = Pubkey::new_from_array(
        cancel_inputs
            .maker_recipient
            .signing_pubkey
            .as_ed25519()
            .expect("maker ed25519"),
    );
    let ix = Cancel {
        maker: maker_signer,
        payer: maker_payer.pubkey(),
        tree,
        cancel_proof: cancel_result.proof.into(),
        order_expiry: escrow.terms.expiry,
        spp_proof: transact,
    }
    .instruction()
    .expect("cancel instruction");

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
    bench.add_table("cancel", proving_time_table(spp_dur, swap_dur));
    bench.add_table("cancel", tx_size_table(&ix, &maker_payer.pubkey()));
}
