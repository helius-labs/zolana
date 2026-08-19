use std::time::{Duration, Instant};

use dynamic_swap_program::state::{
    discriminator::{ESCROW, PAIR},
    Escrow, Pair,
};
use dynamic_swap_prover::ProofInputUtxo;
use dynamic_swap_sdk::{
    escrow_pda,
    instructions::{
        cancel::{Cancel, CancelProofInputParams},
        create_escrow::{CreateEscrow, EscrowOpenProofInputParams},
        create_pair::CreatePair,
        settle::{
            derive_output_blinding, Settle, SettleProofInputParams,
            CANCEL_REFUND_BLINDING_DOMAIN, FUNDER_CHANGE_BLINDING_DOMAIN,
            FUNDER_RECEIPT_BLINDING_DOMAIN, RECIPIENT_BLINDING_DOMAIN,
        },
        update_price::UpdatePrice,
    },
    pair_pda,
    prover::DynamicSwapProverClient,
    state::{escrow_authority_identity, EscrowUtxo},
    Groth16ProofBytes,
};
use light_program_profiler::{
    mollusk::{register_profiling_syscalls, take_profiling_entries},
    report::{CuBenchmark, ReadmeConfig, SectionTable},
};
use mollusk_svm::{result::Check, Mollusk};
use num_bigint::BigUint;
use solana_account::Account;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use zolana_client::{
    MerkleContext, MerkleProof, NonInclusionProof, ProverClient, SpendProof, NULLIFIER_TREE_HEIGHT,
    STATE_TREE_HEIGHT,
};
use zolana_hasher::Poseidon;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData,
    state::{
        address_tree_params, discriminator::TREE_ACCOUNT_DISCRIMINATOR, tree_account_size,
        STATE_HEIGHT,
    },
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, ShieldedKeypair, ShieldedPda, SigningKey};
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};
use zolana_transaction::{
    instructions::{
        transact::{
            encrypt_transaction_data, get_transaction_viewing_key,
            spp_proof_inputs::{asset_field, BN254_MODULUS_DEC},
            ExternalData, SppProofInputs, SppProofOutputUtxo,
        },
        types::SppProofInputUtxo,
    },
    AssetRegistry, Data, Utxo, SOL_MINT,
};
use zolana_tree::TreeAccount;

const PROFILING_SBF_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../target/dynamic-swap-bench"
);
const OUTPUT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../BENCHMARK.md");
const PROVER_KEYS_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../prover/server/proving-keys"
);

const SOURCE_ASSET_ID: u64 = 2;
const DESTINATION_ASSET_ID: u64 = 1;
const PRICE: u64 = 5;
const EXPIRY_SLOTS: u64 = 1_000;

fn mollusk_program_account(program_id: &Pubkey) -> (Pubkey, Account) {
    let account = mollusk_svm::program::create_program_account_loader_v3(program_id);
    (*program_id, account)
}

// A plain, system-owned account: `lamports == 0` reads as "does not exist
// yet" to `pinocchio_system::create_account_with_minimum_balance_signed`'s
// hot path (used for every PDA `create_pair`/`create_escrow` initializes);
// `lamports > 0` models an existing wallet.
fn system_owned_account(lamports: u64) -> Account {
    Account {
        lamports,
        data: Vec::new(),
        owner: Pubkey::new_from_array([0u8; 32]),
        executable: false,
        rent_epoch: 0,
    }
}

// The dynamic-swap program's own PDA state accounts are built directly from
// their `Pod` structs rather than by actually running the prior instruction
// chain: each bench only needs the world "as if" those prior calls already
// happened.
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

/// A well-formed pair fixture for the new layout: the encryption pubkey only
/// needs a valid SEC1 prefix for the program's checks that read it.
fn bench_encryption_pubkey() -> [u8; 33] {
    let mut pubkey = [9u8; 33];
    pubkey[0] = 0x02;
    pubkey
}

fn build_tree_fixture(tree: &Pubkey, leaves: &[[u8; 32]]) -> (Account, [u8; 32], [u8; 32], u16) {
    let mut tree_account_bytes = vec![0u8; tree_account_size()];
    let root_index = leaves.len() as u16;
    let (utxo_root, nullifier_root) = {
        let mut account = TreeAccount::init(
            &mut tree_account_bytes,
            TREE_ACCOUNT_DISCRIMINATOR,
            STATE_HEIGHT as u8,
            tree.to_bytes(),
            address_tree_params(),
        )
        .expect("init tree account");
        for leaf in leaves {
            account.utxo_tree().append(*leaf).expect("append leaf");
        }
        (
            account.get_utxo_tree_root(root_index).expect("utxo root"),
            account.get_nullifier_tree_root(0).expect("nullifier root"),
        )
    };
    let fixture = Account {
        lamports: 1_000_000_000_000,
        data: tree_account_bytes,
        owner: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
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
        tree: *tree,
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

// Maps every account an instruction references onto its mollusk fixture:
// `spp_id` -> the shielded-pool program's own loader-v3 account (it is CPI'd
// into and, for the event self-CPI, appears again inside the forwarded
// account list); `Pubkey::default()` -> the system program (its address is
// literally the all-zero pubkey both SPP and this program use as a
// placeholder); anything else explicit in `fixtures` -> that fixture;
// anything left over -> a funded, empty, system-owned wallet (fee payers,
// PDA signer placeholders whose address alone matters for CPI signer checks).
fn assemble_accounts(
    ix: &Instruction,
    spp_id: &Pubkey,
    fixtures: &[(Pubkey, Account)],
) -> Vec<(Pubkey, Account)> {
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
                (meta.pubkey, account.clone())
            } else {
                (meta.pubkey, system_owned_account(1_000_000_000))
            }
        })
        .collect()
}

fn shielded_keypair_from_seed(seed: [u8; 32]) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&seed))
        .expect("shielded keypair from seed")
}

fn prove_transact_timed(
    proof_inputs: SppProofInputs,
    spend_proofs: &[SpendProof],
    prover: &ProverClient,
) -> (TransactIxData, Duration) {
    prover
        .prove_transact(proof_inputs.clone(), spend_proofs, &[])
        .expect("warm prove transact");
    let start = Instant::now();
    let transact = prover
        .prove_transact(proof_inputs, spend_proofs, &[])
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

fn proving_time_table(spp: Duration, circuit: Duration) -> SectionTable {
    SectionTable {
        title: "Proving Time".into(),
        headers: vec![
            "SPP transfer proof".into(),
            "Dynamic-swap circuit proof".into(),
            "Total".into(),
        ],
        rows: vec![vec![
            format!("{} ms", spp.as_millis()),
            format!("{} ms", circuit.as_millis()),
            format!("{} ms", (spp + circuit).as_millis()),
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
            .map(|meta| meta.pubkey)
            .chain(std::iter::once(ix.program_id))
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
             create_escrow/settle/cancel instructions, replayed under mollusk. Every PDA account \
             (Pair, Escrow) and the shielded-pool tree account are built directly, as if the prior \
             instruction chain already ran -- only the ONE instruction under \
             measurement is actually replayed. Only the dynamic-swap program is profiled; the \
             shielded-pool program is built plain, so the CU its CPI consumes is charged to the \
             `cpi_spp_transact*` row as a black box and its internal functions do not appear \
             here. update_price never verifies a proof or CPI into SPP at all \
             (the whole point of keeping it cheap); create_escrow (taker-only, IN1_OUT2), settle \
             (maker-funded, IN2_OUT3), and cancel (after expiry, IN1_OUT1) each verify their own \
             Groth16 proof and then CPI SPP `transact`, which verifies its own. Each \
             proof-carrying instruction's section also records its proving times (SPP transfer \
             proof plus the dynamic-swap circuit proof) and its serialized transaction size: the \
             instruction prefixed with a compute-budget limit ix, as a legacy transaction and as \
             a v0 transaction with every non-signer account and the program id in one address \
             lookup table (Solana's packet limit is 1232 bytes). Dropping the maker legs from \
             create_escrow brought it and cancel back under the limit as plain legacy \
             transactions; only settle still needs the v0+ALT form."
            .into(),
        output_path: OUTPUT_PATH.into(),
        regenerate_command: Some("just bench-dynamic-swap".into()),
        ..Default::default()
    });

    start_prover();

    bench_create_pair(&mut mollusk, &spp_id, &dynamic_swap_id, &mut bench);
    bench_update_price(&mut mollusk, &spp_id, &dynamic_swap_id, &mut bench);
    bench_create_escrow(&mut mollusk, &spp_id, &dynamic_swap_id, &mut bench);
    bench_settle(&mut mollusk, &spp_id, &dynamic_swap_id, &mut bench);
    bench_cancel(&mut mollusk, &spp_id, &dynamic_swap_id, &mut bench);

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
        expiry_slots: EXPIRY_SLOTS,
        source_asset: [0u8; 32],
        destination_asset: [0u8; 32],
        maker_encryption_pubkey: bench_encryption_pubkey(),
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
        authority: authority.pubkey(),
        source_asset_id: SOURCE_ASSET_ID,
        destination_asset_id: DESTINATION_ASSET_ID,
        price: PRICE,
        expiry_slots: EXPIRY_SLOTS,
        source_asset: [0u8; 32],
        destination_asset: [0u8; 32],
        maker_encryption_pubkey: bench_encryption_pubkey(),
        _pad2: [0u8; 7],
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

/// The identity + escrow-account world shared by the create_escrow, settle,
/// and cancel benches: one taker, one maker, one pair, one order UTXO.
struct EscrowBenchWorld {
    authority_solana: Keypair,
    authority_keypair: ShieldedKeypair,
    user_solana: Keypair,
    user_keypair: ShieldedKeypair,
    source_asset: Address,
    pair: Pubkey,
    escrow_owner: ShieldedPda,
    tree: Pubkey,
    escrow_utxo: EscrowUtxo,
    assets: AssetRegistry,
}

const ORDER_AMOUNT: u64 = 100_000_000;
const FUNDING_AMOUNT: u64 = 1_000_000_000;
const CREATED_AT: u64 = 1_000;

fn escrow_bench_world() -> EscrowBenchWorld {
    let authority_solana = Keypair::new();
    let authority_keypair = shielded_keypair_from_seed(
        authority_solana.to_bytes()[..32]
            .try_into()
            .expect("ed25519 seed is the first 32 bytes"),
    );
    let user_solana = Keypair::new();
    let user_keypair = shielded_keypair_from_seed(
        user_solana.to_bytes()[..32]
            .try_into()
            .expect("ed25519 seed is the first 32 bytes"),
    );
    let source_asset = Address::new_from_array([2u8; 32]);
    let pair = pair_pda(
        &authority_solana.pubkey(),
        SOURCE_ASSET_ID,
        DESTINATION_ASSET_ID,
    );
    let escrow_owner = escrow_authority_identity(&pair, &authority_keypair.viewing_key)
        .expect("escrow authority identity");
    let recipient_owner_hash = user_keypair.owner_hash().expect("user owner hash");
    let escrow_utxo = EscrowUtxo {
        recipient_owner_hash,
        asset: source_asset,
        order_amount: ORDER_AMOUNT,
        blinding: random_blinding(),
    };
    let mut assets = AssetRegistry::default();
    assets
        .insert(SOURCE_ASSET_ID, source_asset)
        .expect("register source asset");
    EscrowBenchWorld {
        authority_solana,
        authority_keypair,
        user_solana,
        user_keypair,
        source_asset,
        pair,
        escrow_owner,
        tree: Keypair::new().pubkey(),
        escrow_utxo,
        assets,
    }
}

impl EscrowBenchWorld {
    fn pair_state(&self) -> Pair {
        Pair {
            discriminator: PAIR,
            bump: 255,
            _pad: [0u8; 6],
            authority: self.authority_solana.pubkey(),
            source_asset_id: SOURCE_ASSET_ID,
            destination_asset_id: DESTINATION_ASSET_ID,
            price: PRICE,
            expiry_slots: EXPIRY_SLOTS,
            source_asset: asset_field(&self.source_asset).expect("source asset field"),
            destination_asset: asset_field(&SOL_MINT).expect("destination asset field"),
            maker_encryption_pubkey: *self.escrow_owner.viewing_pubkey().as_bytes(),
            _pad2: [0u8; 7],
        }
    }

    fn order_in(&self) -> (SppProofInputUtxo, [u8; 32]) {
        let order_in = self
            .escrow_utxo
            .to_input_utxo(
                &self
                    .escrow_owner
                    .shielded_address()
                    .expect("escrow authority address"),
            )
            .expect("order_in");
        let order_in_hash = ProofInputUtxo::try_from(&order_in)
            .expect("order_in proof utxo")
            .hash()
            .expect("order_in hash");
        (order_in, order_in_hash)
    }

    fn escrow_state(&self, order_utxo_hash: [u8; 32]) -> Escrow {
        Escrow {
            discriminator: ESCROW,
            bump: 255,
            _pad: [0u8; 6],
            pair: self.pair,
            order_utxo_hash,
            owner: self.user_solana.pubkey(),
            created_at: CREATED_AT,
            execution_price: PRICE,
        }
    }
}

fn bench_create_escrow(
    mollusk: &mut Mollusk,
    spp_id: &Pubkey,
    dynamic_swap_id: &Pubkey,
    bench: &mut CuBenchmark,
) {
    let world = escrow_bench_world();

    let source_utxo = Utxo {
        owner: world.user_keypair.signing_pubkey(),
        asset: world.source_asset,
        amount: FUNDING_AMOUNT,
        blinding: random_blinding(),
        ring_program_id: None,
        data: Data::default(),
    };
    let source_in = SppProofInputUtxo::new(source_utxo, &world.user_keypair);

    let escrow_authority_address = world
        .escrow_owner
        .shielded_address()
        .expect("escrow authority address");
    let order_out = world
        .escrow_utxo
        .output_utxo(&escrow_authority_address)
        .expect("order_out");
    let order_utxo_hash = order_out.hash().expect("order_utxo hash");

    let user_address = world
        .user_keypair
        .shielded_address()
        .expect("user address");
    let taker_change =
        SppProofOutputUtxo::new(world.source_asset, FUNDING_AMOUNT - ORDER_AMOUNT, user_address)
            .expect("taker_change");

    // Both ciphertexts are kept: the order slot is the maker handoff, the
    // change slot is the taker's own note.
    let input_utxos = vec![source_in.clone()];
    let viewing_key = get_transaction_viewing_key(&world.user_keypair, &input_utxos)
        .expect("transaction viewing key");
    let encoded = encrypt_transaction_data(
        &[order_out.clone(), taker_change.clone()],
        &world.assets,
        &viewing_key,
    )
    .expect("encode outputs");
    let external_data = ExternalData::new(
        *viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    let external_data_hash = external_data.hash().expect("external data hash");
    // The escrow authority owns the data-bearing order output but spends no
    // input, so it must be declared as the extra owner signer.
    let spp_proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        world.user_solana.pubkey(),
    )
    .with_owner_signer(
        escrow_authority_address
            .solana_address()
            .expect("escrow authority solana address"),
    );

    let commitments = spp_proof_inputs
        .input_utxo_hashes()
        .expect("input commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|input| input.utxo_hash).collect();
    let (tree_account, utxo_root, nullifier_root, root_index) =
        build_tree_fixture(&world.tree, &leaves);
    let state_tree = local_state_tree(&leaves);
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let nf_tree = nullifier_tree();
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let spend_proofs = build_spend_proofs(
        &world.tree,
        &state_tree,
        &nf_tree,
        &commitments,
        utxo_root,
        nullifier_root,
        root_index,
    );

    let prover = ProverClient::local();
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &prover);

    let proof_inputs = EscrowOpenProofInputParams {
        source_in,
        order_out,
        taker_change,
        escrow_authority_owner_hash: escrow_authority_address
            .owner_hash()
            .expect("escrow authority owner hash"),
        source_asset: asset_field(&world.source_asset).expect("source asset field"),
        order_amount: ORDER_AMOUNT,
        external_data_hash,
    }
    .to_proof_inputs()
    .expect("escrow_open proof inputs");
    let circuit_start = Instant::now();
    let order_proof = DynamicSwapProverClient::new()
        .prove_escrow_open(&proof_inputs)
        .expect("prove escrow_open");
    let circuit_dur = circuit_start.elapsed();

    let escrow = escrow_pda(&order_utxo_hash);
    let ix = CreateEscrow {
        taker: world.user_solana.pubkey(),
        pair: world.pair,
        escrow,
        tree: world.tree,
        proof: Groth16ProofBytes {
            proof_a: order_proof.proof_a,
            proof_b: order_proof.proof_b,
            proof_c: order_proof.proof_c,
        },
        max_price: PRICE,
        transact,
    }
    .instruction()
    .expect("create_escrow instruction");

    // `created_at` is program-stamped from the Clock sysvar; any slot works.
    mollusk.sysvars.clock.slot = CREATED_AT;

    let fixtures = vec![
        (
            world.user_solana.pubkey(),
            system_owned_account(100_000_000_000),
        ),
        (world.pair, pair_fixture(world.pair_state(), dynamic_swap_id)),
        (escrow, system_owned_account(0)),
        (world.tree, tree_account),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for 'create_escrow'"
    );
    bench.add_from_entries("create_escrow", entries);
    bench.add_table("create_escrow", proving_time_table(spp_dur, circuit_dur));
    bench.add_table(
        "create_escrow",
        tx_size_table(&ix, &world.user_solana.pubkey()),
    );
}

fn bench_settle(
    mollusk: &mut Mollusk,
    spp_id: &Pubkey,
    dynamic_swap_id: &Pubkey,
    bench: &mut CuBenchmark,
) {
    let world = escrow_bench_world();

    let (order_in, order_in_hash) = world.order_in();

    // The funder brings its own destination-asset note at fill time.
    let maker_funding_utxo = Utxo {
        owner: world.authority_keypair.signing_pubkey(),
        asset: SOL_MINT,
        amount: FUNDING_AMOUNT,
        blinding: random_blinding(),
        ring_program_id: None,
        data: Data::default(),
    };
    let funding_blinding = maker_funding_utxo.blinding;
    let maker_funding = SppProofInputUtxo::new(maker_funding_utxo, &world.authority_keypair);

    let owed = ORDER_AMOUNT * PRICE;
    let change_amount = FUNDING_AMOUNT - owed;

    let authority_address = world
        .authority_keypair
        .shielded_address()
        .expect("authority shielded address");
    let mut recipient_out = SppProofOutputUtxo::new(
        SOL_MINT,
        owed,
        world.user_keypair.shielded_address().expect("user address"),
    )
    .expect("recipient_out");
    let mut funder_change =
        SppProofOutputUtxo::new(SOL_MINT, change_amount, authority_address).expect("funder_change");
    let mut funder_receipt =
        SppProofOutputUtxo::new(world.source_asset, ORDER_AMOUNT, authority_address)
            .expect("funder_receipt");

    // The circuit fixes each output blinding to a derivation over one input
    // blinding; the same value feeds the SPP transaction and the settle proof.
    recipient_out.blinding =
        derive_output_blinding(&world.escrow_utxo.blinding, RECIPIENT_BLINDING_DOMAIN)
            .expect("recipient_out blinding");
    funder_change.blinding =
        derive_output_blinding(&funding_blinding, FUNDER_CHANGE_BLINDING_DOMAIN)
            .expect("funder_change blinding");
    funder_receipt.blinding =
        derive_output_blinding(&funding_blinding, FUNDER_RECEIPT_BLINDING_DOMAIN)
            .expect("funder_receipt blinding");

    // funder_change (output index 1) returns to the funder and is tracked
    // off-chain, so its ciphertext is dropped.
    const FUNDER_CHANGE_INDEX: usize = 1;
    let input_utxos = vec![order_in.clone(), maker_funding.clone()];
    let viewing_key = get_transaction_viewing_key(&world.authority_keypair, &input_utxos)
        .expect("transaction viewing key");
    let encoded = encrypt_transaction_data(
        &[
            recipient_out.clone(),
            funder_change.clone(),
            funder_receipt.clone(),
        ],
        &world.assets,
        &viewing_key,
    )
    .expect("encode outputs");
    let mut outputs = encoded.outputs;
    outputs
        .get_mut(FUNDER_CHANGE_INDEX)
        .expect("funder_change output index in range")
        .data = None;
    let external_data = ExternalData::new(
        *viewing_key.pubkey().as_bytes(),
        encoded.salt,
        outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    let external_data_hash = external_data.hash().expect("external data hash");
    let spp_proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        world.authority_solana.pubkey(),
    );

    let commitments = spp_proof_inputs
        .input_utxo_hashes()
        .expect("input commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|input| input.utxo_hash).collect();
    let (tree_account, utxo_root, nullifier_root, root_index) =
        build_tree_fixture(&world.tree, &leaves);
    let state_tree = local_state_tree(&leaves);
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let nf_tree = nullifier_tree();
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let spend_proofs = build_spend_proofs(
        &world.tree,
        &state_tree,
        &nf_tree,
        &commitments,
        utxo_root,
        nullifier_root,
        root_index,
    );

    let prover = ProverClient::local();
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &prover);

    let proof_inputs = SettleProofInputParams {
        order_in,
        maker_funding,
        recipient_out,
        funder_change,
        funder_receipt,
        execution_price: PRICE,
        order_amount: ORDER_AMOUNT,
        order_utxo_hash: order_in_hash,
        destination_asset: asset_field(&SOL_MINT).expect("destination asset field"),
        external_data_hash,
    }
    .to_proof_inputs()
    .expect("escrow_settle proof inputs");
    let circuit_start = Instant::now();
    let order_proof = DynamicSwapProverClient::new()
        .prove_escrow_settle(&proof_inputs)
        .expect("prove escrow_settle");
    let circuit_dur = circuit_start.elapsed();

    let escrow = escrow_pda(&order_in_hash);
    let ix = Settle {
        funder: world.authority_solana.pubkey(),
        pair: world.pair,
        escrow,
        rent_recipient: world.user_solana.pubkey(),
        tree: world.tree,
        proof: Groth16ProofBytes {
            proof_a: order_proof.proof_a,
            proof_b: order_proof.proof_b,
            proof_c: order_proof.proof_c,
        },
        transact,
    }
    .instruction()
    .expect("settle instruction");

    // Inside the settle window: created_at <= slot <= created_at + expiry.
    mollusk.sysvars.clock.slot = CREATED_AT + 1;

    let fixtures = vec![
        (
            world.authority_solana.pubkey(),
            system_owned_account(100_000_000_000),
        ),
        (
            world.user_solana.pubkey(),
            system_owned_account(1_000_000_000),
        ),
        (world.pair, pair_fixture(world.pair_state(), dynamic_swap_id)),
        (
            escrow,
            escrow_fixture(world.escrow_state(order_in_hash), dynamic_swap_id),
        ),
        (world.tree, tree_account),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for 'settle'");
    bench.add_from_entries("settle", entries);
    bench.add_table("settle", proving_time_table(spp_dur, circuit_dur));
    bench.add_table(
        "settle",
        tx_size_table(&ix, &world.authority_solana.pubkey()),
    );
}

fn bench_cancel(
    mollusk: &mut Mollusk,
    spp_id: &Pubkey,
    dynamic_swap_id: &Pubkey,
    bench: &mut CuBenchmark,
) {
    let world = escrow_bench_world();

    let (order_in, order_in_hash) = world.order_in();

    let mut refund_out = SppProofOutputUtxo::new(
        world.source_asset,
        ORDER_AMOUNT,
        world.user_keypair.shielded_address().expect("user address"),
    )
    .expect("refund_out");
    refund_out.blinding =
        derive_output_blinding(&world.escrow_utxo.blinding, CANCEL_REFUND_BLINDING_DOMAIN)
            .expect("refund_out blinding");

    let input_utxos = vec![order_in.clone()];
    let viewing_key = get_transaction_viewing_key(&world.user_keypair, &input_utxos)
        .expect("transaction viewing key");
    let encoded = encrypt_transaction_data(&[refund_out.clone()], &world.assets, &viewing_key)
        .expect("encode outputs");
    let external_data = ExternalData::new(
        *viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    let external_data_hash = external_data.hash().expect("external data hash");
    let spp_proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        world.user_solana.pubkey(),
    );

    let commitments = spp_proof_inputs
        .input_utxo_hashes()
        .expect("input commitments");
    let leaves: Vec<[u8; 32]> = commitments.iter().map(|input| input.utxo_hash).collect();
    let (tree_account, utxo_root, nullifier_root, root_index) =
        build_tree_fixture(&world.tree, &leaves);
    let state_tree = local_state_tree(&leaves);
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let nf_tree = nullifier_tree();
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let spend_proofs = build_spend_proofs(
        &world.tree,
        &state_tree,
        &nf_tree,
        &commitments,
        utxo_root,
        nullifier_root,
        root_index,
    );

    let prover = ProverClient::local();
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &prover);

    let proof_inputs = CancelProofInputParams {
        order_in,
        refund_out,
        order_amount: ORDER_AMOUNT,
        order_utxo_hash: order_in_hash,
        external_data_hash,
    }
    .to_proof_inputs()
    .expect("escrow_cancel proof inputs");
    let circuit_start = Instant::now();
    let cancel_proof = DynamicSwapProverClient::new()
        .prove_escrow_cancel(&proof_inputs)
        .expect("prove escrow_cancel");
    let circuit_dur = circuit_start.elapsed();

    let escrow = escrow_pda(&order_in_hash);
    let ix = Cancel {
        caller: world.user_solana.pubkey(),
        pair: world.pair,
        escrow,
        rent_recipient: world.user_solana.pubkey(),
        tree: world.tree,
        proof: Groth16ProofBytes {
            proof_a: cancel_proof.proof_a,
            proof_b: cancel_proof.proof_b,
            proof_c: cancel_proof.proof_c,
        },
        transact,
    }
    .instruction()
    .expect("cancel instruction");

    // Past the settle window: slot > created_at + expiry.
    mollusk.sysvars.clock.slot = CREATED_AT + EXPIRY_SLOTS + 1;

    let fixtures = vec![
        (
            world.user_solana.pubkey(),
            system_owned_account(100_000_000_000),
        ),
        (world.pair, pair_fixture(world.pair_state(), dynamic_swap_id)),
        (
            escrow,
            escrow_fixture(world.escrow_state(order_in_hash), dynamic_swap_id),
        ),
        (world.tree, tree_account),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for 'cancel'");
    bench.add_from_entries("cancel", entries);
    bench.add_table("cancel", proving_time_table(spp_dur, circuit_dur));
    bench.add_table("cancel", tx_size_table(&ix, &world.user_solana.pubkey()));
}
