use std::time::{Duration, Instant};

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
        settle::{
            derive_settle_output_blinding, Settle, SettleProofInputParams,
            MAKER_COUNTER_BLINDING_DOMAIN, MAKER_SOURCE_BLINDING_DOMAIN, RECIPIENT_BLINDING_DOMAIN,
        },
        update_price::UpdatePrice,
    },
    pair_pda,
    prover::DynamicSwapProverClient,
    shared_address::SharedShieldedAddress,
    state::{EscrowTerms, EscrowUtxo, Reservation},
    SettleProof,
};
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
use zolana_keypair::{random_blinding, ShieldedKeypair, ViewingKey};
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

// A plain, system-owned account: `lamports == 0` reads as "does not exist
// yet" to `pinocchio_system::create_account_with_minimum_balance_signed`'s
// hot path (used for every PDA `create_pair`/`create_escrow` initializes);
// `lamports > 0` models an existing wallet.
fn system_owned_account(lamports: u64) -> MolluskAccount {
    MolluskAccount {
        lamports,
        data: Vec::new(),
        owner: MolluskPubkey::new_from_array([0u8; 32]),
        executable: false,
        rent_epoch: 0,
    }
}

// The dynamic-swap program's own PDA state accounts are built directly from
// their `Pod` structs rather than by actually running `create_pair`/
// `deposit_liquidity` first: each bench only
// needs the world "as if" those prior calls already happened, exactly
// mirroring how `zk-program-swap`'s own bench constructs its order UTXOs and
// tree fixture directly instead of replaying a deposit.
fn dynamic_swap_account(bytes: Vec<u8>, program_id: &MolluskPubkey) -> MolluskAccount {
    MolluskAccount {
        lamports: 1_000_000_000,
        data: bytes,
        owner: *program_id,
        executable: false,
        rent_epoch: 0,
    }
}

fn pair_fixture(state: Pair, program_id: &MolluskPubkey) -> MolluskAccount {
    dynamic_swap_account(bytemuck::bytes_of(&state).to_vec(), program_id)
}

fn escrow_fixture(state: Escrow, program_id: &MolluskPubkey) -> MolluskAccount {
    dynamic_swap_account(bytemuck::bytes_of(&state).to_vec(), program_id)
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

fn shielded_keypair_from_seed(seed: [u8; 32]) -> ShieldedKeypair {
    ShieldedKeypair::from_ed25519(&seed, ViewingKey::new()).expect("shielded keypair from seed")
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
#[ignore = "CU benchmark; slow, needs SBF binaries + prover. Run via just bench-dynamic-swap"]
fn bench_cu_dynamic_swap() {
    std::env::set_var("SBF_OUT_DIR", PROFILING_SBF_DIR);

    let dynamic_swap_id = MolluskPubkey::new_from_array(*dynamic_swap_program::ID.as_array());
    let spp_id = MolluskPubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);

    let mut mollusk = Mollusk::default();
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&dynamic_swap_id, "dynamic_swap_program", &LOADER_V3);
    mollusk.add_program(&spp_id, "shielded_pool_program", &LOADER_V3);

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
             proof plus the dynamic-swap circuit proof) and its serialized transaction size: the \
             instruction prefixed with a compute-budget limit ix, as a legacy transaction and as \
             a v0 transaction with every non-signer account and the program id in one address \
             lookup table (Solana's packet limit is 1232 bytes) -- create_escrow and settle \
             already need the v0+ALT form to fit at all."
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

    bench.generate().expect("write BENCHMARK.md");
}

fn bench_create_pair(
    mollusk: &mut Mollusk,
    spp_id: &MolluskPubkey,
    _dynamic_swap_id: &MolluskPubkey,
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
    }
    .instruction()
    .expect("create_pair instruction");

    let fixtures = vec![
        (authority.pubkey(), system_owned_account(100_000_000_000)),
        (pair, system_owned_account(0)),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

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
    spp_id: &MolluskPubkey,
    dynamic_swap_id: &MolluskPubkey,
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
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

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
    spp_id: &MolluskPubkey,
    dynamic_swap_id: &MolluskPubkey,
    bench: &mut CuBenchmark,
) {
    const FUNDING_AMOUNT: u64 = 1_000_000_000;
    const ORDER_AMOUNT: u64 = 100_000_000;
    const MAX_PRICE: u64 = PRICE;
    const CREATED_AT: u64 = 1_000;

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
    let escrow_owner = SharedShieldedAddress::from_key_exchange(
        &authority_keypair.viewing_key,
        &user_keypair.viewing_pubkey(),
        escrow_authority_pda(&pair),
    )
    .expect("shared escrow address");
    let tree = Keypair::new().pubkey();

    let source_utxo = Utxo {
        owner: user_keypair.signing_pubkey(),
        asset: source_asset,
        amount: ORDER_AMOUNT,
        blinding: random_blinding(),
        zone_program_id: None,
        data: Data::default(),
    };
    let source_in = SppProofInputUtxo::new(source_utxo, &user_keypair);

    // The maker funds the reservation from its own destination-asset UTXO.
    let maker_funding_utxo = Utxo {
        owner: authority_keypair.signing_pubkey(),
        asset: SOL_MINT,
        amount: FUNDING_AMOUNT,
        blinding: random_blinding(),
        zone_program_id: None,
        data: Data::default(),
    };
    let maker_funding = SppProofInputUtxo::new(maker_funding_utxo, &authority_keypair);

    let recipient_owner_hash = user_keypair.owner_hash().expect("user owner hash");
    let escrow_terms = EscrowTerms {
        recipient_owner_hash,
        max_price: MAX_PRICE,
    };
    // The reservation blinding rides in the order UTXO's encrypted note, so it
    // is chosen up front and fed into the order output.
    let reservation_blinding = random_blinding();
    let escrow_utxo = EscrowUtxo {
        terms: escrow_terms,
        created_at: CREATED_AT,
        asset: source_asset,
        order_amount: ORDER_AMOUNT,
        blinding: random_blinding(),
    };
    let order_out = escrow_utxo
        .output_utxo(&escrow_owner, &reservation_blinding)
        .expect("order_out");
    let order_utxo_hash = order_out.hash().expect("order_utxo hash");

    let reserved = ORDER_AMOUNT * MAX_PRICE;
    let reservation = Reservation {
        asset: SOL_MINT,
        amount: reserved,
        blinding: reservation_blinding,
    };
    let reservation_out = reservation
        .output_utxo(&escrow_owner, order_utxo_hash)
        .expect("reservation_out");

    let authority_address = authority_keypair
        .shielded_address()
        .expect("authority shielded address");
    let maker_change =
        SppProofOutputUtxo::new(SOL_MINT, FUNDING_AMOUNT - reserved, authority_address)
            .expect("maker_change");

    // Output 1 (reservation_out) is spent only by the program itself (settle),
    // so its ciphertext is dropped.
    const RESERVATION_OUTPUT_INDEX: usize = 1;
    let mut assets = AssetRegistry::default();
    assets
        .insert(SOURCE_ASSET_ID, source_asset)
        .expect("register source asset");
    let input_utxos = vec![source_in.clone(), maker_funding.clone()];
    let viewing_key =
        get_transaction_viewing_key(&user_keypair, &input_utxos).expect("transaction viewing key");
    let encoded = encrypt_transaction_data(
        &[
            order_out.clone(),
            reservation_out.clone(),
            maker_change.clone(),
        ],
        &assets,
        &viewing_key,
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
    let external_data_hash = external_data.hash().expect("external data hash");
    let spp_proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        authority_solana.pubkey(),
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

    let prover = ProverClient::local();
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &prover);

    let escrow_authority_owner_hash = escrow_owner
        .shielded_address()
        .expect("escrow authority shielded address")
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
        external_data_hash,
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
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for 'create_escrow'"
    );
    bench.add_from_entries("create_escrow", entries);
    bench.add_table("create_escrow", proving_time_table(spp_dur, circuit_dur));
    bench.add_table(
        "create_escrow",
        tx_size_table(&ix, &authority_solana.pubkey()),
    );
}

fn bench_settle(
    mollusk: &mut Mollusk,
    spp_id: &MolluskPubkey,
    dynamic_swap_id: &MolluskPubkey,
    bench: &mut CuBenchmark,
) {
    const ORDER_AMOUNT: u64 = 100_000_000;
    const MAX_PRICE: u64 = 10;
    const EXECUTION_PRICE: u64 = 5;
    const CREATED_AT: u64 = 1_000;

    let authority_solana = Keypair::new();
    let authority_keypair = shielded_keypair_from_seed(
        authority_solana.to_bytes()[..32]
            .try_into()
            .expect("ed25519 seed is the first 32 bytes"),
    );
    let authority_owner_hash = authority_keypair
        .owner_hash()
        .expect("authority owner hash");
    let user_solana = Keypair::new();
    let user_keypair = shielded_keypair_from_seed(
        user_solana.to_bytes()[..32]
            .try_into()
            .expect("ed25519 seed is the first 32 bytes"),
    );
    let recipient_owner_hash = user_keypair.owner_hash().expect("user owner hash");
    let source_asset = Address::new_from_array([2u8; 32]);

    let pair = pair_pda(
        &authority_solana.pubkey(),
        SOURCE_ASSET_ID,
        DESTINATION_ASSET_ID,
    );
    let escrow_owner = SharedShieldedAddress::from_key_exchange(
        &authority_keypair.viewing_key,
        &user_keypair.viewing_pubkey(),
        escrow_authority_pda(&pair),
    )
    .expect("shared escrow address");
    let tree = Keypair::new().pubkey();

    let escrow_terms = EscrowTerms {
        recipient_owner_hash,
        max_price: MAX_PRICE,
    };
    let escrow_utxo = EscrowUtxo {
        terms: escrow_terms,
        created_at: CREATED_AT,
        asset: source_asset,
        order_amount: ORDER_AMOUNT,
        blinding: random_blinding(),
    };
    let order_in = escrow_utxo.to_input_utxo(&escrow_owner).expect("order_in");
    let order_in_hash = ProofInputUtxo::try_from(&order_in)
        .expect("order_in proof utxo")
        .hash()
        .expect("order_in hash");

    let reserved = ORDER_AMOUNT * MAX_PRICE;
    let reservation = Reservation {
        asset: SOL_MINT,
        amount: reserved,
        blinding: random_blinding(),
    };
    let reservation_in = reservation
        .to_input_utxo(&escrow_owner, order_in_hash)
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
    let mut recipient_out = SppProofOutputUtxo::new(
        SOL_MINT,
        owed,
        user_keypair.shielded_address().expect("user address"),
    )
    .expect("recipient_out");
    let mut maker_counter =
        SppProofOutputUtxo::new(SOL_MINT, remainder, authority_address).expect("maker_counter");
    let mut maker_source = SppProofOutputUtxo::new(source_asset, ORDER_AMOUNT, authority_address)
        .expect("maker_source");

    // The circuit fixes each output blinding to a derivation over both input
    // blindings; the same value feeds the SPP transaction and the settle proof.
    recipient_out.blinding = derive_settle_output_blinding(
        &escrow_utxo.blinding,
        &reservation.blinding,
        RECIPIENT_BLINDING_DOMAIN,
    )
    .expect("recipient_out blinding");
    maker_counter.blinding = derive_settle_output_blinding(
        &escrow_utxo.blinding,
        &reservation.blinding,
        MAKER_COUNTER_BLINDING_DOMAIN,
    )
    .expect("maker_counter blinding");
    maker_source.blinding = derive_settle_output_blinding(
        &escrow_utxo.blinding,
        &reservation.blinding,
        MAKER_SOURCE_BLINDING_DOMAIN,
    )
    .expect("maker_source blinding");

    // maker_counter (output index 1) returns to the maker and is tracked
    // off-chain, so its ciphertext is dropped.
    const MAKER_COUNTER_INDEX: usize = 1;
    let mut assets = AssetRegistry::default();
    assets
        .insert(SOURCE_ASSET_ID, source_asset)
        .expect("register source asset");
    let input_utxos = vec![order_in.clone(), reservation_in.clone()];
    let viewing_key = get_transaction_viewing_key(&authority_keypair, &input_utxos)
        .expect("transaction viewing key");
    let encoded = encrypt_transaction_data(
        &[
            recipient_out.clone(),
            maker_counter.clone(),
            maker_source.clone(),
        ],
        &assets,
        &viewing_key,
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
    let external_data_hash = external_data.hash().expect("external data hash");
    let spp_proof_inputs = SppProofInputs::new(
        input_utxos,
        encoded.output_utxos,
        external_data,
        authority_solana.pubkey(),
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

    let prover = ProverClient::local();
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &prover);

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
        external_data_hash,
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
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for 'settle'");
    bench.add_from_entries("settle", entries);
    bench.add_table("settle", proving_time_table(spp_dur, circuit_dur));
    bench.add_table("settle", tx_size_table(&ix, &authority_solana.pubkey()));
}
