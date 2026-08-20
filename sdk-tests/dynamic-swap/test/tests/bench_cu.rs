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
        rebalance_liquidity::{RebalanceLiquidity, RebalanceProofInputParams},
        settle::{
            derive_output_blinding, Settle, SettleProofInputParams, CANCEL_REFUND_BLINDING_DOMAIN,
            RECIPIENT_BLINDING_DOMAIN,
        },
        update_price::UpdatePrice,
        withdraw_liquidity::{WithdrawLiquidity, WithdrawProofInputParams, WithdrawSplAccounts},
    },
    pair_pda,
    prover::DynamicSwapProverClient,
    state::{escrow_authority_identity, pool_authority_identity, EscrowUtxo, PoolUtxo},
    Groth16ProofBytes,
};
use light_program_profiler::{
    mollusk::{register_profiling_syscalls, take_profiling_entries},
    report::{CuBenchmark, ReadmeConfig, SectionTable},
};
use mollusk_svm::{program::loader_keys::LOADER_V3, result::Check, Mollusk};
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
    pda,
    state::{
        address_tree_params, discriminator::TREE_ACCOUNT_DISCRIMINATOR, tree_account_size,
        STATE_HEIGHT,
    },
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET,
    SPL_TOKEN_ACCOUNT_INITIALIZED, SPL_TOKEN_ACCOUNT_LEN, SPL_TOKEN_ACCOUNT_STATE_OFFSET,
    SPL_TOKEN_MINT_ACCOUNT_LEN, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, ShieldedKeypair, ShieldedPda, SigningKey};
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};
use zolana_transaction::{
    instructions::{
        transact::{
            encrypt_transaction_data, get_transaction_viewing_key,
            spp_proof_inputs::{asset_field, BN254_MODULUS_DEC},
            ExternalData, SettlementTransfer, SppProofInputs, SppProofOutputUtxo,
        },
        types::SppProofInputUtxo,
    },
    AssetRegistry, Data, Utxo,
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
const SPL_TOKEN_PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../target/deploy/spl_token.so"
);

const SOURCE_ASSET_ID: u64 = 2;
const DESTINATION_ASSET_ID: u64 = 3;
const PRICE: u64 = 5;
const EXPIRY_SLOTS: u64 = 1_000;
const MAX_ORDER_SIZE: u64 = 600_000_000;

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

fn token_mint_fixture(token_program: &Pubkey) -> Account {
    let mut data = vec![0u8; SPL_TOKEN_MINT_ACCOUNT_LEN];
    data[44] = 0;
    data[45] = 1;
    Account {
        lamports: 1_000_000_000,
        data,
        owner: *token_program,
        executable: false,
        rent_epoch: 0,
    }
}

fn token_account_fixture(
    mint: &Pubkey,
    owner: &[u8; 32],
    amount: u64,
    token_program: &Pubkey,
) -> Account {
    let mut data = vec![0u8; SPL_TOKEN_ACCOUNT_LEN];
    data[..32].copy_from_slice(&mint.to_bytes());
    data[32..64].copy_from_slice(owner);
    data[SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET..SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET + 8]
        .copy_from_slice(&amount.to_le_bytes());
    data[SPL_TOKEN_ACCOUNT_STATE_OFFSET] = SPL_TOKEN_ACCOUNT_INITIALIZED;
    Account {
        lamports: 1_000_000_000,
        data,
        owner: *token_program,
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

fn non_inclusion_proof(
    nf_tree: &IndexedMerkleTree<Poseidon, usize>,
    merkle_context: &MerkleContext,
    nullifier: [u8; 32],
    nullifier_root: [u8; 32],
) -> NonInclusionProof {
    let nf = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
        .expect("non inclusion proof");
    NonInclusionProof {
        leaf: nullifier,
        merkle_context: merkle_context.clone(),
        path: nf.merkle_proof.to_vec(),
        low_element: nf.leaf_lower_range_value,
        low_element_index: nf.leaf_index as u64,
        high_element: nf.leaf_higher_range_value,
        high_element_index: 0,
        root: nullifier_root,
        root_seq: 0,
        root_index: 0,
    }
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
                nullifier: non_inclusion_proof(
                    nf_tree,
                    &merkle_context,
                    commitment.nullifier,
                    nullifier_root,
                ),
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
    dummy_nullifier_proofs: &[NonInclusionProof],
    prover: &ProverClient,
) -> (TransactIxData, Duration) {
    prover
        .prove_transact(proof_inputs.clone(), spend_proofs, dummy_nullifier_proofs)
        .expect("warm prove transact");
    let start = Instant::now();
    let transact = prover
        .prove_transact(proof_inputs, spend_proofs, dummy_nullifier_proofs)
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
    let token_program_id = Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID);
    let spl_token_elf = std::fs::read(SPL_TOKEN_PROGRAM_PATH).unwrap_or_else(|_| {
        panic!("missing {SPL_TOKEN_PROGRAM_PATH}; run `just bench-dynamic-swap`")
    });
    mollusk.add_program_with_loader_and_elf(&token_program_id, &LOADER_V3, &spl_token_elf);

    let mut bench = CuBenchmark::new(ReadmeConfig {
        title: "Dynamic Swap -- CU Benchmark".into(),
        description: "Compute unit profiling for the dynamic-swap create_pair/update_price/\
             create_escrow/settle/cancel/withdraw_liquidity/rebalance_liquidity instructions, \
             replayed under mollusk. Every PDA account (Pair, Escrow) and the shielded-pool tree \
             account are built directly, as if the prior instruction chain already ran -- only \
             the ONE instruction under measurement is actually replayed. Only the dynamic-swap \
             program is profiled; the shielded-pool program is built plain, so the CU its CPI \
             consumes is charged to the `cpi_spp_*` row as a black box and its internal functions \
             do not appear here. update_price never verifies a proof or CPI into SPP at all (the \
             whole point of keeping it cheap); create_escrow (taker-only, IN1_OUT2), settle \
             (pool-funded, maker-only, IN2_OUT3), cancel (after expiry, IN1_OUT1), \
             withdraw_liquidity (IN1_OUT1 with an SPL withdrawal), and rebalance_liquidity \
             (IN5_OUT4, dummy-padded) \
             each verify their own Groth16 proof and then CPI SPP `transact`, which verifies its \
             own. deposit_liquidity is proof-free (the program validates the public entry and \
             forwards SPP's proofless deposit with its SPL settlement) and is not profiled here \
             -- it would need token-program fixtures; its on-chain cost is dominated by the SPP \
             deposit CPI. Each proof-carrying instruction's section also records its proving \
             times (SPP transfer proof plus the dynamic-swap circuit proof) and its serialized \
             transaction size: the instruction prefixed with a compute-budget limit ix, as a \
             legacy transaction and as a v0 transaction with every non-signer account and the \
             program id in one address lookup table (Solana's packet limit is 1232 bytes)."
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
    bench_withdraw_liquidity(&mut mollusk, &spp_id, &dynamic_swap_id, &mut bench);
    bench_rebalance_liquidity(&mut mollusk, &spp_id, &dynamic_swap_id, &mut bench);

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
        max_order_size: MAX_ORDER_SIZE,
        source_asset: [0u8; 32],
        destination_asset: [0u8; 32],
        maker_receipt_owner_hash: [7u8; 32],
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
    let world = escrow_bench_world();
    let pair_state = world.pair_state(MAX_ORDER_SIZE, 0);
    let authority = &world.authority_solana;
    let pair = world.pair;

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
/// cancel, and liquidity benches: one taker, one maker, one pair, one order
/// UTXO, one pool authority.
struct EscrowBenchWorld {
    authority_solana: Keypair,
    authority_keypair: ShieldedKeypair,
    user_solana: Keypair,
    user_keypair: ShieldedKeypair,
    source_asset: Address,
    destination_asset: Address,
    pair: Pubkey,
    escrow_owner: ShieldedPda,
    pool_owner: ShieldedPda,
    tree: Pubkey,
    escrow_utxo: EscrowUtxo,
    assets: AssetRegistry,
}

const ORDER_AMOUNT: u64 = 100_000_000;
const OWED: u64 = ORDER_AMOUNT * PRICE;
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
    let destination_asset = Address::new_from_array([3u8; 32]);
    let pair = pair_pda(
        &authority_solana.pubkey(),
        SOURCE_ASSET_ID,
        DESTINATION_ASSET_ID,
    );
    let escrow_owner = escrow_authority_identity(&pair, &authority_keypair.viewing_key)
        .expect("escrow authority identity");
    let pool_owner = pool_authority_identity(&pair, &authority_keypair.viewing_key)
        .expect("pool authority identity");
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
    assets
        .insert(DESTINATION_ASSET_ID, destination_asset)
        .expect("register destination asset");
    EscrowBenchWorld {
        authority_solana,
        authority_keypair,
        user_solana,
        user_keypair,
        source_asset,
        destination_asset,
        pair,
        escrow_owner,
        pool_owner,
        tree: Keypair::new().pubkey(),
        escrow_utxo,
        assets,
    }
}

impl EscrowBenchWorld {
    fn pair_state(&self, available_liquidity: u64, open_reservations: u64) -> Pair {
        Pair {
            discriminator: PAIR,
            bump: 255,
            _pad: [0u8; 6],
            authority: self.authority_solana.pubkey(),
            source_asset_id: SOURCE_ASSET_ID,
            destination_asset_id: DESTINATION_ASSET_ID,
            price: PRICE,
            expiry_slots: EXPIRY_SLOTS,
            max_order_size: MAX_ORDER_SIZE,
            available_liquidity,
            open_reservations,
            source_asset: asset_field(&self.source_asset).expect("source asset field"),
            destination_asset: asset_field(&self.destination_asset)
                .expect("destination asset field"),
            maker_receipt_owner_hash: self
                .authority_keypair
                .owner_hash()
                .expect("authority owner hash"),
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

    fn pool_address(&self) -> zolana_keypair::ShieldedAddress {
        self.pool_owner
            .shielded_address()
            .expect("pool authority address")
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

    let user_address = world.user_keypair.shielded_address().expect("user address");
    let taker_change = SppProofOutputUtxo::new(
        world.source_asset,
        FUNDING_AMOUNT - ORDER_AMOUNT,
        user_address,
    )
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
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &[], &prover);

    let proof_inputs = EscrowOpenProofInputParams {
        source_in,
        order_out,
        taker_change,
        escrow_authority_owner_hash: escrow_authority_address
            .owner_hash()
            .expect("escrow authority owner hash"),
        source_asset: asset_field(&world.source_asset).expect("source asset field"),
        execution_price: PRICE,
        max_order_size: MAX_ORDER_SIZE,
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

    // The pool covers the worst-case reservation.
    let fixtures = vec![
        (
            world.user_solana.pubkey(),
            system_owned_account(100_000_000_000),
        ),
        (
            world.pair,
            pair_fixture(world.pair_state(FUNDING_AMOUNT, 0), dynamic_swap_id),
        ),
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

    // The payout is funded from the committed pool.
    let pool_address = world.pool_address();
    let pool_note = PoolUtxo {
        asset: world.destination_asset,
        amount: FUNDING_AMOUNT,
        booked: FUNDING_AMOUNT,
        blinding: random_blinding(),
    };
    let pool_in = pool_note.to_input_utxo(&pool_address).expect("pool_in");

    let authority_address = world
        .authority_keypair
        .shielded_address()
        .expect("authority shielded address");
    let mut recipient_out = SppProofOutputUtxo::new(
        world.destination_asset,
        OWED,
        world.user_keypair.shielded_address().expect("user address"),
    )
    .expect("recipient_out");
    // The recipient blinding derives from the order blinding; the pool change
    // and receipt blindings are the maker's own fresh choices.
    recipient_out.blinding =
        derive_output_blinding(&world.escrow_utxo.blinding, RECIPIENT_BLINDING_DOMAIN)
            .expect("recipient_out blinding");
    let pool_change_note = PoolUtxo {
        asset: world.destination_asset,
        amount: FUNDING_AMOUNT - OWED,
        booked: FUNDING_AMOUNT - MAX_ORDER_SIZE,
        blinding: random_blinding(),
    };
    let pool_change = pool_change_note
        .output_utxo(&pool_address)
        .expect("pool_change");
    let maker_receipt =
        SppProofOutputUtxo::new(world.source_asset, ORDER_AMOUNT, authority_address)
            .expect("maker_receipt");

    // All three ciphertexts are kept (the pool change's is the maker's own
    // pool-scan handoff).
    let input_utxos = vec![order_in.clone(), pool_in.clone()];
    let viewing_key = get_transaction_viewing_key(&world.authority_keypair, &input_utxos)
        .expect("transaction viewing key");
    let encoded = encrypt_transaction_data(
        &[
            recipient_out.clone(),
            pool_change.clone(),
            maker_receipt.clone(),
        ],
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
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &[], &prover);

    let pool_authority_owner_hash = pool_address.owner_hash().expect("pool owner hash");
    let proof_inputs = SettleProofInputParams {
        order_in,
        pool_in,
        pool_booked_in: pool_note.booked,
        recipient_out,
        pool_change,
        maker_receipt,
        execution_price: PRICE,
        order_amount: ORDER_AMOUNT,
        order_utxo_hash: order_in_hash,
        destination_asset: asset_field(&world.destination_asset).expect("destination asset field"),
        pool_authority_owner_hash,
        max_order_size: MAX_ORDER_SIZE,
        receipt_owner_hash: world
            .authority_keypair
            .owner_hash()
            .expect("authority owner hash"),
        external_data_hash,
    }
    .to_proof_inputs()
    .expect("pool_settle proof inputs");
    let circuit_start = Instant::now();
    let order_proof = DynamicSwapProverClient::new()
        .prove_pool_settle(&proof_inputs)
        .expect("prove pool_settle");
    let circuit_dur = circuit_start.elapsed();

    let escrow = escrow_pda(&order_in_hash);
    let ix = Settle {
        authority: world.authority_solana.pubkey(),
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

    // One open reservation for settle to release; the bound is already net of
    // it.
    let fixtures = vec![
        (
            world.authority_solana.pubkey(),
            system_owned_account(100_000_000_000),
        ),
        (
            world.user_solana.pubkey(),
            system_owned_account(1_000_000_000),
        ),
        (
            world.pair,
            pair_fixture(
                world.pair_state(FUNDING_AMOUNT - MAX_ORDER_SIZE, 1),
                dynamic_swap_id,
            ),
        ),
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
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &[], &prover);

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

    // One open reservation for cancel to release in full.
    let fixtures = vec![
        (
            world.user_solana.pubkey(),
            system_owned_account(100_000_000_000),
        ),
        (
            world.pair,
            pair_fixture(
                world.pair_state(FUNDING_AMOUNT - MAX_ORDER_SIZE, 1),
                dynamic_swap_id,
            ),
        ),
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

fn bench_withdraw_liquidity(
    mollusk: &mut Mollusk,
    spp_id: &Pubkey,
    dynamic_swap_id: &Pubkey,
    bench: &mut CuBenchmark,
) {
    let world = escrow_bench_world();
    let pool_address = world.pool_address();
    let amount = MAX_ORDER_SIZE;
    let mint = Pubkey::new_from_array(world.destination_asset.to_bytes());
    let user_token = Pubkey::new_unique();
    let token_program = Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID);
    let spl_interface = pda::spl_interface(&mint);

    let pool_in_note = PoolUtxo {
        asset: world.destination_asset,
        amount: FUNDING_AMOUNT,
        booked: FUNDING_AMOUNT,
        blinding: random_blinding(),
    };
    let pool_out_note = PoolUtxo {
        asset: world.destination_asset,
        amount: FUNDING_AMOUNT - amount,
        booked: FUNDING_AMOUNT - amount,
        blinding: random_blinding(),
    };
    let pool_in = pool_in_note.to_input_utxo(&pool_address).expect("pool_in");
    let pool_out = pool_out_note.output_utxo(&pool_address).expect("pool_out");

    let input_utxos = vec![pool_in.clone()];
    let viewing_key = get_transaction_viewing_key(&world.authority_keypair, &input_utxos)
        .expect("transaction viewing key");
    let encoded =
        encrypt_transaction_data(std::slice::from_ref(&pool_out), &world.assets, &viewing_key)
            .expect("encode outputs");
    let external_data = ExternalData::new(
        *viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    )
    .with_interface_transfer(SettlementTransfer::Spl {
        mint,
        is_deposit: false,
        amount,
        user_spl_token: user_token,
        spl_token_interface: spl_interface,
    })
    .expect("withdrawal interface transfer");
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
    let (transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &[], &prover);

    let withdraw_proof_inputs = WithdrawProofInputParams {
        pool_in: pool_in_note,
        pool_out: pool_out_note,
        pool_authority: pool_address,
        amount,
        destination_asset: asset_field(&world.destination_asset).expect("destination asset field"),
        external_data_hash,
    }
    .to_proof_inputs()
    .expect("pool_withdraw proof inputs");
    let circuit_start = Instant::now();
    let withdraw_proof = DynamicSwapProverClient::new()
        .prove_pool_withdraw(&withdraw_proof_inputs)
        .expect("prove pool_withdraw");
    let circuit_dur = circuit_start.elapsed();

    let ix = WithdrawLiquidity {
        authority: world.authority_solana.pubkey(),
        pair: world.pair,
        tree: world.tree,
        amount,
        spl: WithdrawSplAccounts {
            mint,
            user_token,
            token_program,
        },
        proof: Groth16ProofBytes {
            proof_a: withdraw_proof.proof_a,
            proof_b: withdraw_proof.proof_b,
            proof_c: withdraw_proof.proof_c,
        },
        transact,
    }
    .instruction()
    .expect("withdraw instruction");

    let fixtures = vec![
        (
            world.authority_solana.pubkey(),
            system_owned_account(100_000_000_000),
        ),
        (
            world.pair,
            pair_fixture(world.pair_state(FUNDING_AMOUNT, 0), dynamic_swap_id),
        ),
        (world.tree, tree_account),
        (mint, token_mint_fixture(&token_program)),
        (
            spl_interface,
            token_account_fixture(
                &mint,
                &SHIELDED_POOL_CPI_AUTHORITY,
                FUNDING_AMOUNT,
                &token_program,
            ),
        ),
        (
            user_token,
            token_account_fixture(
                &mint,
                &world.authority_solana.pubkey().to_bytes(),
                0,
                &token_program,
            ),
        ),
        (
            token_program,
            mollusk_svm::program::create_program_account_loader_v3(&token_program),
        ),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for 'withdraw_liquidity'"
    );
    bench.add_from_entries("withdraw_liquidity", entries);
    bench.add_table(
        "withdraw_liquidity",
        proving_time_table(spp_dur, circuit_dur),
    );
    bench.add_table(
        "withdraw_liquidity",
        tx_size_table(&ix, &world.authority_solana.pubkey()),
    );
}

fn bench_rebalance_liquidity(
    mollusk: &mut Mollusk,
    spp_id: &Pubkey,
    dynamic_swap_id: &Pubkey,
    bench: &mut CuBenchmark,
) {
    let world = escrow_bench_world();
    let pool_address = world.pool_address();

    // Publish surplus from one settle-change-shaped note (1 real input, 1 real
    // output, 4 + 3 dummy slots).
    const CREDIT: u64 = MAX_ORDER_SIZE - OWED;
    let pool_in_note = PoolUtxo {
        asset: world.destination_asset,
        amount: FUNDING_AMOUNT - OWED,
        booked: FUNDING_AMOUNT - MAX_ORDER_SIZE,
        blinding: random_blinding(),
    };
    let pool_out_note = PoolUtxo {
        asset: world.destination_asset,
        amount: FUNDING_AMOUNT - OWED,
        booked: FUNDING_AMOUNT - OWED,
        blinding: random_blinding(),
    };

    let prepared = RebalanceProofInputParams {
        inputs: vec![pool_in_note],
        outputs: vec![pool_out_note],
        pool_authority: pool_address,
        credit: CREDIT,
        destination_asset: asset_field(&world.destination_asset).expect("destination asset field"),
    }
    .prepare()
    .expect("rebalance prepare");

    let spp_proof_inputs = prepared
        .spp_proof_inputs(
            &world.authority_keypair,
            &world.assets,
            world.authority_solana.pubkey(),
        )
        .expect("rebalance spp inputs");
    let external_data_hash = spp_proof_inputs
        .external_data
        .hash()
        .expect("external data hash");
    let bundle = prepared
        .to_proof_inputs(external_data_hash)
        .expect("rebalance proof inputs");

    // Only the real input is a tree leaf; each dummy input needs its own
    // nullifier non-inclusion proof.
    let commitments = spp_proof_inputs
        .input_utxo_hashes()
        .expect("input commitments");
    let real_commitments: Vec<zolana_transaction::instructions::types::InputUtxoContext> =
        commitments
            .iter()
            .zip(&prepared.spp_inputs)
            .filter(|(_, input)| !input.is_dummy())
            .map(
                |(commitment, _)| zolana_transaction::instructions::types::InputUtxoContext {
                    index: commitment.index,
                    utxo_hash: commitment.utxo_hash,
                    nullifier: commitment.nullifier,
                },
            )
            .collect();
    let leaves: Vec<[u8; 32]> = real_commitments
        .iter()
        .map(|input| input.utxo_hash)
        .collect();
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
        &real_commitments,
        utxo_root,
        nullifier_root,
        root_index,
    );
    let merkle_context = MerkleContext {
        tree_type: 0,
        tree: world.tree,
    };
    let dummy_proofs: Vec<NonInclusionProof> = prepared
        .spp_inputs
        .iter()
        .filter(|input| input.is_dummy())
        .map(|input| {
            non_inclusion_proof(
                &nf_tree,
                &merkle_context,
                input.nullifier().expect("dummy nullifier"),
                nullifier_root,
            )
        })
        .collect();

    let prover = ProverClient::local();
    let (transact, spp_dur) =
        prove_transact_timed(spp_proof_inputs, &spend_proofs, &dummy_proofs, &prover);

    let circuit_start = Instant::now();
    let rebalance_proof = DynamicSwapProverClient::new()
        .prove_pool_rebalance(&bundle.proof_inputs)
        .expect("prove pool_rebalance");
    let circuit_dur = circuit_start.elapsed();

    let ix = RebalanceLiquidity {
        authority: world.authority_solana.pubkey(),
        pair: world.pair,
        tree: world.tree,
        credit: CREDIT,
        proof: Groth16ProofBytes {
            proof_a: rebalance_proof.proof_a,
            proof_b: rebalance_proof.proof_b,
            proof_c: rebalance_proof.proof_c,
        },
        transact,
    }
    .instruction()
    .expect("rebalance instruction");

    let fixtures = vec![
        (
            world.authority_solana.pubkey(),
            system_owned_account(100_000_000_000),
        ),
        (
            world.pair,
            pair_fixture(
                world.pair_state(FUNDING_AMOUNT - MAX_ORDER_SIZE, 0),
                dynamic_swap_id,
            ),
        ),
        (world.tree, tree_account),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(
        !entries.is_empty(),
        "no profiling entries for 'rebalance_liquidity'"
    );
    bench.add_from_entries("rebalance_liquidity", entries);
    bench.add_table(
        "rebalance_liquidity",
        proving_time_table(spp_dur, circuit_dur),
    );
    bench.add_table(
        "rebalance_liquidity",
        tx_size_table(&ix, &world.authority_solana.pubkey()),
    );
}
