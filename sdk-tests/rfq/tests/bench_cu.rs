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
use solana_instruction::{AccountMeta, Instruction};
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
    instruction::{instruction_data::transact::TransactIxData, Transact},
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
        types::{InputUtxoContext, SppProofInputUtxo},
    },
    AssetRegistry, Data, Utxo, SOL_MINT,
};
use zolana_tree::TreeAccount;

const SELL_SOL: u64 = 250_000_000;
const BUY_USDC: u64 = 100_000_000;
const USDC_ASSET_ID: u64 = 2;
const TAKER_SIGNER_INDEX: u8 = 3;

const PROFILING_SBF_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/rfq-bench");
const OUTPUT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/BENCHMARK.md");
const PROVER_KEYS_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../prover/server/proving-keys"
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
    commitments: &[InputUtxoContext],
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

fn proving_time_table(spp: Duration) -> SectionTable {
    SectionTable {
        title: "Proving Time".into(),
        headers: vec!["SPP transfer proof".into()],
        rows: vec![vec![format!("{} ms", spp.as_millis())]],
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
#[ignore = "CU benchmark; slow, needs SBF binaries + prover. Run via just bench-rfq"]
fn bench_cu_rfq() {
    std::env::set_var("SBF_OUT_DIR", PROFILING_SBF_DIR);

    let spp_id = MolluskPubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);

    let mut mollusk = Mollusk::default();
    register_profiling_syscalls(&mut mollusk);
    mollusk.add_program(&spp_id, "shielded_pool_program", &LOADER_V3);

    let mut bench = CuBenchmark::new(ReadmeConfig {
        title: "RFQ Settlement -- CU Benchmark".into(),
        description:
            "Compute unit profiling for a confidential RFQ settlement, replayed under mollusk. The \
             settlement is a single shielded-pool `transact` co-signed by a maker and a taker that \
             swaps SOL for USDC with no escrow and no custom program: the maker spends one SOL UTXO \
             and receives USDC, the taker spends one USDC UTXO and receives SOL (shape IN2_OUT2, \
             eddsa rail). The shielded-pool program is built with `profile-program`, so its \
             `#[profile]` functions appear in the CU table; the tree account is built directly (the \
             program's `create_tree` init plus the input utxo hashes appended). The section also \
             records the SPP transfer proving time (warm, key already loaded) and the serialized \
             transaction size: the instruction prefixed with a compute-budget limit ix, as a legacy \
             transaction and as a v0 transaction with every non-signer account and the program id in \
             one address lookup table (Solana's packet limit is 1232 bytes)."
                .into(),
        output_path: OUTPUT_PATH.into(),
        regenerate_command: Some("just bench-rfq".into()),
        ..Default::default()
    });

    start_prover();
    bench_settlement(&mut mollusk, &spp_id, &mut bench);

    bench.generate().expect("write BENCHMARK.md");
}

fn bench_settlement(mollusk: &mut Mollusk, spp_id: &MolluskPubkey, bench: &mut CuBenchmark) {
    let tree = Keypair::new().pubkey();
    let maker_payer = Keypair::new();
    let taker_payer = Keypair::new();
    let maker = keypair_from_payer(&maker_payer);
    let taker = keypair_from_payer(&taker_payer);
    let maker_address = maker.shielded_address().expect("maker address");
    let taker_address = taker.shielded_address().expect("taker address");

    let usdc_mint = Address::new_from_array([7u8; 32]);

    let maker_sol_utxo = Utxo {
        owner: maker.signing_pubkey(),
        asset: SOL_MINT,
        amount: SELL_SOL,
        blinding: random_blinding(),
        zone_program_id: None,
        data: Data::default(),
    };
    let taker_usdc_utxo = Utxo {
        owner: taker.signing_pubkey(),
        asset: usdc_mint,
        amount: BUY_USDC,
        blinding: random_blinding(),
        zone_program_id: None,
        data: Data::default(),
    };

    let maker_spend = SppProofInputUtxo::new(maker_sol_utxo, &maker);
    let taker_spend = SppProofInputUtxo::new(taker_usdc_utxo, &taker);
    let input_utxos = vec![maker_spend, taker_spend];

    let sol_to_taker =
        SppProofOutputUtxo::new(SOL_MINT, SELL_SOL, taker_address).expect("sol output");
    let usdc_to_maker =
        SppProofOutputUtxo::new(usdc_mint, BUY_USDC, maker_address).expect("usdc output");

    let mut assets = AssetRegistry::default();
    assets
        .insert(USDC_ASSET_ID, usdc_mint)
        .expect("register usdc");

    let transaction_viewing_key =
        get_transaction_viewing_key(&maker, &input_utxos).expect("transaction viewing key");
    let encoded = encrypt_transaction_data(
        &[sol_to_taker, usdc_to_maker],
        &assets,
        &transaction_viewing_key,
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

    let prover = ProverClient::local();
    let (mut transact, spp_dur) = prove_transact_timed(spp_proof_inputs, &spend_proofs, &prover);
    transact
        .inputs
        .get_mut(1)
        .expect("taker input")
        .eddsa_signer_index = TAKER_SIGNER_INDEX;

    let mut ix = Transact {
        payer: maker_payer.pubkey(),
        tree,
        withdrawal: None,
        data: transact,
    }
    .instruction();
    ix.accounts
        .push(AccountMeta::new_readonly(taker_payer.pubkey(), true));

    let fixtures = vec![
        (tree, tree_account),
        (maker_payer.pubkey(), system_owned_account(100_000_000_000)),
    ];
    let accounts = assemble_accounts(&ix, spp_id, &fixtures);
    let mollusk_ix = to_mollusk_instruction(&ix);
    mollusk.process_and_validate_instruction(&mollusk_ix, &accounts, &[Check::success()]);

    let entries = take_profiling_entries();
    assert!(!entries.is_empty(), "no profiling entries for 'settlement'");
    bench.add_from_entries("settlement", entries);
    bench.add_table("settlement", proving_time_table(spp_dur));
    bench.add_table("settlement", tx_size_table(&ix, &maker_payer.pubkey()));
}
