//! Batched fills against solo fills.
//!
//! A batch needs the 4096-byte transaction SIMD-0296 introduces, so it runs
//! under LiteSVM rather than on a validator. LiteSVM runs the real SVM and the
//! real `alt_bn128` syscalls, and does not enforce the packet size.

use std::time::Instant;

use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use swap_prover::{preload, CircuitId as SwapCircuitId, TAKE_MODE_DERIVED};
use swap_sdk::{
    instructions::{
        take::{Take, TakeProofInputParams},
        take_batch::{TakeBatch, TakeBatchLeg},
    },
    prover::SwapProverClient,
    state::{OrderTerms, OrderUtxo},
};
use zolana_client::{
    assemble,
    prover::{AggregateInputs, AggregateLeg},
    MerkleContext, MerkleProof, NonInclusionProof, Proof, ProofCompressed, ProverClient,
    ProverInputs, SpendProof, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_hasher::Poseidon;
use zolana_interface::instruction::{
    instruction_data::transact::TransactIxData, AssetDeposit, DepositAsset, UtxoData,
};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, ViewingKey};
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::{backend::LiteSvmPoolBackend, prover::spawn_workspace_prover};
use zolana_transaction::{
    derive_blinding,
    instructions::{
        transact::{
            encrypt_transaction_data, get_transaction_viewing_key,
            spp_proof_inputs::BN254_MODULUS_DEC, ExternalData, SppProofInputs,
        },
        types::SppProofInputUtxo,
    },
    AssetRegistry, Data, Utxo, SOL_ASSET_ID, SOL_MINT,
};
use zolana_tree::TreeAccount;

const EXPIRY: u64 = 2_000_000_000;
const SOURCE_AMOUNT: u64 = 400_000_000;
const DESTINATION_AMOUNT: u64 = 250_000_000;

/// One maker's order, its funding, and the taker note that fills it.
struct Fill {
    order_utxo: OrderUtxo,
    maker: ShieldedAddress,
    taker_in_blinding: [u8; 32],
    source_output_blinding: [u8; 32],
}

/// A filled leg, ready for both the solo and the batched instruction.
struct Leg {
    take_proof: swap_sdk::TakeProof,
    spp_proof: TransactIxData,
    raw_proof: Proof,
    public_input_hash: [u8; 32],
    prove_ms: u128,
    outputs: [[u8; 32]; 2],
}

fn swap_program_elf() -> Vec<u8> {
    let path = std::env::var("SWAP_PROGRAM_SO").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../target/deploy/swap_program.so"
        )
        .to_string()
    });
    std::fs::read(&path)
        .unwrap_or_else(|err| panic!("read {path}; run `just build-programs`: {err}"))
}

fn pool() -> LiteSvmPoolBackend {
    let mut env = LiteSvmPoolBackend::initialized();
    env.rpc
        .svm
        .add_program(swap_program::ID, &swap_program_elf())
        .expect("load swap program");
    env
}

fn taker_keypair() -> ShieldedKeypair {
    ShieldedKeypair::from_ed25519(
        &[0x42; 32],
        ViewingKey::from_bytes(&[0x43; 32]).expect("taker viewing key"),
    )
    .expect("taker keypair")
}

fn maker_address(index: usize) -> Result<ShieldedAddress> {
    let seed = [0x50 + index as u8; 32];
    let viewing = ViewingKey::from_bytes(&[0x60 + index as u8; 32])?;
    Ok(ShieldedKeypair::from_ed25519(&seed, viewing)?.shielded_address()?)
}

/// One order per maker, all filled by one taker. The take circuit binds a
/// single order, so each fill carries its own proof.
fn fills(taker: &ShieldedKeypair, count: usize) -> Result<Vec<Fill>> {
    let taker_address = taker.shielded_address()?;
    (0..count)
        .map(|index| {
            let step = index as u64 + 1;
            let maker = maker_address(index)?;
            let terms = OrderTerms {
                destination_mint: SOL_MINT,
                destination_amount: DESTINATION_AMOUNT + step * 1_000,
                destination: maker,
                taker: taker_address.solana_address()?,
                expiry: EXPIRY,
                take_mode: TAKE_MODE_DERIVED,
            };
            Ok(Fill {
                order_utxo: OrderUtxo {
                    terms,
                    blinding: derive_blinding(&[0x70; 32], index as u8),
                    source_mint: SOL_MINT,
                    source_amount: SOURCE_AMOUNT + step * 1_000,
                    destination_asset_id: SOL_ASSET_ID,
                },
                maker,
                taker_in_blinding: derive_blinding(&[0x80; 32], index as u8),
                source_output_blinding: derive_blinding(&[0x90; 32], index as u8),
            })
        })
        .collect()
}

impl Fill {
    fn order_spend(&self) -> Result<SppProofInputUtxo> {
        self.order_utxo.to_input_utxo()
    }

    fn taker_spend(&self, taker: &ShieldedKeypair) -> Result<SppProofInputUtxo> {
        let utxo = Utxo {
            owner: taker.signing_pubkey(),
            asset: self.order_utxo.terms.destination_mint,
            amount: self.order_utxo.terms.destination_amount,
            blinding: self.taker_in_blinding,
            ring_program_id: None,
            data: Data::default(),
        };
        Ok(SppProofInputUtxo::new(utxo, taker))
    }
}

/// A deposit mints the order UTXO the maker would mint with `make`. A batch
/// settles take legs, so the test funds its inputs directly.
fn fund(env: &mut LiteSvmPoolBackend, fill: &Fill, taker: &ShieldedKeypair) -> Result<()> {
    let tree = env.tree.pubkey();
    let payer = env.rpc.payer.insecure_clone();
    let taker_address = taker.shielded_address()?;

    let order = fill.order_spend()?;
    let order_owner = zolana_keypair::hash::owner_hash(
        &order.utxo.owner,
        &order.nullifier_key.pubkey().map_err(|e| anyhow!("{e:?}"))?,
    )?;
    let order_deposit = AssetDeposit {
        asset: DepositAsset::Sol,
        view_tag: taker_address.viewing_pubkey.x(),
        owner: order_owner,
        blinding: fill.order_utxo.blinding,
        amount: fill.order_utxo.source_amount,
        utxo_data: Some(UtxoData {
            data_hash: fill.order_utxo.terms.data_hash()?,
            data: fill
                .order_utxo
                .terms
                .to_plaintext(fill.order_utxo.destination_asset_id)
                .serialize()?,
        }),
        memo: None,
    };
    let minted = env
        .rpc
        .deposit(&tree, &payer, &order_deposit)
        .map_err(|e| anyhow!("order deposit: {e:?}"))?;
    assert_eq!(minted.utxo_hash, order.hash()?, "order utxo gate");

    let taker_in = fill.taker_spend(taker)?;
    let taker_deposit = AssetDeposit {
        asset: DepositAsset::Sol,
        view_tag: taker_address.viewing_pubkey.x(),
        owner: taker_address.owner_hash()?,
        blinding: fill.taker_in_blinding,
        amount: fill.order_utxo.terms.destination_amount,
        utxo_data: None,
        memo: None,
    };
    let minted = env
        .rpc
        .deposit(&tree, &payer, &taker_deposit)
        .map_err(|e| anyhow!("taker deposit: {e:?}"))?;
    assert_eq!(minted.utxo_hash, taker_in.hash()?, "taker utxo gate");
    Ok(())
}

fn tree_roots(rpc: &ZolanaProgramTest, tree: &Pubkey, utxo_index: u16) -> ([u8; 32], [u8; 32]) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.get_utxo_tree_root(utxo_index).expect("utxo root"),
        account.get_nullifier_tree_root(0).expect("nullifier root"),
    )
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

fn spend_proofs(
    tree: &Pubkey,
    state_tree: &MerkleTree<Poseidon>,
    leaf_indices: [usize; 2],
    commitments: &[zolana_transaction::instructions::types::InputUtxoContext],
    roots: ([u8; 32], [u8; 32]),
    root_index: u16,
) -> Vec<SpendProof> {
    let nf_tree = nullifier_tree();
    let merkle_context = MerkleContext {
        tree_type: 0,
        tree: Address::new_from_array(tree.to_bytes()),
    };
    commitments
        .iter()
        .zip(leaf_indices)
        .map(|(commitment, leaf_index)| {
            let path = state_tree
                .get_proof_of_leaf(leaf_index, true)
                .expect("state proof")
                .to_vec();
            let non_inclusion = nf_tree
                .get_non_inclusion_proof(&BigUint::from_bytes_be(&commitment.nullifier))
                .expect("non inclusion proof");
            SpendProof {
                state: MerkleProof {
                    leaf: commitment.utxo_hash,
                    merkle_context: merkle_context.clone(),
                    path,
                    leaf_index: leaf_index as u64,
                    root: roots.0,
                    root_seq: 0,
                    root_index,
                },
                nullifier: NonInclusionProof {
                    leaf: commitment.nullifier,
                    merkle_context: merkle_context.clone(),
                    path: non_inclusion.merkle_proof.to_vec(),
                    low_element: non_inclusion.leaf_lower_range_value,
                    low_element_index: non_inclusion.leaf_index as u64,
                    high_element: non_inclusion.leaf_higher_range_value,
                    high_element_index: 0,
                    root: roots.1,
                    root_seq: 0,
                    root_index: 0,
                },
            }
        })
        .collect()
}

/// Prove one fill, the SPP leg and the swap take proof over the same
/// `private_tx_hash`.
fn build_leg(
    fill: &Fill,
    taker: &ShieldedKeypair,
    tree: &Pubkey,
    state_tree: &MerkleTree<Poseidon>,
    leaf_indices: [usize; 2],
    roots: ([u8; 32], [u8; 32]),
    root_index: u16,
) -> Result<Leg> {
    let taker_address = taker.shielded_address()?;
    let order_utxo = fill.order_utxo.clone();
    let taker_in = order_utxo.destination_output(taker_address, fill.taker_in_blinding);
    let source_output = order_utxo.source_output(taker_address, fill.source_output_blinding);
    let destination_output = order_utxo.derived_destination_output(fill.maker)?;

    let inputs = vec![fill.order_spend()?, fill.taker_spend(taker)?];
    let viewing_key = get_transaction_viewing_key(taker, &inputs)?;
    let encoded = encrypt_transaction_data(
        &[source_output.clone(), destination_output.clone()],
        &AssetRegistry::default(),
        &viewing_key,
    )?;
    let mut external_data = ExternalData::new(
        *viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        vec![],
    );
    external_data.expiry_unix_ts = order_utxo.terms.expiry;
    let proof_inputs = SppProofInputs::new(
        inputs,
        encoded.output_utxos,
        external_data,
        taker_address.solana_address()?,
    );

    let external_data_hash = proof_inputs.external_data.hash()?;
    let commitments = proof_inputs.input_utxo_hashes()?;
    let proofs = spend_proofs(
        tree,
        state_tree,
        leaf_indices,
        &commitments,
        roots,
        root_index,
    );

    let started = Instant::now();
    let assembled = assemble(proof_inputs, &proofs, &[])?;
    let ProverInputs::Eddsa(prover_inputs) = &assembled.prover_inputs;
    let raw_proof = ProverClient::local().prove_transfer(prover_inputs)?;
    let public_input_hash = assembled.public_input_hash;
    let spp_proof = assembled.with_proof(ProofCompressed::try_from(raw_proof)?.to_transact_proof());

    let take_proof = SwapProverClient::new().prove_take(
        &TakeProofInputParams {
            order_utxo,
            taker_in,
            source_output: source_output.clone(),
            destination_output: destination_output.clone(),
            external_data_hash,
        }
        .to_proof_inputs()?,
    )?;
    let prove_ms = started.elapsed().as_millis();

    Ok(Leg {
        take_proof: take_proof.into(),
        spp_proof,
        raw_proof,
        public_input_hash,
        prove_ms,
        outputs: [source_output.hash()?, destination_output.hash()?],
    })
}

/// The leaves a fill's deposits append, in deposit order.
fn deposit_leaves(fills: &[Fill], taker: &ShieldedKeypair) -> Result<Vec<[u8; 32]>> {
    let mut leaves = Vec::with_capacity(2 * fills.len());
    for fill in fills {
        leaves.push(fill.order_spend()?.hash()?);
        leaves.push(fill.taker_spend(taker)?.hash()?);
    }
    Ok(leaves)
}

fn state_tree(leaves: &[[u8; 32]]) -> MerkleTree<Poseidon> {
    let mut tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    for leaf in leaves {
        tree.append(leaf).expect("append state leaf");
    }
    tree
}

/// The state every fill settles is two outputs appended and two nullifiers queued.
fn assert_settled(env: &LiteSvmPoolBackend, leaves: &[[u8; 32]], spent: u64) {
    let tree = env.tree.pubkey();
    assert_eq!(
        env.rpc.state_root(&tree),
        Some(state_tree(leaves).root()),
        "settled state root"
    );
    let mut data = env.rpc.account_data(&tree).expect("tree account");
    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    assert_eq!(
        account.nullifer_tree().queue_batches.next_index,
        spent,
        "queued nullifiers"
    );
}

fn send(env: &mut LiteSvmPoolBackend, ix: solana_instruction::Instruction, taker: &Keypair) -> u64 {
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    env.rpc
        .create_and_send_transaction(&[budget, ix], &taker.pubkey(), &[taker])
        .expect("send fill");
    env.rpc
        .last_transaction_trace()
        .expect("transaction trace")
        .compute_units_consumed
}

#[test]
fn take_batch_reports_compute() -> Result<()> {
    spawn_workspace_prover();
    preload(SwapCircuitId::Take).map_err(|e| anyhow!("preload take circuit: {e:?}"))?;
    for legs in [2usize, 3] {
        measure(legs)?;
    }
    Ok(())
}

fn measure(count: usize) -> Result<()> {
    let taker = taker_keypair();
    let taker_payer = taker.to_solana_keypair()?;
    let fills = fills(&taker, count)?;
    let deposits = deposit_leaves(&fills, &taker)?;

    let mut env = pool();
    env.rpc
        .airdrop(&taker_payer.pubkey(), 100_000_000_000)
        .map_err(|e| anyhow!("fund taker: {e:?}"))?;
    for fill in &fills {
        fund(&mut env, fill, &taker)?;
    }

    // Every leg proves against the root after the last deposit, so one batch
    // needs one merkle tree and one root index.
    let tree = env.tree.pubkey();
    let root_index = deposits.len() as u16;
    let roots = tree_roots(&env.rpc, &tree, root_index);
    let deposit_tree = state_tree(&deposits);
    assert_eq!(deposit_tree.root(), roots.0, "state root gate");

    let legs = fills
        .iter()
        .enumerate()
        .map(|(index, fill)| {
            build_leg(
                fill,
                &taker,
                &tree,
                &deposit_tree,
                [2 * index, 2 * index + 1],
                roots,
                root_index,
            )
        })
        .collect::<Result<Vec<_>>>()?;

    let started = Instant::now();
    let outer = ProverClient::local().prove_aggregate(&AggregateInputs {
        inner: zolana_interface::verifying_keys::InnerCircuitKind::ConfidentialEddsa,
        num_inputs: 2,
        num_outputs: 2,
        legs: legs
            .iter()
            .map(|leg| AggregateLeg {
                proof: leg.raw_proof,
                public_input_hash: leg.public_input_hash,
            })
            .collect(),
    })?;
    let aggregate_prove_ms = started.elapsed().as_millis();
    let (proof, bsb22_commitment) =
        ProofCompressed::try_from(outer)?.into_ring_p256_transact_parts()?;

    let instruction = TakeBatch {
        payer: taker_payer.pubkey(),
        tree,
        proof,
        bsb22_commitment,
        legs: legs
            .iter()
            .map(|leg| TakeBatchLeg {
                take_proof: leg.take_proof,
                spp_proof: leg.spp_proof.clone(),
            })
            .collect(),
    }
    .instruction()?;
    let data_len = instruction.data.len();
    let batched = send(&mut env, instruction, &taker_payer);

    let mut settled = deposits.clone();
    for leg in &legs {
        settled.extend(leg.outputs);
    }
    let spent = 2 * count as u64;
    assert_settled(&env, &settled, spent);

    // The batch spent every leg's inputs, so replaying one solo is rejected.
    let replay = Take {
        payer: taker_payer.pubkey(),
        tree,
        take_proof: legs[0].take_proof,
        spp_proof: legs[0].spp_proof.clone(),
    }
    .instruction()?;
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    assert!(
        env.rpc
            .create_and_send_transaction(&[budget, replay], &taker_payer.pubkey(), &[&taker_payer])
            .is_err(),
        "a batched leg replayed"
    );

    // Solo baseline on a fresh pool, so each fill settles the same state the
    // batch settled.
    let mut solo_env = pool();
    solo_env
        .rpc
        .airdrop(&taker_payer.pubkey(), 100_000_000_000)
        .map_err(|e| anyhow!("fund taker: {e:?}"))?;
    for fill in &fills {
        fund(&mut solo_env, fill, &taker)?;
    }
    let solo_tree = solo_env.tree.pubkey();
    let mut solo_leaves = deposits.clone();
    let mut solo = 0u64;
    // The root history advances once per transaction, the leaves once per
    // output, so a solo run tracks the two separately.
    let first_root_index = deposits.len() as u16;
    for (root_index, (index, fill)) in (first_root_index..).zip(fills.iter().enumerate()) {
        let roots = tree_roots(&solo_env.rpc, &solo_tree, root_index);
        let tree_now = state_tree(&solo_leaves);
        assert_eq!(tree_now.root(), roots.0, "solo state root gate");
        let leg = build_leg(
            fill,
            &taker,
            &solo_tree,
            &tree_now,
            [2 * index, 2 * index + 1],
            roots,
            root_index,
        )?;
        let instruction = Take {
            payer: taker_payer.pubkey(),
            tree: solo_tree,
            take_proof: leg.take_proof,
            spp_proof: leg.spp_proof.clone(),
        }
        .instruction()?;
        solo += send(&mut solo_env, instruction, &taker_payer);
        solo_leaves.extend(leg.outputs);
    }
    assert_settled(&solo_env, &solo_leaves, spent);
    assert_eq!(settled, solo_leaves, "batched and solo fills settle alike");

    let leg_prove_ms: Vec<u128> = legs.iter().map(|leg| leg.prove_ms).collect();
    println!("swap take, {count} fills");
    println!("  instruction data: {data_len} bytes");
    println!("  leg proving: {leg_prove_ms:?} ms");
    println!("  aggregate proving: {aggregate_prove_ms} ms");
    println!("  batched: {batched} CU against {solo} CU solo");
    if solo > batched {
        println!("  saved: {} CU", solo - batched);
    } else {
        println!("  cost: {} CU over solo", batched - solo);
    }
    Ok(())
}
