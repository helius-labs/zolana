//! Batch compute against the solo path, on every batchable rail.
//!
//! A batch needs the 4096-byte transaction SIMD-0296 introduces, so it runs
//! here rather than on a validator. LiteSVM runs the real SVM and the real
//! `alt_bn128` syscalls, and does not enforce the packet size.

use std::time::Instant;

use num_bigint::BigUint;
use shielded_pool_tests::support::{fixtures::Pool, transact::tree_roots};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    prover::{AggregateInputs, AggregateLeg},
    ProverClient, PublicInputs, PublicTransfers, TransferOutput, STATE_TREE_HEIGHT,
};
use zolana_hasher::{primitives::hash_bytes, Hasher, Poseidon};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{InterfaceTransfer, ResolvedInterfaceTransfer},
        instruction_data::{
            aggregate_transact::{AggregateTransactIxData, EMPTY_LEG_COMMITMENT, EMPTY_LEG_PROOF},
            transact::{CircuitId, ExternalDataHash, TransactIxData},
        },
        AggregateTransact, RingTransact, Transact, TransactInterfaceTransferAccounts,
        TransactSolTransferAccounts,
    },
    verifying_keys::{AggregateCircuitId, InnerCircuitKind, RingP256ProofData},
    N_PUBLIC_SLOTS,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey, ShieldedKeypair};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::test_blinding;
use zolana_test_utils::transact::{
    build_transfer_prover_inputs, dummy_input, dummy_transfer_output, eddsa_input_utxo, fe,
    inline_outputs, new_transact_ix_data, nullifier_tree, output_owner_pk_hashes, p256_coordinates,
    prove_and_verify_p256_raw, prove_and_verify_rail_raw, public_sol_field, resolve_outputs,
    set_output_owner_tags, sol_public_slots, spend_input, SpendInputArgs, TransferProverInputsArgs,
};
use zolana_transaction::{
    instructions::transact::PrivateTxHash, Data, SyncWalletAuthority, Utxo, SOL_MINT,
};

const SLOTS: u8 = N_PUBLIC_SLOTS as u8;

/// The transaction budget the run sets. A batch that reaches it stops being
/// sendable, so the measurement is also the ceiling.
const AGGREGATE_CU_LIMIT: u64 = 1_400_000;

struct Leg {
    data: TransactIxData,
    proof: zolana_client::Proof,
    public_input_hash: [u8; 32],
    settlement: Option<Pubkey>,
    prove_ms: u128,
    /// The leg's own commitment. A batch clears it, the solo path needs it.
    commitment: Option<zolana_interface::verifying_keys::Bsb22Commitment>,
}

/// Each leg withdraws its whole input, so a batch exercises the settlement
/// path every leg runs after its hash is chained.
const WITHDRAW_LAMPORTS: u64 = 1_000_000;

/// One real input the payer owns, one dummy input, three dummy outputs.
/// `index` keeps every leg's blinding, nullifier, and tree leaf distinct.
struct LegInputs {
    utxo_hash: [u8; 32],
    nullifier: [u8; 32],
    nullifier_key: NullifierKey,
    owner_field: [u8; 32],
    utxo: Utxo,
    /// Present on the P256 rail, whose owner authorizes in circuit.
    p256: Option<ShieldedKeypair>,
}

/// Which rail a batch proves. The batched pipeline is the same either way, so
/// the rail only changes the leg's UTXO binding and its account run.
#[derive(Clone, Copy, PartialEq)]
enum Rail {
    Confidential,
    Ring,
    P256,
}

impl Rail {
    fn kind(self) -> InnerCircuitKind {
        match self {
            Rail::Confidential => InnerCircuitKind::ConfidentialEddsa,
            Rail::Ring => InnerCircuitKind::RingEddsa,
            Rail::P256 => InnerCircuitKind::RingP256,
        }
    }

    fn circuit(self) -> CircuitId {
        match self {
            Rail::Confidential => CircuitId::ConfidentialEddsa(2, 3, SLOTS),
            Rail::Ring => CircuitId::RingEddsa(2, 3, SLOTS),
            Rail::P256 => CircuitId::RingP256(
                2,
                3,
                SLOTS,
                RingP256ProofData {
                    bsb22_commitment: EMPTY_LEG_COMMITMENT,
                    default_owner_tag: None,
                },
            ),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Rail::Confidential => "confidential",
            Rail::Ring => "ring eddsa",
            Rail::P256 => "ring p256",
        }
    }

    /// The ring rails settle through a ring config account.
    fn is_ring(self) -> bool {
        self != Rail::Confidential
    }
}

fn ring_address() -> Address {
    Address::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID)
}

fn leg_inputs(env: &mut Pool, index: u8, rail: Rail) -> LegInputs {
    let payer = env.rpc.payer.insecure_clone();
    let owner_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    let blinding = test_blinding(7 + index);
    let amount = WITHDRAW_LAMPORTS;
    let nullifier_key = NullifierKey::from_secret([9 + index; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let p256 = (rail == Rail::P256).then(|| ShieldedKeypair::new().expect("p256 keypair"));
    let owner_public_key = match &p256 {
        Some(keypair) => keypair.signing_pubkey(),
        None => PublicKey::from_ed25519(&owner_bytes),
    };
    let owner_field = owner_hash(&owner_public_key, &nullifier_pk).expect("owner field");
    let utxo = Utxo {
        owner: owner_public_key,
        asset: SOL_MINT,
        amount,
        blinding,
        ring_program_id: rail.is_ring().then(ring_address),
        data: Data::default(),
    };
    match rail {
        Rail::Confidential => {
            env.rpc
                .deposit_sol(&env.tree.pubkey(), &payer, amount, owner_field, blinding)
                .expect("proofless deposit");
        }
        Rail::Ring | Rail::P256 => {
            let shield = env.rpc.ring_sol_shield_data(amount, owner_field, blinding);
            env.rpc
                .ring_deposit(&env.tree.pubkey(), &payer, &shield)
                .expect("ring deposit");
        }
    }

    let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
    let nullifier = nullifier_key
        .nullifier(&utxo_hash, &blinding)
        .expect("nullifier");
    LegInputs {
        utxo_hash,
        nullifier,
        nullifier_key,
        owner_field,
        utxo,
        p256,
    }
}

fn build_leg(
    env: &Pool,
    index: usize,
    inputs: &LegInputs,
    state_tree: &MerkleTree<Poseidon>,
    roots: ([u8; 32], [u8; 32]),
    root_index: u16,
    rail: Rail,
) -> Leg {
    let payer_bytes = env.rpc.payer.pubkey().to_bytes();
    let zero = [0u8; 32];
    let owner_public_key = PublicKey::from_ed25519(&payer_bytes);
    let owner_pk_hash = owner_public_key
        .owner_proof_input_hash()
        .expect("owner pk hash");

    let state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(index, true)
        .expect("state proof")
        .to_vec();
    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    let non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&inputs.nullifier))
        .expect("non-inclusion proof");

    let (dummy_input_1, dummy_nullifier) =
        dummy_input(&[2 + index as u8; 31], &nf_tree, roots).expect("dummy input");
    // A P256 input contributes the zero sentinel the circuit's shared
    // authorization consumes, where an ed25519 input contributes its hash.
    let input_owner_pk_hash = match rail {
        Rail::P256 => zero,
        _ => owner_pk_hash,
    };
    let real_input = spend_input(SpendInputArgs {
        utxo: &inputs.utxo,
        owner_field: &inputs.owner_field,
        state_path: &state_path,
        state_path_index: index as u64,
        non_inclusion: &non_inclusion,
        roots,
        nullifier: &inputs.nullifier,
        owner_pk_hash: &input_owner_pk_hash,
        nullifier_key: &inputs.nullifier_key,
    })
    .expect("real input");

    let base = 1 + 3 * index as u8;
    let dummy_outputs: Vec<(TransferOutput, [u8; 32])> = [base, base + 1, base + 2]
        .iter()
        .map(|seed| dummy_transfer_output(&[*seed; 31]).expect("dummy output"))
        .collect();
    let output_hashes: Vec<[u8; 32]> = dummy_outputs.iter().map(|(_, hash)| *hash).collect();
    let mut outputs: Vec<TransferOutput> = dummy_outputs.into_iter().map(|(out, _)| out).collect();

    let recipient = Pubkey::new_unique();
    let mut data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(inputs.nullifier, root_index),
            eddsa_input_utxo(dummy_nullifier, root_index),
        ],
        vec![InterfaceTransfer::SolWithdrawal {
            amount: WITHDRAW_LAMPORTS,
        }],
        inline_outputs(&output_hashes, &[payer_bytes; 3]),
    );
    data.circuit = rail.circuit();

    // The ring rail publishes an owner tag only for a confidential-marked
    // output, and every output here is an unmarked dummy.
    let owner_pk_hashes = match rail {
        Rail::Confidential => {
            output_owner_pk_hashes(&data.outputs).expect("output owner pk hashes")
        }
        Rail::Ring | Rail::P256 => vec![zero; 3],
    };
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &[zero, zero, zero]);

    let resolved_transfers = [ResolvedInterfaceTransfer::SolWithdrawal {
        amount: WITHDRAW_LAMPORTS,
        recipient: recipient.to_bytes(),
    }];
    // The leg binds the discriminator of its own rail, which is what makes one
    // proof valid both alone and inside a batch.
    let resolved_outputs = resolve_outputs(&data).expect("resolved outputs");
    let external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: rail.kind().solo_tag(),
        expiry_unix_ts: data.expiry_unix_ts,
        interface_transfers: &resolved_transfers,
        data_hash: None,
        ring_data_hash: None,
        tx_viewing_pk: &data.tx_viewing_pk,
        salt: &data.salt,
        outputs: &resolved_outputs,
        messages: &data.messages,
    }
    .hash()
    .expect("external data hash");

    let private_tx = PrivateTxHash::new(
        &[inputs.utxo_hash, zero],
        &[zero, zero, zero],
        &external_data_hash,
    )
    .hash()
    .expect("private tx hash");

    let payer_hash = hash_bytes(&payer_bytes).expect("payer hash");
    let signer_hashes = [payer_hash, zero, zero];
    let (public_slot_assets, public_slot_amounts) =
        sol_public_slots(public_sol_field(Some(-(WITHDRAW_LAMPORTS as i64))));
    let public_inputs = PublicInputs {
        nullifiers: &[inputs.nullifier, dummy_nullifier],
        output_hashes: &output_hashes,
        utxo_roots: &[roots.0, roots.0],
        nullifier_tree_roots: &[roots.1, roots.1],
        private_tx: &private_tx,
        external_data_hash: &external_data_hash,
        public_transfers: &PublicTransfers {
            assets: public_slot_assets,
            amounts: public_slot_amounts,
        },
        ring_program_id: &ring_program_field(rail),
        allow_dummy_inputs: &fe(1),
        signer_pk_hashes: &signer_hashes,
        output_owner_pk_hashes: Some(&owner_pk_hashes),
    };
    // The P256 rail extends the preimage after private_tx_hash with the signed
    // message hash and the default owner tag, which is zero for a ring-only
    // input.
    let p256_authorization = inputs.p256.as_ref().map(|keypair| {
        let message_digest =
            zolana_hasher::sha256::Sha256::hash(&private_tx).expect("p256 message digest");
        let signature =
            SyncWalletAuthority::sign_p256(keypair, &message_digest).expect("p256 signature");
        (message_digest, signature)
    });
    let public_input_hash = match &p256_authorization {
        Some((message_digest, _)) => {
            let message_hash = hash_bytes(message_digest).expect("p256 message proof input");
            public_inputs
                .hash_p256(&message_hash, &zero)
                .expect("public input hash")
        }
        None => public_inputs.hash().expect("public input hash"),
    };

    let mut prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![real_input, dummy_input_1],
        outputs,
        external_data_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        signer_pk_hashes: signer_hashes.to_vec(),
        public_input_hash,
    });
    prover_inputs.ring_program_id = num_bigint::BigUint::from_bytes_be(&ring_program_field(rail));

    let started = Instant::now();
    let (packed, raw, commitment) = match &p256_authorization {
        Some((message_digest, signature)) => {
            let p256_inputs =
                p256_prover_inputs(&prover_inputs, message_digest, signature, public_input_hash);
            let (packed, commitment, raw) =
                prove_and_verify_p256_raw(&p256_inputs, public_input_hash, "p256 leg")
                    .expect("prove p256 leg");
            (packed, raw, Some(commitment))
        }
        None => {
            let (packed, raw) =
                prove_and_verify_rail_raw(&prover_inputs, public_input_hash, "leg", rail.is_ring())
                    .expect("prove leg");
            (packed, raw, None)
        }
    };
    let prove_ms = started.elapsed().as_millis();
    data.private_tx_hash = private_tx;
    data.proof = packed;

    Leg {
        data,
        proof: raw,
        public_input_hash,
        settlement: Some(recipient),
        prove_ms,
        commitment,
    }
}

/// Widen the eddsa witness to the P256 one. The two share every field but the
/// signature, its public key, and the split message digest.
fn p256_prover_inputs(
    base: &zolana_client::TransferInputs,
    message_digest: &[u8; 32],
    signature: &zolana_transaction::P256Signature,
    public_input_hash: [u8; 32],
) -> zolana_client::TransferP256Inputs {
    use num_bigint::BigUint;

    let (pub_x, pub_y) = p256_coordinates(&signature.pubkey).expect("p256 coordinates");

    zolana_client::TransferP256Inputs {
        inputs: base.inputs.clone(),
        outputs: base.outputs.clone(),
        external_data_hash: base.external_data_hash.clone(),
        private_tx_hash: base.private_tx_hash.clone(),
        p256_pub_x: BigUint::from_bytes_be(&pub_x),
        p256_pub_y: BigUint::from_bytes_be(&pub_y),
        p256_sig_r: BigUint::from_bytes_be(&signature.sig_r),
        p256_sig_s: BigUint::from_bytes_be(&signature.sig_s),
        p256_message_hash_low: BigUint::from_bytes_be(&message_digest[16..]),
        p256_message_hash_high: BigUint::from_bytes_be(&message_digest[..16]),
        default_p256_owner_pk_hash: BigUint::from_bytes_be(&[0u8; 32]),
        public_assets: base.public_assets.clone(),
        public_amounts: base.public_amounts.clone(),
        ring_program_id: base.ring_program_id.clone(),
        signer_pk_hashes: base.signer_pk_hashes.clone(),
        allow_dummy_inputs: base.allow_dummy_inputs.clone(),
        published_output_owner_pk_hashes: base.published_output_owner_pk_hashes.clone(),
        public_input_hash: BigUint::from_bytes_be(&public_input_hash),
    }
}

/// The public input binds the hashed ring program id, zero off the ring rail.
fn ring_program_field(rail: Rail) -> [u8; 32] {
    match rail {
        Rail::Confidential => [0u8; 32],
        Rail::Ring | Rail::P256 => {
            hash_bytes(&ring_address().to_bytes()).expect("ring program hash")
        }
    }
}

fn sol_settlement(leg: &Leg) -> Vec<TransactInterfaceTransferAccounts> {
    leg.settlement
        .map(|recipient| {
            vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient },
            )]
        })
        .unwrap_or_default()
}

/// The ring rail needs its program and an enabled config before any deposit.
fn pool_for(rail: Rail) -> Pool {
    let mut env = Pool::initialized();
    if rail.is_ring() {
        env.rpc
            .load_ring_test_program()
            .expect("load ring test program");
        let authority = env.authority.insecure_clone();
        env.rpc
            .create_ring_config(&authority, &authority.pubkey(), true)
            .expect("create ring config");
    }
    env
}

fn solo_compute(env: &mut Pool, leg: &Leg, rail: Rail) -> u64 {
    // The batch clears a leg's commitment, so the solo path puts it back.
    let mut data = leg.data.clone();
    if let Some(commitment) = leg.commitment {
        data.circuit = CircuitId::RingP256(
            2,
            3,
            SLOTS,
            RingP256ProofData {
                bsb22_commitment: commitment,
                default_owner_tag: None,
            },
        );
    }
    let ix = match rail {
        Rail::Confidential => Transact {
            payer: env.rpc.payer.pubkey(),
            input_tree: env.tree.pubkey(),
            output_tree: env.tree.pubkey(),
            owner_signers: Vec::new(),
            interface_transfer_accounts: sol_settlement(leg),
            data,
        }
        .instruction(),
        Rail::Ring | Rail::P256 => RingTransact {
            payer: env.rpc.payer.pubkey(),
            input_tree: env.tree.pubkey(),
            output_tree: env.tree.pubkey(),
            ring_program_id: Pubkey::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID),
            owner_signers: Vec::new(),
            interface_transfer_accounts: sol_settlement(leg),
            data,
        }
        .instruction(),
    };
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    env.rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .expect("solo transact");
    env.rpc
        .last_transaction_trace()
        .expect("solo trace")
        .compute_units_consumed
}

#[test]
fn aggregate_reports_compute() {
    for rail in [Rail::Confidential, Rail::Ring, Rail::P256] {
        for legs in [2usize, 3] {
            measure(rail, legs);
        }
    }
}

fn measure(rail: Rail, legs: usize) {
    {
        let mut env = pool_for(rail);

        let mut inputs = Vec::with_capacity(legs);
        for index in 0..legs {
            inputs.push(leg_inputs(&mut env, index as u8, rail));
        }

        // Every leg proves against the root after the last deposit, so the
        // batch needs one merkle tree and one root index.
        let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
        for leg in &inputs {
            state_tree
                .append(&leg.utxo_hash)
                .expect("append state leaf");
        }
        let root_index = legs as u16;
        let roots = tree_roots(&env.rpc, &env.tree.pubkey(), root_index);
        assert_eq!(state_tree.root(), roots.0, "state root gate");

        let built: Vec<Leg> = inputs
            .iter()
            .enumerate()
            .map(|(index, leg)| build_leg(&env, index, leg, &state_tree, roots, root_index, rail))
            .collect();

        let started = Instant::now();
        let outer = ProverClient::local()
            .prove_aggregate(&AggregateInputs {
                inner: rail.kind(),
                num_inputs: 2,
                num_outputs: 3,
                legs: built
                    .iter()
                    .map(|leg| AggregateLeg {
                        proof: leg.proof,
                        public_input_hash: leg.public_input_hash,
                    })
                    .collect(),
            })
            .expect("prove aggregate");
        let aggregate_prove_ms = started.elapsed().as_millis();
        let outer = zolana_client::ProofCompressed::try_from(outer).expect("compress outer");
        let (proof, bsb22_commitment) = outer
            .into_ring_p256_transact_parts()
            .expect("outer proof parts");

        let data = AggregateTransactIxData {
            circuit: AggregateCircuitId {
                kind: rail.kind(),
                num_inputs: 2,
                num_outputs: 3,
                num_public_asset_slots: SLOTS,
                batch: legs as u8,
            },
            proof,
            bsb22_commitment,
            legs: built
                .iter()
                .map(|leg| TransactIxData {
                    proof: EMPTY_LEG_PROOF,
                    ..leg.data.clone()
                })
                .collect(),
            leg_account_counts: Vec::new(),
        };
        let instruction = AggregateTransact {
            payer: env.rpc.payer.pubkey(),
            input_tree: env.tree.pubkey(),
            output_tree: env.tree.pubkey(),
            ring_program_ids: vec![
                Pubkey::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID);
                legs
            ],
            owner_signers: vec![Vec::new(); legs],
            interface_transfer_accounts: built.iter().map(sol_settlement).collect(),
            data,
        }
        .instruction();

        let data_len = instruction.data.len();
        let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        env.rpc
            .create_and_send_default_payer_transaction(&[budget, instruction], &[])
            .expect("aggregate transact");
        let consumed = env
            .rpc
            .last_transaction_trace()
            .expect("aggregate trace")
            .compute_units_consumed;

        // Solo baseline on a fresh environment, so the tree state matches.
        let mut solo_env = pool_for(rail);
        let solo_inputs = leg_inputs(&mut solo_env, 0, rail);
        let mut solo_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
        solo_tree
            .append(&solo_inputs.utxo_hash)
            .expect("append solo leaf");
        let solo_roots = tree_roots(&solo_env.rpc, &solo_env.tree.pubkey(), 1);
        let solo_leg = build_leg(&solo_env, 0, &solo_inputs, &solo_tree, solo_roots, 1, rail);
        let solo = solo_compute(&mut solo_env, &solo_leg, rail);

        let leg_prove_ms: Vec<u128> = built.iter().map(|leg| leg.prove_ms).collect();
        println!("{} 2x3, {legs} legs", rail.label());
        println!("  instruction data: {data_len} bytes");
        println!("  leg proving: {leg_prove_ms:?} ms");
        println!("  aggregate proving: {aggregate_prove_ms} ms");
        println!(
            "  aggregate: {consumed} CU against {} CU solo",
            solo * legs as u64
        );
        let solo_total = solo * legs as u64;
        println!("  saved: {} CU", solo_total.saturating_sub(consumed));
        // The batched path exists only to undercut the solo total. A change
        // that inverts that has to move this assertion, not just the number.
        assert!(
            consumed < solo_total,
            "{} {legs} legs: batch cost {consumed} CU against {solo_total} CU solo",
            rail.label()
        );
        assert!(
            consumed <= AGGREGATE_CU_LIMIT,
            "{} {legs} legs: batch cost {consumed} CU, over the transaction budget",
            rail.label()
        );
    }
}
