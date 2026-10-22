//! Paired Squads/SPP proofs against real in-memory state and nullifier trees.
//! Requires `just build-prover-server`; missing SPP keys download on demand.
//! Starts its own main prover on an ephemeral port and stops it on exit.

use std::{
    fs::File,
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use groth16_solana::{decompression::decompress_g1, groth16::Groth16Verifier};
use num_bigint::BigUint;
use solana_address::Address;
use zolana_client::{
    prover::{
        merge::{MergePublicInputBinding, MergePublicInputs},
        PublicInputs,
    },
    MerkleContext, MerkleProof, NonInclusionProof, PublicTransfers, Shape, SpendProof,
    NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_hasher::{
    hash_chain::create_hash_chain_4_from_slice,
    primitives::{hash_bytes, solana_owner_identity},
    Poseidon,
};
use zolana_interface::{
    instruction::{
        instruction_data::merge_transact::MergeExternalDataHash,
        tag::{RING_AUTHORITY_TRANSACT, RING_MERGE_TRANSACT, RING_TRANSACT},
    },
    pda,
    state::cache::empty_cached_input_fields,
    tree_slot::{pack_input_flags, populated_tree_slots_hash_chain, TreeSlot},
    verifying_keys::merge_ring_8_1,
    INPUT_TREES, SOL_ASSET_FIELD,
};
use zolana_keypair::{NullifierKey, PublicKey, SigningKey, X25519Keypair};
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};
use zolana_squads_interface::SQUADS_RING_PROGRAM_ID;
use zolana_squads_sdk::prover::{
    dummy_input, merge_dummy_nullifiers, probe_squads_spend, prove_squads_merge, sign_spend,
    SquadsDummyInput, SquadsMergeRequest, SquadsOwner, SquadsRecipient, SquadsSender,
    SquadsSpendInput, SquadsSpendOperation, SquadsSpendProof, SquadsSpendRequest,
    WithdrawalSettlement,
};
use zolana_transaction::{
    instructions::{
        merge::{merge_output_key, MergeOutputPlaintext},
        transact::{signed_magnitude_to_field, transact_message_hash, BN254_MODULUS_DEC},
    },
    Data, Mint, Utxo, SOL_MINT,
};

const TREE_ID: u16 = 0;
const PAYER: Address = Address::new_from_array([91; 32]);

struct ProverServer {
    url: String,
    child: Child,
}

impl ProverServer {
    fn start() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let binary = std::env::var_os("SPP_PROVER_SERVER_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("target/prover-server"));
        assert!(
            binary.is_file(),
            "missing {}; run just build-prover-server",
            binary.display()
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve prover port");
        let address = listener.local_addr().expect("prover address");
        drop(listener);
        let metrics = TcpListener::bind("127.0.0.1:0").expect("reserve metrics port");
        let metrics_address = metrics.local_addr().expect("metrics address");
        drop(metrics);
        let log_path = root.join("rings/squads/target/paired-proof-server.log");
        let log = File::create(&log_path).expect("create prover log");
        let keys = std::env::var_os("ZOLANA_SPP_KEYS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("prover/server/proving-keys"));
        let child = Command::new(binary)
            .arg("start")
            .args([
                "--prover-address",
                &address.to_string(),
                "--metrics-address",
                &metrics_address.to_string(),
            ])
            .arg("--keys-dir")
            .arg(keys)
            .arg("--auto-download")
            .args([
                "--serve",
                "transfer_eddsa_ring_2_2",
                "--serve",
                "transfer_eddsa_ring_1_2",
                "--serve",
                "transfer_ring_authority_2_2",
                "--serve",
                "merge_ring_8_1",
            ])
            .stdin(Stdio::null())
            .stdout(log.try_clone().expect("clone prover log"))
            .stderr(log)
            .spawn()
            .expect("start main SPP prover");
        let mut server = Self {
            url: format!("http://{address}"),
            child,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while TcpStream::connect(address).is_err() {
            assert!(
                server.child.try_wait().expect("poll prover").is_none(),
                "prover exited; see {}",
                log_path.display()
            );
            if Instant::now() >= deadline {
                panic!("prover startup timed out; see {}", log_path.display());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        server
    }
}

impl Drop for ProverServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct InputUtxoFixture {
    amount: u64,
    blinding: [u8; 32],
    hash: [u8; 32],
    nullifier: [u8; 32],
    leaf_index: u64,
}

struct Trees {
    state: MerkleTree<Poseidon>,
    nullifiers: IndexedMerkleTree<Poseidon, usize>,
    input_utxos: Vec<InputUtxoFixture>,
}

fn context() -> MerkleContext {
    MerkleContext {
        tree_type: 0,
        tree: pda::tree(TREE_ID),
    }
}

impl Trees {
    fn new(owner_identity: [u8; 32], nullifier_key: &NullifierKey, amounts: &[u64]) -> Self {
        let mut state = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
        let upper = BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10).expect("modulus") - 1u32;
        let nullifiers = IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(
            NULLIFIER_TREE_HEIGHT,
            0,
            upper,
        )
        .expect("indexed nullifier tree");
        let nullifier_pk = nullifier_key.pubkey().expect("nullifier public key");
        let input_utxos = amounts
            .iter()
            .enumerate()
            .map(|(index, amount)| {
                let mut blinding = [0; 32];
                blinding[31] = u8::try_from(index + 1).expect("small fixture index");
                let utxo = Utxo {
                    owner: PublicKey::from_owner_identity(owner_identity),
                    asset: Mint::SOL,
                    amount: *amount,
                    blinding,
                    ring_program_id: Some(Address::new_from_array(SQUADS_RING_PROGRAM_ID)),
                    data: Data::default(),
                };
                let hash = utxo
                    .hash(&nullifier_pk, &[0; 32], &[0; 32], TREE_ID)
                    .expect("input_utxo hash");
                state.append(&hash).expect("append input_utxo");
                InputUtxoFixture {
                    amount: *amount,
                    blinding,
                    hash,
                    nullifier: nullifier_key
                        .nullifier(&hash, &blinding)
                        .expect("nullifier"),
                    leaf_index: index as u64,
                }
            })
            .collect();
        Self {
            state,
            nullifiers,
            input_utxos,
        }
    }

    fn non_inclusion(&self, nullifier: [u8; 32]) -> NonInclusionProof {
        let proof = self
            .nullifiers
            .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
            .expect("non-inclusion proof");
        NonInclusionProof {
            leaf: nullifier,
            merkle_context: context(),
            path: proof.merkle_proof.to_vec(),
            low_element: proof.leaf_lower_range_value,
            low_element_index: proof.leaf_index as u64,
            high_element: proof.leaf_higher_range_value,
            high_element_index: 0,
            root: proof.root,
            root_seq: 0,
            root_index: 0,
        }
    }

    fn inputs(&self) -> Vec<SquadsSpendInput> {
        self.input_utxos
            .iter()
            .map(|input_utxo| SquadsSpendInput {
                asset: SOL_MINT,
                amount: input_utxo.amount,
                blinding: input_utxo.blinding,
                tree_id: TREE_ID,
                leaf_index: input_utxo.leaf_index,
                spend_proof: SpendProof {
                    state: MerkleProof {
                        leaf: input_utxo.hash,
                        merkle_context: context(),
                        path: self
                            .state
                            .get_proof_of_leaf(input_utxo.leaf_index as usize, true)
                            .expect("state inclusion")
                            .to_vec(),
                        leaf_index: input_utxo.leaf_index,
                        root: self.state.root(),
                        root_seq: 0,
                        root_index: 0,
                    },
                    nullifier: self.non_inclusion(input_utxo.nullifier),
                },
            })
            .collect()
    }

    fn tree_slots(&self) -> [TreeSlot; INPUT_TREES] {
        let mut slots = [TreeSlot::ZERO; INPUT_TREES];
        slots[0] = TreeSlot::new(TREE_ID, self.state.root(), self.nullifiers.root());
        slots
    }
}

fn verify_spend(result: &SquadsSpendProof, trees: &Trees, withdrawal: u64) {
    let spp = &result.spp;
    let anonymous = spp.circuit.is_anonymous();
    let tag = if anonymous {
        RING_TRANSACT
    } else {
        RING_AUTHORITY_TRANSACT
    };
    let external = squads_ring_tests::spp_external_data_hash(tag, spp, &result.spp_accounts);
    let n_in = usize::from(spp.circuit.num_inputs());
    let n_out = usize::from(spp.circuit.num_outputs());
    let mut nullifiers = spp
        .inputs
        .iter()
        .map(|input| input.nullifier_hash)
        .collect::<Vec<_>>();
    nullifiers.resize(n_in, [0; 32]);
    let mut outputs = spp
        .outputs
        .iter()
        .map(|output| output.utxo_hash)
        .collect::<Vec<_>>();
    outputs.resize(n_out, [0; 32]);
    let slots = trees.tree_slots();
    let mut public_transfers = PublicTransfers::default();
    if withdrawal > 0 {
        public_transfers.assets[0] = SOL_ASSET_FIELD;
        public_transfers.amounts[0] = signed_magnitude_to_field(false, withdrawal);
    }
    let ring = hash_bytes(&SQUADS_RING_PROGRAM_ID).expect("ring identity");
    let flags = pack_input_flags(true, spp.inputs.iter().map(|input| input.tree_index))
        .expect("input flags");
    let signers = if anonymous {
        vec![[0; 32]; Shape::new(n_in, n_out).signer_width()]
    } else {
        vec![solana_owner_identity(PAYER.as_array()).expect("payer identity")]
    };
    let owner_hashes = vec![[0; 32]; n_out];
    let public = PublicInputs {
        nullifiers: &nullifiers,
        output_hashes: &outputs,
        tree_slots: &slots,
        output_tree_id: TREE_ID,
        private_tx: &spp.private_tx_hash,
        external_data_hash: &external,
        public_transfers: &public_transfers,
        ring_program_id: &ring,
        input_flags: &flags,
        signer_pk_hashes: &signers,
        output_owner_pk_hashes: anonymous.then_some(owner_hashes.as_slice()),
        cached_inputs: empty_cached_input_fields(n_in).expect("empty cache"),
    };
    let after_private = if anonymous {
        vec![
            hash_bytes(&transact_message_hash(&spp.private_tx_hash, &external))
                .expect("message field"),
            [0; 32],
        ]
    } else {
        Vec::new()
    };
    let mut fields = public
        .without_roots(&after_private)
        .expect("statement fields");
    fields.insert(
        2,
        populated_tree_slots_hash_chain(&slots[..1]).expect("tree slots hash"),
    );
    let hash = create_hash_chain_4_from_slice(&fields).expect("public input hash");
    let a = decompress_g1(&spp.proof.a).expect("decompress proof A");
    let c = decompress_g1(&spp.proof.c).expect("decompress proof C");
    let inputs = [hash];
    let vk = spp.circuit.verifying_key().expect("supported SPP shape");
    if let Some(commitment) = spp.circuit.bsb22_commitment() {
        let com = decompress_g1(&commitment.commitment).expect("commitment");
        let pok = decompress_g1(&commitment.commitment_pok).expect("commitment proof");
        Groth16Verifier::new_with_commitment(&a, &spp.proof.b, &c, &com, &pok, &inputs, vk)
            .expect("committed verifier")
            .verify()
            .expect("anonymous SPP proof verifies against final wire data");
    } else {
        Groth16Verifier::new(&a, &spp.proof.b, &c, &inputs, vk)
            .expect("vanilla verifier")
            .verify()
            .expect("ring-authority SPP proof verifies against final wire data");
    }
}

fn prove_spend(url: &str, smart_account: bool, transfer: bool) {
    let owner = SigningKey::from_ed25519_bytes(&[3; 32]);
    let owner_identity = owner
        .pubkey()
        .owner_proof_input_hash()
        .expect("owner identity");
    let nullifier_key = NullifierKey::from_secret([2; 31]);
    let viewing_secret = X25519Keypair::from_bytes(&[7; 32]);
    let trees = Trees::new(
        owner_identity,
        &nullifier_key,
        if transfer { &[70, 30] } else { &[100] },
    );
    let dummy = smart_account.then(|| {
        let blinding = [9; 32];
        let nullifier = dummy_input(blinding, TREE_ID).expect("dummy").nullifier;
        SquadsDummyInput {
            blinding,
            nullifier_proof: trees.non_inclusion(nullifier),
        }
    });
    let operation = if transfer {
        SquadsSpendOperation::Transfer {
            recipient: SquadsRecipient {
                owner_identity: SigningKey::from_ed25519_bytes(&[4; 32])
                    .pubkey()
                    .owner_proof_input_hash()
                    .expect("recipient identity"),
                nullifier_pubkey: NullifierKey::from_secret([5; 31])
                    .pubkey()
                    .expect("recipient nullifier key"),
                viewing_pubkey: X25519Keypair::from_bytes(&[6; 32]).pubkey(),
                view_tag: [8; 32],
            },
            amount: 40,
        }
    } else {
        SquadsSpendOperation::Withdrawal {
            amount: 40,
            settlement: WithdrawalSettlement::Sol {
                recipient: Address::new_from_array([11; 32]),
            },
        }
    };
    let probe = probe_squads_spend(SquadsSpendRequest {
        sender: SquadsSender {
            owner: if smart_account {
                SquadsOwner::SmartAccount
            } else {
                SquadsOwner::Ed25519(owner.pubkey().as_ed25519().expect("Ed25519 owner"))
            },
            owner_identity,
            nullifier_key,
            viewing_secret,
            view_tag: [10; 32],
        },
        inputs: trees.inputs(),
        dummy,
        operation,
        payer: PAYER,
        output_tree_id: TREE_ID,
        expiry_unix_ts: u64::MAX,
        proposal: None,
        prover_url: url.into(),
    })
    .expect("probe spend with real Merkle proofs");
    let authorization = (!smart_account)
        .then(|| sign_spend(&owner, &probe.message_hash).expect("sign detached message"));
    let result = probe
        .finalize(authorization)
        .expect("prove paired Squads and SPP spend");
    assert_eq!(
        (
            result.change.amount,
            result.recipient.map(|output| output.amount)
        ),
        (60, transfer.then_some(40)),
        "value conservation"
    );
    assert_eq!(
        (result.spp.inputs.len(), result.spp.outputs.len()),
        (
            if smart_account || transfer { 2 } else { 1 },
            if transfer { 2 } else { 1 }
        ),
        "compact padding omitted from wire outputs"
    );
    verify_spend(&result, &trees, if transfer { 0 } else { 40 });
}

fn prove_merge(url: &str) {
    let identity = SigningKey::from_ed25519_bytes(&[3; 32])
        .pubkey()
        .owner_proof_input_hash()
        .expect("owner identity");
    let key = NullifierKey::from_secret([2; 31]);
    let trees = Trees::new(identity, &key, &[70, 30]);
    let dummies = merge_dummy_nullifiers(
        &key,
        &trees.input_utxos[0].nullifier,
        trees.input_utxos.len(),
    )
    .expect("merge padding nullifiers");
    let result = prove_squads_merge(SquadsMergeRequest {
        owner_identity: identity,
        nullifier_key: key.clone(),
        viewing_pubkey: X25519Keypair::from_bytes(&[7; 32]).pubkey(),
        inputs: trees.inputs(),
        dummy_nullifier_proofs: dummies
            .into_iter()
            .map(|nullifier| trees.non_inclusion(nullifier))
            .collect(),
        expiry_unix_ts: u64::MAX,
        output_tree_id: TREE_ID,
        payer: PAYER,
        prover_url: url.into(),
    })
    .expect("prove Squads merge with compact dummy inputs");
    assert_eq!(
        (
            result.output_amount,
            result.spp.merge.nullifiers.len(),
            result.nullifiers.len()
        ),
        (100, 2, 8),
        "merge pads witness to8 but publishes2real nullifiers"
    );
    let merge = &result.spp.merge;
    let external = MergeExternalDataHash {
        spp_instruction_discriminator: RING_MERGE_TRANSACT,
        expiry_unix_ts: merge.expiry_unix_ts,
        output_utxo_hash: &merge.output_utxo_hash,
        cache: None,
    }
    .hash()
    .expect("merge external hash");
    let mut padded = merge.nullifiers.clone();
    padded.resize(8, [0; 32]);
    let slots = trees.tree_slots();
    let hash = MergePublicInputs {
        nullifiers: &padded,
        output_hash: merge.output_utxo_hash,
        output_tree_id: TREE_ID,
        private_tx_hash: merge.private_tx_hash,
        external_data_hash: external,
        allow_dummy_inputs: true,
        binding: MergePublicInputBinding::Ring {
            output_data_hash: result.spp.output_ring_data_hash,
            program_id_hash: hash_bytes(&SQUADS_RING_PROGRAM_ID).expect("ring identity"),
        },
    }
    .hash(populated_tree_slots_hash_chain(&slots[..1]).expect("merge tree slots"))
    .expect("merge public input hash");
    let a = decompress_g1(&merge.proof.a).expect("merge proof A");
    let c = decompress_g1(&merge.proof.c).expect("merge proof C");
    Groth16Verifier::new(
        &a,
        &merge.proof.b,
        &c,
        &[hash],
        &merge_ring_8_1::VERIFYINGKEY,
    )
    .expect("merge verifier")
    .verify()
    .expect("SPP merge proof verifies against final wire data");
    let output_key = merge_output_key(&key, &merge.nullifiers[0]).expect("merged output key");
    let zolana_interface::instruction::instruction_data::merge_transact::MergeOutputEncryption::PoseidonCtrV1 { salt, ciphertext } = merge.output_encryption;
    let body: Vec<_> = salt
        .into_iter()
        .chain(ciphertext.into_iter().flatten())
        .collect();
    assert_eq!(
        MergeOutputPlaintext::decrypt(&body, &output_key).expect("decrypt merged output"),
        MergeOutputPlaintext {
            amount: 100,
            mint: SOL_MINT
        }
    );
}

#[test]
fn paired_spp_proofs_verify_spends_padding_and_merge() {
    let server = ProverServer::start();
    for (name, smart, transfer) in [
        ("keypair transfer2x2", false, true),
        ("keypair withdrawal1x2", false, false),
        ("smart-account withdrawal2x2", true, false),
    ] {
        eprintln!("proving {name}");
        prove_spend(&server.url, smart, transfer);
    }
    eprintln!("proving merge-ring with compact padding");
    prove_merge(&server.url);
}
