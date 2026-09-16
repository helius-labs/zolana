use num_bigint::BigUint;
use solana_account::Account;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    prover::direct_spend as direct,
    prover::{ProofCompressed, ProveRequest},
    MerkleContext, MerkleProof, NonInclusionProof, ProverClient,
};
use zolana_hasher::{primitives::solana_owner_identity, Hasher, Poseidon};
use zolana_interface::{
    direct_spend::{
        self as wire, field, Payload, Payment, PaymentInputs, PrepareCertificate, Root,
    },
    instruction::builders::direct_spend as instructions,
    pda, PROGRAM_ID_PUBKEY,
};
use zolana_keypair::NullifierKey;
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::transact::nullifier_tree;
use zolana_transaction::ProofInputUtxo;
use zolana_tree::{
    pending_nullifiers::PendingNullifiers, NullifierTreeInitParams, TreeAccount, TreeFeeSchedule,
};

struct Fixture {
    rpc: ZolanaProgramTest,
    owner: Keypair,
    tree: Pubkey,
    output_tree: Pubkey,
    inputs: Vec<direct::Input>,
    key: NullifierKey,
}

impl Fixture {
    fn new(count: usize) -> Self {
        let mut rpc = ZolanaProgramTest::new().unwrap();
        let owner = rpc.payer.insecure_clone();
        let tree = pda::tree(7);
        let key = NullifierKey::from_secret([19; 31]);
        let owner_hash = Poseidon::hashv(&[
            &solana_owner_identity(&owner.pubkey().to_bytes()).unwrap(),
            &key.pubkey().unwrap(),
        ])
        .unwrap();
        let mut state = MerkleTree::<Poseidon>::new(32, 0);
        let mut notes = Vec::new();
        let mut data = vec![0; TreeAccount::account_size()];
        let mut account = TreeAccount::init(
            &mut data,
            1,
            32,
            tree.to_bytes(),
            7,
            NullifierTreeInitParams::default(),
            TreeFeeSchedule::default(),
        )
        .unwrap();
        account.enable_compact_nullifiers().unwrap();
        for index in 0..count {
            let note = ProofInputUtxo {
                domain: field(3),
                tree_id: field(7),
                owner_hash,
                asset: field(1),
                amount: field(10),
                blinding: field(index as u64 + 100),
                data_hash: [0; 32],
                ring_data_hash: [0; 32],
                ring_program_id: [0; 32],
            };
            let leaf = note.hash().unwrap();
            state.append(&leaf).unwrap();
            notes.push(note);
        }
        account
            .utxo_tree()
            .append_batch(
                notes
                    .iter()
                    .map(|note| note.hash().unwrap())
                    .collect::<Vec<_>>()
                    .iter(),
                0,
            )
            .unwrap();
        let root = state.root();
        let root_index = (0..500)
            .find(|index| account.get_utxo_tree_root(*index).ok() == Some(root))
            .unwrap();
        drop(account);
        rpc.svm
            .set_account(
                tree,
                Account {
                    lamports: 1_000_000_000,
                    data,
                    owner: PROGRAM_ID_PUBKEY,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let mut pending = vec![0; PendingNullifiers::account_size(25_000).unwrap()];
        PendingNullifiers::init(&mut pending, &tree.to_bytes()).unwrap();
        rpc.svm
            .set_account(
                pda::pending_nullifiers(&tree).0,
                Account {
                    lamports: 100_000_000_000,
                    data: pending,
                    owner: PROGRAM_ID_PUBKEY,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let output_tree = pda::tree(8);
        let mut data = vec![0; TreeAccount::account_size()];
        TreeAccount::init(
            &mut data,
            1,
            32,
            output_tree.to_bytes(),
            8,
            NullifierTreeInitParams::default(),
            TreeFeeSchedule::default(),
        )
        .unwrap();
        rpc.svm
            .set_account(
                output_tree,
                Account {
                    lamports: 1_000_000_000,
                    data,
                    owner: PROGRAM_ID_PUBKEY,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let context = MerkleContext {
            tree_type: 0,
            tree: Address::new_from_array(tree.to_bytes()),
        };
        let inputs = notes
            .into_iter()
            .enumerate()
            .map(|(index, note)| {
                let proof = MerkleProof {
                    leaf: note.hash().unwrap(),
                    merkle_context: context.clone(),
                    path: state.get_proof_of_leaf(index, true).unwrap(),
                    leaf_index: index as u64,
                    root,
                    root_index,
                    root_seq: 0,
                };
                direct::Input::new(note, proof).unwrap()
            })
            .collect();
        Self {
            rpc,
            owner,
            tree,
            output_tree,
            inputs,
            key,
        }
    }

    fn upload(&mut self, nonce: [u8; 32], payload: Payload) -> Pubkey {
        let owner = self.owner.pubkey();
        for instruction in instructions::upload_spend(owner, nonce, &payload).unwrap() {
            self.rpc
                .create_and_send_transaction_with_budget(
                    &[instruction],
                    &owner,
                    &[&self.owner],
                    direct::COMPUTE_BUDGET,
                )
                .unwrap();
        }
        instructions::spend_buffer(&owner, &nonce)
    }

    fn freshness(
        &self,
        certificate: &wire::Certificate,
        capacity: usize,
    ) -> (Root, direct::Request) {
        let tree = nullifier_tree().unwrap();
        let proofs = certificate
            .nullifiers
            .iter()
            .map(|nullifier| {
                let proof = tree
                    .get_non_inclusion_proof(&BigUint::from_bytes_be(nullifier))
                    .unwrap();
                NonInclusionProof {
                    leaf: *nullifier,
                    merkle_context: MerkleContext {
                        tree_type: 0,
                        tree: Address::new_from_array(self.tree.to_bytes()),
                    },
                    path: proof.merkle_proof,
                    low_element: proof.leaf_lower_range_value,
                    low_element_index: proof.leaf_index as u64,
                    high_element: proof.leaf_higher_range_value,
                    high_element_index: 0,
                    root: tree.root(),
                    root_seq: 0,
                    root_index: 0,
                }
            })
            .collect::<Vec<_>>();
        direct::freshness(certificate, 7, &proofs, capacity).unwrap()
    }

    fn payment(&self, inputs: PaymentInputs) -> (Payment, Vec<direct::Output>) {
        let recipient = self.owner.pubkey().to_bytes();
        let nullifier_pk = self.key.pubkey().unwrap();
        let owner_hash =
            Poseidon::hashv(&[&solana_owner_identity(&recipient).unwrap(), &nullifier_pk]).unwrap();
        let outputs = [self.inputs.len() as u64 * 10, 0]
            .into_iter()
            .enumerate()
            .map(|(index, amount)| direct::Output {
                note: ProofInputUtxo {
                    domain: field(3),
                    tree_id: field(8),
                    owner_hash,
                    asset: field(1),
                    amount: field(amount),
                    blinding: field(50_000 + index as u64),
                    data_hash: [0; 32],
                    ring_data_hash: [0; 32],
                    ring_program_id: [0; 32],
                },
                nullifier_pk,
            })
            .collect::<Vec<_>>();
        let public = outputs
            .iter()
            .map(|output| wire::Output {
                recipient,
                utxo: zolana_interface::event::OutputUtxo {
                    view_tag: [0; 32],
                    utxo_hash: output.note.hash().unwrap(),
                    data: Vec::new(),
                },
            })
            .collect();
        (
            Payment {
                inputs,
                output_tree: self.output_tree.to_bytes(),
                expiry_slot: u64::MAX,
                max_forester_fee: 0,
                outputs: public,
                tx_viewing_pk: [0; 33],
                salt: [0; 16],
            },
            outputs,
        )
    }
}

fn prove(request: &impl ProveRequest) -> wire::Proof {
    let url = std::env::var("ZOLANA_PROVER_URL")
        .expect("set ZOLANA_PROVER_URL to a prover with direct-spend development keys");
    let proof = ProverClient::new(url).prove(request).unwrap();
    ProofCompressed::try_from(proof)
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn prepared_spend_consumes_original_inputs_and_rejects_replay() {
    let count = std::env::var("DIRECT_SPEND_TEST_INPUTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(40);
    let mut fixture = Fixture::new(count);
    let owner = fixture.owner.pubkey();
    let mut certificates = Vec::new();
    let mut openings = Vec::new();
    for start in (0..count).step_by(wire::CERTIFICATE_INPUTS) {
        let nonce = field(start as u64 + 1);
        let buffer = instructions::spend_buffer(&owner, &nonce);
        let end = (start + wire::CERTIFICATE_INPUTS).min(count);
        let plan = direct::certificate(
            owner.to_bytes(),
            buffer.to_bytes(),
            fixture.tree.to_bytes(),
            7,
            &fixture.key,
            &fixture.inputs[start..end],
            field(start as u64 + 23),
            wire::CERTIFICATE_INPUTS,
        )
        .unwrap();
        let certificate_proof = prove(&plan.request);
        let (root, fresh) = fixture.freshness(&plan.statement, wire::CERTIFICATE_INPUTS);
        let freshness_proof = prove(&fresh);
        fixture.upload(
            nonce,
            Payload::Certificate {
                statement: plan.statement,
                proof: certificate_proof,
            },
        );
        let ix = instructions::prepare_certificate(
            owner,
            buffer,
            fixture.tree,
            &PrepareCertificate {
                freshness: root,
                proof: freshness_proof,
            },
        );
        fixture
            .rpc
            .create_and_send_transaction_with_budget(
                &[ix],
                &owner,
                &[&fixture.owner],
                direct::COMPUTE_BUDGET,
            )
            .unwrap();
        certificates.push(buffer);
        openings.push(plan.opening);
    }
    let nonce = field(9999);
    let buffer = instructions::spend_buffer(&owner, &nonce);
    let (payment, outputs) = fixture.payment(PaymentInputs::Certificates(
        certificates.iter().map(|key| key.to_bytes()).collect(),
    ));
    let request = direct::balance(
        &payment,
        owner.to_bytes(),
        buffer.to_bytes(),
        8,
        &openings.iter().collect::<Vec<_>>(),
        &outputs,
        wire::MAX_CERTIFICATES,
    )
    .unwrap();
    let proof = prove(&request);
    fixture.upload(
        nonce,
        Payload::Payment {
            statement: payment,
            proof,
        },
    );
    let ix = instructions::commit_spend(
        owner,
        buffer,
        fixture.tree,
        fixture.output_tree,
        &certificates,
    );
    let result = fixture
        .rpc
        .create_and_send_transaction_with_budget(
            &[ix.clone()],
            &owner,
            &[&fixture.owner],
            direct::COMPUTE_BUDGET,
        )
        .unwrap();
    println!(
        "commit CU: {}",
        fixture
            .rpc
            .last_transaction_trace()
            .unwrap()
            .compute_units_consumed
    );
    assert_eq!(
        result
            .events
            .iter()
            .map(|event| event.decoded.as_ref().unwrap().inputs.len())
            .sum::<usize>(),
        count
    );
    assert_eq!(
        result
            .events
            .iter()
            .map(|event| event.decoded.as_ref().unwrap().outputs.len())
            .sum::<usize>(),
        2
    );
    assert!(fixture
        .rpc
        .create_and_send_transaction_with_budget(
            &[ix],
            &owner,
            &[&fixture.owner],
            direct::COMPUTE_BUDGET
        )
        .is_err());
}

#[test]
#[ignore]
fn gkr_payment_checks_commitment_statement_and_replay() {
    payment_checks_commitment_statement_and_replay(PaymentMode::Gkr);
}

#[test]
#[ignore]
fn admitted_payment_checks_history_commitment_statement_and_replay() {
    payment_checks_commitment_statement_and_replay(PaymentMode::Admitted);
}

#[test]
#[ignore]
fn dag_payment_checks_history_commitment_statement_and_replay() {
    payment_checks_commitment_statement_and_replay(PaymentMode::Dag);
}

enum PaymentMode {
    Gkr,
    Admitted,
    Dag,
}

fn payment_checks_commitment_statement_and_replay(mode: PaymentMode) {
    let admitted = !matches!(mode, PaymentMode::Gkr);
    let dag = matches!(mode, PaymentMode::Dag);
    let count = std::env::var("DIRECT_SPEND_TEST_INPUTS")
        .ok()
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(4);
    let capacity = if !dag && count <= 144 { 144 } else { 512 };
    let mut fixture = Fixture::new(count);
    let filter_key = pda::nullifier_filter(&fixture.tree).0;
    {
        use zolana_tree::nullifier_filter::{NullifierFilter, DEFAULT_BIT_BYTES, DEFAULT_HASHES};
        let mut tree = fixture.rpc.svm.get_account(&fixture.tree).unwrap();
        TreeAccount::from_bytes(&mut tree.data, fixture.tree.to_bytes())
            .unwrap()
            .enable_nullifier_filter()
            .unwrap();
        fixture.rpc.svm.set_account(fixture.tree, tree).unwrap();
        let mut data = vec![0; NullifierFilter::account_size(DEFAULT_BIT_BYTES).unwrap()];
        NullifierFilter::init_zeroed(&mut data, &fixture.tree.to_bytes(), DEFAULT_HASHES).unwrap();
        fixture
            .rpc
            .svm
            .set_account(
                filter_key,
                Account {
                    lamports: 100_000_000_000,
                    data,
                    owner: PROGRAM_ID_PUBKEY,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
    }
    let owner = fixture.owner.pubkey();
    let nonce = field(8888);
    let buffer = instructions::spend_buffer(&owner, &nonce);
    let plan = direct::certificate(
        owner.to_bytes(),
        buffer.to_bytes(),
        fixture.tree.to_bytes(),
        7,
        &fixture.key,
        &fixture.inputs,
        field(23),
        capacity,
    )
    .unwrap();
    let (root, freshness) = if admitted {
        (
            Root {
                index: 0,
                value: [0; 32],
            },
            None,
        )
    } else {
        let (root, request) = fixture.freshness(&plan.statement, capacity);
        (root, Some(request))
    };
    let (payment, outputs) = fixture.payment(PaymentInputs::Notes {
        certificate: plan.statement,
        freshness: root,
    });
    let balance = direct::balance(
        &payment,
        owner.to_bytes(),
        buffer.to_bytes(),
        8,
        &[&plan.opening],
        &outputs,
        1,
    )
    .unwrap();
    let request = if let Some(freshness) = freshness {
        direct::payment(
            plan.request,
            freshness,
            balance,
            &payment,
            owner.to_bytes(),
            buffer.to_bytes(),
            7,
            8,
            &plan.opening,
        )
        .unwrap()
        .with_gkr()
        .unwrap()
    } else if dag {
        direct::admitted_dag_payment(
            plan.request,
            balance,
            &payment,
            owner.to_bytes(),
            buffer.to_bytes(),
            7,
            8,
            &plan.opening,
            &fixture.inputs,
        )
        .unwrap()
    } else {
        direct::admitted_payment(
            plan.request,
            balance,
            &payment,
            owner.to_bytes(),
            buffer.to_bytes(),
            7,
            8,
            &plan.opening,
        )
        .unwrap()
    };
    let url = std::env::var("ZOLANA_PROVER_URL").expect("set ZOLANA_PROVER_URL");
    let proof = ProofCompressed::try_from(ProverClient::new(url).prove(&request).unwrap()).unwrap();
    let commitment = proof.commitment.expect("GKR must carry a commitment");
    let mut payload = Payload::GkrPayment {
        statement: payment,
        proof: wire::Proof {
            a: proof.a,
            b: proof.b,
            c: proof.c,
        },
        commitment: zolana_interface::verifying_keys::Bsb22Commitment {
            commitment: commitment.commitment,
            commitment_pok: commitment.commitment_pok,
        },
        inputs: capacity as u16,
    };
    if admitted {
        let Payload::GkrPayment {
            statement,
            proof,
            commitment,
            inputs,
        } = payload
        else {
            unreachable!()
        };
        payload = if dag {
            Payload::DagPayment {
                statement,
                proof,
                commitment,
                inputs,
            }
        } else {
            Payload::AdmittedPayment {
                statement,
                proof,
                commitment,
                inputs,
            }
        };
    }
    fixture.upload(nonce, payload.clone());
    let original = fixture.rpc.svm.get_account(&buffer).unwrap();
    let tree_before = fixture.rpc.svm.get_account(&fixture.tree).unwrap().data;
    let pending_key = pda::pending_nullifiers(&fixture.tree).0;
    let pending_before = fixture.rpc.svm.get_account(&pending_key).unwrap().data;
    let mut instruction =
        instructions::commit_spend(owner, buffer, fixture.tree, fixture.output_tree, &[]);
    {
        zolana_interface::instruction::builders::historical_nullifiers::use_nullifier_filter(
            &mut instruction,
            &fixture.tree,
        )
        .unwrap();
    }
    let original_tree = fixture.rpc.svm.get_account(&fixture.tree).unwrap();
    if admitted {
        let history = fixture.rpc.svm.get_account(&filter_key).unwrap();
        let mut changed = history.clone();
        zolana_tree::nullifier_filter::NullifierFilter::from_bytes(
            &mut changed.data,
            &fixture.tree.to_bytes(),
        )
        .unwrap()
        .record_batch(&[field(999)], 1, true)
        .unwrap();
        fixture.rpc.svm.set_account(filter_key, changed).unwrap();
        let error = fixture
            .rpc
            .create_and_send_transaction_with_budget(
                &[instruction.clone()],
                &owner,
                &[&fixture.owner],
                direct::COMPUTE_BUDGET,
            )
            .unwrap_err();
        zolana_program_test::Rejection::pool(
            zolana_interface::error::ShieldedPoolError::InvalidNullifierFilter,
        )
        .assert_litesvm(error);
        fixture
            .rpc
            .last_transaction_trace()
            .unwrap()
            .assert_rolled_back_except(&[owner]);
        fixture.rpc.svm.set_account(filter_key, history).unwrap();

        let mut retired = original_tree.clone();
        TreeAccount::from_bytes(&mut retired.data, fixture.tree.to_bytes())
            .unwrap()
            .retire_nullifier_filter()
            .unwrap();
        fixture.rpc.svm.set_account(fixture.tree, retired).unwrap();
        let without_filter =
            instructions::commit_spend(owner, buffer, fixture.tree, fixture.output_tree, &[]);
        let error = fixture
            .rpc
            .create_and_send_transaction_with_budget(
                &[without_filter],
                &owner,
                &[&fixture.owner],
                direct::COMPUTE_BUDGET,
            )
            .unwrap_err();
        zolana_program_test::Rejection::pool(
            zolana_interface::error::ShieldedPoolError::InvalidNullifierFilter,
        )
        .assert_litesvm(error);
        fixture
            .rpc
            .last_transaction_trace()
            .unwrap()
            .assert_rolled_back_except(&[owner]);
        fixture
            .rpc
            .svm
            .set_account(fixture.tree, original_tree.clone())
            .unwrap();
    }

    for evict_nullifier_root in [false, true] {
        if admitted && evict_nullifier_root {
            continue;
        }
        let mut account = original_tree.clone();
        let (Payload::GkrPayment { statement, .. }
        | Payload::AdmittedPayment { statement, .. }
        | Payload::DagPayment { statement, .. }) = &payload
        else {
            unreachable!()
        };
        let PaymentInputs::Notes {
            certificate,
            freshness,
        } = &statement.inputs
        else {
            unreachable!()
        };
        let mut tree = TreeAccount::from_bytes(&mut account.data, fixture.tree.to_bytes()).unwrap();
        if evict_nullifier_root {
            tree.nullifier_tree().root_history.roots[usize::from(freshness.index)] = field(99);
        } else {
            tree.utxo_tree().root_history[usize::from(certificate.state_root.index)] = field(99);
        }
        drop(tree);
        fixture.rpc.svm.set_account(fixture.tree, account).unwrap();
        let error = fixture
            .rpc
            .create_and_send_transaction_with_budget(
                &[instruction.clone()],
                &owner,
                &[&fixture.owner],
                direct::COMPUTE_BUDGET,
            )
            .unwrap_err();
        let rejection = if evict_nullifier_root {
            zolana_program_test::Rejection::pool(
                zolana_interface::error::ShieldedPoolError::InvalidTreeAccounts,
            )
        } else {
            zolana_program_test::Rejection::new(
                solana_instruction::error::InstructionError::InvalidArgument,
            )
        };
        rejection.assert_litesvm(error);
        fixture
            .rpc
            .last_transaction_trace()
            .unwrap()
            .assert_rolled_back_except(&[owner]);
    }
    fixture
        .rpc
        .svm
        .set_account(fixture.tree, original_tree)
        .unwrap();
    for mutation in [
        "commitment",
        "knowledge",
        "shape",
        "output",
        "nullifier",
        "selector",
    ] {
        if mutation == "selector" && !dag {
            continue;
        }
        let mut changed = payload.clone();
        let (Payload::GkrPayment {
            statement,
            commitment,
            inputs,
            ..
        }
        | Payload::AdmittedPayment {
            statement,
            commitment,
            inputs,
            ..
        }
        | Payload::DagPayment {
            statement,
            commitment,
            inputs,
            ..
        }) = &mut changed
        else {
            unreachable!()
        };
        match mutation {
            "commitment" => commitment.commitment = commitment.commitment_pok,
            "knowledge" => commitment.commitment_pok = commitment.commitment,
            "shape" => *inputs = if capacity == 144 { 512 } else { 144 },
            "output" => statement.outputs[0].utxo.utxo_hash = field(12),
            "nullifier" => {
                let PaymentInputs::Notes { certificate, .. } = &mut statement.inputs else {
                    unreachable!()
                };
                certificate.nullifiers[1] = certificate.nullifiers[0];
            }
            "selector" => {}
            _ => unreachable!(),
        }
        if mutation == "selector" {
            let Payload::DagPayment {
                statement,
                proof,
                commitment,
                inputs,
            } = changed
            else {
                unreachable!()
            };
            changed = Payload::AdmittedPayment {
                statement,
                proof,
                commitment,
                inputs,
            };
        }
        let encoded = borsh::to_vec(&changed).unwrap();
        let mut account = original.clone();
        let header_len = account.data.len() - encoded.len();
        account.data[header_len..].copy_from_slice(&encoded);
        fixture.rpc.svm.set_account(buffer, account).unwrap();
        assert!(
            fixture
                .rpc
                .create_and_send_transaction_with_budget(
                    &[instruction.clone()],
                    &owner,
                    &[&fixture.owner],
                    direct::COMPUTE_BUDGET,
                )
                .is_err(),
            "accepted altered {mutation}"
        );
        fixture
            .rpc
            .last_transaction_trace()
            .unwrap()
            .assert_rolled_back_except(&[owner]);
        assert_eq!(
            fixture.rpc.svm.get_account(&fixture.tree).unwrap().data,
            tree_before
        );
        assert_eq!(
            fixture.rpc.svm.get_account(&pending_key).unwrap().data,
            pending_before
        );
    }
    fixture
        .rpc
        .svm
        .set_account(buffer, original.clone())
        .unwrap();
    let history = fixture.rpc.svm.get_account(&filter_key).unwrap();
    let mut saturated = history.clone();
    let header_len = saturated.data.len() - zolana_tree::nullifier_filter::DEFAULT_BIT_BYTES;
    saturated.data[header_len..].fill(255);
    fixture.rpc.svm.set_account(filter_key, saturated).unwrap();
    if admitted {
        let error = fixture
            .rpc
            .create_and_send_transaction_with_budget(
                &[instruction.clone()],
                &owner,
                &[&fixture.owner],
                direct::COMPUTE_BUDGET,
            )
            .unwrap_err();
        zolana_program_test::Rejection::pool(
            zolana_interface::error::ShieldedPoolError::NullifierProofRequired,
        )
        .assert_litesvm(error);
        fixture
            .rpc
            .last_transaction_trace()
            .unwrap()
            .assert_rolled_back_except(&[owner]);
        fixture.rpc.svm.set_account(filter_key, history).unwrap();
    }
    let result = fixture
        .rpc
        .create_and_send_transaction_with_budget(
            &[instruction.clone()],
            &owner,
            &[&fixture.owner],
            direct::COMPUTE_BUDGET,
        )
        .unwrap();
    assert_eq!(
        result
            .events
            .iter()
            .map(|event| event.decoded.as_ref().unwrap().inputs.len())
            .sum::<usize>(),
        count
    );
    assert_eq!(
        result
            .events
            .iter()
            .map(|event| event.decoded.as_ref().unwrap().outputs.len())
            .sum::<usize>(),
        2
    );
    println!(
        "DIRECT_PAYMENT_CU admitted={admitted} dag={dag} count={count} cu={}",
        fixture
            .rpc
            .last_transaction_trace()
            .unwrap()
            .compute_units_consumed
    );
    let mut history = fixture.rpc.svm.get_account(&filter_key).unwrap();
    let filter = zolana_tree::nullifier_filter::NullifierFilter::from_bytes(
        &mut history.data,
        &fixture.tree.to_bytes(),
    )
    .unwrap();
    assert_eq!(filter.next_sequence(), count as u64 + 1);
    assert!(fixture
        .rpc
        .create_and_send_transaction_with_budget(
            &[instruction.clone()],
            &owner,
            &[&fixture.owner],
            direct::COMPUTE_BUDGET,
        )
        .is_err());
    fixture
        .rpc
        .svm
        .set_account(buffer, original.clone())
        .unwrap();
    let error = fixture
        .rpc
        .create_and_send_transaction_with_budget(
            &[instruction.clone()],
            &owner,
            &[&fixture.owner],
            direct::COMPUTE_BUDGET,
        )
        .unwrap_err();
    zolana_program_test::Rejection::pool(
        zolana_interface::error::ShieldedPoolError::NullifierAlreadySpent,
    )
    .assert_litesvm(error);
    fixture
        .rpc
        .last_transaction_trace()
        .unwrap()
        .assert_rolled_back_except(&[owner]);
    if admitted {
        let mut pending = fixture.rpc.svm.get_account(&pending_key).unwrap();
        pending.data.fill(0);
        PendingNullifiers::init_zeroed(&mut pending.data, &fixture.tree.to_bytes()).unwrap();
        fixture.rpc.svm.set_account(pending_key, pending).unwrap();
        let history = fixture.rpc.svm.get_account(&filter_key).unwrap();
        let error = fixture
            .rpc
            .create_and_send_transaction_with_budget(
                &[instruction],
                &owner,
                &[&fixture.owner],
                direct::COMPUTE_BUDGET,
            )
            .unwrap_err();
        zolana_program_test::Rejection::pool(
            zolana_interface::error::ShieldedPoolError::NullifierProofRequired,
        )
        .assert_litesvm(error);
        fixture
            .rpc
            .last_transaction_trace()
            .unwrap()
            .assert_rolled_back_except(&[owner]);
        assert_eq!(
            fixture.rpc.svm.get_account(&filter_key).unwrap().data,
            history.data
        );
    }
}
