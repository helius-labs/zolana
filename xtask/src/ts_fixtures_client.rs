use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    thread,
};

use ark_bn254::{G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use serde_json::{json, Value};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_hash::Hash;
use solana_message::Message;
use solana_pubkey::Pubkey;
use zolana_client::{
    assemble, prover::Proof, solana_rpc::transact_output_view_tags_from_instruction_groups,
    ClientError, ConfirmedInstructionGroups, IndexerPollConfig, MerkleContext, MerkleProof,
    NonInclusionProof, ProofCompressed, ProverClient, ProverInputs, SpendProof,
    SPP_SUPPORTED_SHAPES,
};
use zolana_event::{InstructionGroup, ParsedInstruction};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        builders::Transact,
        instruction_data::transact::{OwnerTag, TransactOutput, TransactProof},
        TransactSolWithdrawal, TransactSplWithdrawal, TransactWithdrawal,
    },
    pda, SPL_TOKEN_PROGRAM_ID,
};
use zolana_keypair::{
    NullifierKey, PublicKey, ShieldedKeypair, ShieldedKeypairTrait, SigningKey, ViewingKey,
};
use zolana_transaction::{
    derive_blinding,
    instructions::{
        transact::{
            encode_confidential_slots, ConfidentialTransfer, ExternalData, Shape, SppProofInputs,
            SppProofOutputUtxo, WithdrawalTarget,
        },
        types::SppProofInputUtxo,
    },
    AssetRegistry, Data, Utxo, SOL_MINT,
};

const P256_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
];
const ED25519_SECRET: [u8; 32] = [31; 32];
const VIEWING_SEED: [u8; 32] = [32; 32];
const BLINDING_SEED: [u8; 31] = [33; 31];
const WORKFLOW_SPL_ASSET_ID: u64 = 2;

fn main() {
    match vectors() {
        Ok(value) => println!(
            "{}",
            serde_json::to_string(&value).expect("serialize vectors")
        ),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn vectors() -> Result<Value, Box<dyn std::error::Error>> {
    Ok(json!({
        "prover": prover_vectors()?,
        "proof": proof_vectors()?,
        "rpc": rpc_vectors()?,
        "workflow_transfer": workflow_transfer_vectors()?,
        "workflow_withdraw_sol": workflow_withdraw_sol_vectors()?,
        "workflow_withdraw_spl": workflow_withdraw_spl_vectors()?
    }))
}

fn keypair(p256: bool) -> Result<ShieldedKeypair, Box<dyn std::error::Error>> {
    let signing = if p256 {
        SigningKey::from_bytes(&P256_SECRET)?
    } else {
        SigningKey::from_ed25519(&ED25519_SECRET)
    };
    Ok(ShieldedKeypair::from_keys(
        signing,
        ViewingKey::from_seed(&VIEWING_SEED, u32::from(p256))?,
    )?)
}

fn real_input(keypair: &ShieldedKeypair) -> SppProofInputUtxo {
    SppProofInputUtxo::new(
        Utxo {
            owner: keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount: 100,
            blinding: derive_blinding(&BLINDING_SEED, 0),
            zone_program_id: None,
            data: Data::default(),
        },
        keypair,
    )
}

fn dummy_input(position: u8) -> SppProofInputUtxo {
    SppProofInputUtxo {
        utxo: Utxo {
            owner: PublicKey::zeroed(),
            asset: SOL_MINT,
            amount: 0,
            blinding: derive_blinding(&BLINDING_SEED, position),
            zone_program_id: None,
            data: Data::default(),
        },
        nullifier_key: NullifierKey::from_secret([0; 31]),
        data_hash: None,
        zone_data_hash: None,
    }
}

fn output(
    keypair: &ShieldedKeypair,
    position: u8,
    dummy: bool,
) -> Result<SppProofOutputUtxo, Box<dyn std::error::Error>> {
    if dummy {
        return Ok(SppProofOutputUtxo {
            blinding: derive_blinding(&BLINDING_SEED, position),
            owner_tag: Some([position; 32]),
            ..Default::default()
        });
    }
    Ok(SppProofOutputUtxo {
        owner_address: Some(keypair.shielded_address()?),
        owner_tag: Some(keypair.signing_pubkey().confidential_view_tag()?),
        asset: SOL_MINT,
        amount: 100,
        blinding: derive_blinding(&BLINDING_SEED, position),
        ..Default::default()
    })
}

fn proof_inputs(
    p256: bool,
    n_inputs: usize,
    n_outputs: usize,
) -> Result<(SppProofInputs, Vec<SpendProof>), Box<dyn std::error::Error>> {
    let keypair = keypair(p256)?;
    let mut inputs = vec![real_input(&keypair)];
    for position in 1..n_inputs {
        inputs.push(dummy_input(position as u8));
    }
    let mut outputs = Vec::with_capacity(n_outputs);
    for position in 0..n_outputs {
        outputs.push(output(&keypair, position as u8 + 64, position != 0)?);
    }
    let resolved_tags = outputs
        .iter()
        .map(|output| output.owner_tag.expect("fixture owner tag"))
        .collect::<Vec<_>>();
    let wire_outputs = outputs
        .iter()
        .zip(&resolved_tags)
        .map(|(output, tag)| {
            Ok(TransactOutput {
                utxo_hash: output.hash()?,
                owner_tag: OwnerTag::Inline(*tag),
                data: Some(vec![1, 2, 3]),
            })
        })
        .collect::<Result<Vec<_>, zolana_transaction::TransactionError>>()?;
    let external = ExternalData::new([41; 33], [42; 16], wire_outputs, resolved_tags, vec![])
        .with_public_sol(-5, solana_address::Address::new_from_array([43; 32]))?;
    let mut inputs = SppProofInputs::new(
        inputs,
        outputs,
        external,
        solana_address::Address::new_from_array([44; 32]),
    );
    if p256 {
        inputs.sign_p256(&keypair)?;
    }
    let contexts = inputs.input_utxo_hashes()?;
    let tree = solana_address::Address::new_from_array([45; 32]);
    let proofs = contexts
        .iter()
        .enumerate()
        .map(|(index, context)| SpendProof {
            state: MerkleProof {
                leaf: context.utxo_hash,
                merkle_context: MerkleContext { tree_type: 1, tree },
                path: vec![field_byte(46 + index as u8); 32],
                leaf_index: index as u64,
                root: field_byte(47),
                root_seq: 48,
                root_index: 49 + index as u16,
            },
            nullifier: NonInclusionProof {
                leaf: context.nullifier,
                merkle_context: MerkleContext { tree_type: 2, tree },
                path: vec![field_byte(50 + index as u8); 40],
                low_element: field_byte(51),
                low_element_index: 0,
                high_element: field_byte(52),
                high_element_index: 1,
                root: field_byte(53),
                root_seq: 54,
                root_index: 55 + index as u16,
            },
        })
        .collect();
    Ok((inputs, proofs))
}

fn prover_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    let mut rails = Vec::new();
    for (rail, p256) in [("eddsa", false), ("p256", true)] {
        let mut shapes = Vec::new();
        for shape in SPP_SUPPORTED_SHAPES {
            let (inputs, proofs) = proof_inputs(p256, shape.n_inputs(), shape.n_outputs())?;
            let assembled = assemble(inputs.clone(), &proofs)?;
            let request = capture_prover_request(&assembled.prover_inputs)?;
            let before =
                assemble(inputs.clone(), &proofs)?.with_proof(TransactProof::zeroed_eddsa());
            let after_proof = deterministic_transact_proof(p256)?;
            let after = assemble(inputs, &proofs)?.with_proof(after_proof);
            shapes.push(json!({
                "shape": {"inputs": shape.n_inputs().to_string(), "outputs": shape.n_outputs().to_string()},
                "publicInputHashBytes": hex(&assembled.public_input_hash),
                "proverInputs": prover_inputs_json(&assembled.prover_inputs),
                "proverJson": request,
                "transactIxData": {
                    "beforeProofBytes": hex(&before.serialize()?),
                    "afterProofBytes": hex(&after.serialize()?)
                }
            }));
        }
        rails.push(json!({"rail": rail, "shapes": shapes}));
    }
    Ok(json!({
        "inputs": {
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "ed25519SecretBytes": hex(&ED25519_SECRET),
            "p256SecretBytes": hex(&P256_SECRET),
            "testOnlySecret": true,
            "viewingSeedBytes": hex(&VIEWING_SEED)
        },
        "expected": {"rails": rails}
    }))
}

fn capture_prover_request(inputs: &ProverInputs) -> Result<Value, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        let body = read_http_body(&mut stream).map_err(|error| error.to_string())?;
        sender.send(body).map_err(|error| error.to_string())?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .map_err(|error| error.to_string())?;
        Ok(())
    });
    let client = ProverClient::new(format!("http://{address}"));
    let _ = match inputs {
        ProverInputs::Eddsa(value) => client.prove_transfer(value),
        ProverInputs::P256(value) => client.prove_transfer_p256(value),
    };
    let request = serde_json::from_slice(&receiver.recv()?)?;
    server
        .join()
        .map_err(|_| "prover fixture server panicked")??;
    Ok(request)
}

fn read_http_body(stream: &mut impl Read) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    let header_end = loop {
        let read = stream.read(&mut buffer)?;
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec())?;
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then_some(value)
        })
        .ok_or("missing content-length")?
        .trim()
        .parse::<usize>()?;
    while bytes.len() < header_end + content_length {
        let read = stream.read(&mut buffer)?;
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(bytes[header_end..header_end + content_length].to_vec())
}

fn prover_inputs_json(inputs: &ProverInputs) -> Value {
    match inputs {
        ProverInputs::Eddsa(value) => json!({
            "rail": "eddsa",
            "inputs": value.inputs.iter().map(transfer_input_json).collect::<Vec<_>>(),
            "outputs": value.outputs.iter().map(transfer_output_json).collect::<Vec<_>>(),
            "externalDataHash": value.external_data_hash.to_string(),
            "privateTxHash": value.private_tx_hash.to_string(),
            "publicInputHash": value.public_input_hash.to_string(),
            "publicSolAmount": value.public_sol_amount.to_string(),
            "publicSplAmount": value.public_spl_amount.to_string(),
            "publicSplAssetPubkey": value.public_spl_asset_pubkey.to_string(),
            "zoneProgramId": value.zone_program_id.to_string(),
            "payerPubkeyHash": value.payer_pubkey_hash.to_string()
        }),
        ProverInputs::P256(value) => json!({
            "rail": "p256",
            "inputs": value.inputs.iter().map(transfer_input_json).collect::<Vec<_>>(),
            "outputs": value.outputs.iter().map(transfer_output_json).collect::<Vec<_>>(),
            "externalDataHash": value.external_data_hash.to_string(),
            "privateTxHash": value.private_tx_hash.to_string(),
            "publicInputHash": value.public_input_hash.to_string(),
            "p256PubX": value.p256_pub_x.to_string(),
            "p256PubY": value.p256_pub_y.to_string(),
            "p256SigR": value.p256_sig_r.to_string(),
            "p256SigS": value.p256_sig_s.to_string(),
            "p256MessageHashLow": value.p256_message_hash_low.to_string(),
            "p256MessageHashHigh": value.p256_message_hash_high.to_string(),
            "p256SigningPkField": value.p256_signing_pk_field.to_string(),
            "publicSolAmount": value.public_sol_amount.to_string(),
            "publicSplAmount": value.public_spl_amount.to_string(),
            "publicSplAssetPubkey": value.public_spl_asset_pubkey.to_string(),
            "zoneProgramId": value.zone_program_id.to_string(),
            "payerPubkeyHash": value.payer_pubkey_hash.to_string()
        }),
    }
}

fn transfer_input_json(input: &zolana_client::TransferInput) -> Value {
    json!({
        "isDummy": input.is_dummy.to_string(),
        "statePathElements": input.state_path_elements.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "statePathIndex": input.state_path_index.to_string(),
        "nullifierLowValue": input.nullifier_low_value.to_string(),
        "nullifierNextValue": input.nullifier_next_value.to_string(),
        "nullifierLowPathElements": input.nullifier_low_path_elements.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "nullifierLowPathIndex": input.nullifier_low_path_index.to_string(),
        "utxoTreeRoot": input.utxo_tree_root.to_string(),
        "nullifierTreeRoot": input.nullifier_tree_root.to_string(),
        "nullifier": input.nullifier.to_string(),
        "ownerPkHash": input.owner_pk_hash.to_string(),
        "nullifierSecret": input.nullifier_secret.to_string(),
        "utxo": proof_utxo_json(&input.utxo)
    })
}

fn transfer_output_json(output: &zolana_client::TransferOutput) -> Value {
    json!({
        "isDummy": output.is_dummy.to_string(),
        "hash": output.hash.to_string(),
        "ownerPkHash": output.owner_pk_hash.to_string(),
        "nullifierPk": output.nullifier_pk.to_string(),
        "utxo": proof_utxo_json(&output.utxo)
    })
}

fn proof_utxo_json(utxo: &zolana_transaction::ProofInputUtxo) -> Value {
    json!({
        "domainBytes":hex(&utxo.domain),
        "ownerHashBytes":hex(&utxo.owner_hash),
        "assetBytes":hex(&utxo.asset),
        "amountBytes":hex(&utxo.amount),
        "blindingBytes":hex(&utxo.blinding),
        "dataHashBytes":hex(&utxo.data_hash),
        "zoneDataHashBytes":hex(&utxo.zone_data_hash),
        "zoneProgramIdBytes":hex(&utxo.zone_program_id)
    })
}

fn gnark_proof(commitment: bool) -> Value {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let pair = |x: &ark_bn254::Fq, y: &ark_bn254::Fq| vec![field_hex(x), field_hex(y)];
    json!({
        "ar": pair(&g1.x, &g1.y),
        "bs": [
            pair(&g2.x.c0, &g2.x.c1),
            pair(&g2.y.c0, &g2.y.c1)
        ],
        "krs": pair(&g1.x, &g1.y),
        "proof_commitment": if commitment { pair(&g1.x, &g1.y) } else { Vec::<String>::new() },
        "proof_commitment_pok": if commitment { pair(&g1.x, &g1.y) } else { Vec::<String>::new() }
    })
}

fn field_hex(field: &ark_bn254::Fq) -> String {
    format!("0x{}", hex(&field.into_bigint().to_bytes_be()))
}

fn parsed_proof(commitment: bool) -> Result<Proof, Box<dyn std::error::Error>> {
    proof_response(json!({"proof": gnark_proof(commitment)}))
}

fn proof_response(response: Value) -> Result<Proof, Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(&response)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept proof request");
        let _ = read_http_body(&mut stream).expect("read proof request");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("write proof headers");
        stream.write_all(&body).expect("write proof response");
    });
    let client = ProverClient::new(format!("http://{address}"));
    let dummy = zolana_client::TransferInputs {
        inputs: vec![],
        outputs: vec![],
        external_data_hash: 0u8.into(),
        private_tx_hash: 0u8.into(),
        public_sol_amount: 0u8.into(),
        public_spl_amount: 0u8.into(),
        public_spl_asset_pubkey: 0u8.into(),
        zone_program_id: 0u8.into(),
        payer_pubkey_hash: 0u8.into(),
        public_input_hash: 0u8.into(),
    };
    let proof = client.prove_transfer(&dummy)?;
    server.join().map_err(|_| "proof fixture server panicked")?;
    Ok(proof)
}

fn proof_response_error(response: Value) -> Result<ClientError, Box<dyn std::error::Error>> {
    match proof_response(response) {
        Ok(_) => Err("invalid proof response was accepted".into()),
        Err(error) => error
            .downcast::<ClientError>()
            .map(|error| *error)
            .map_err(|error| error),
    }
}

fn deterministic_transact_proof(p256: bool) -> Result<TransactProof, Box<dyn std::error::Error>> {
    let proof = ProofCompressed::try_from(parsed_proof(p256)?)?;
    Ok(proof.to_transact_proof())
}

fn proof_json(proof: &Proof) -> Value {
    json!({
        "aBytes": hex(&proof.a),
        "bBytes": hex(&proof.b),
        "cBytes": hex(&proof.c),
        "commitment": proof.commitment.map(|value| json!({
            "commitmentBytes": hex(&value.commitment),
            "commitmentPokBytes": hex(&value.commitment_pok)
        }))
    })
}

fn compressed_json(proof: &ProofCompressed) -> Value {
    json!({
        "aBytes": hex(&proof.a),
        "bBytes": hex(&proof.b),
        "cBytes": hex(&proof.c),
        "commitment": proof.commitment.map(|value| json!({
            "commitmentBytes": hex(&value.commitment),
            "commitmentPokBytes": hex(&value.commitment_pok)
        }))
    })
}

fn proof_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    let vanilla = parsed_proof(false)?;
    let bsb22 = parsed_proof(true)?;
    let vanilla_compressed = ProofCompressed::try_from(vanilla)?;
    let bsb22_compressed = ProofCompressed::try_from(bsb22)?;
    let off_curve = ProofCompressed::try_from(Proof {
        a: [0xff; 64],
        b: bsb22.b,
        c: bsb22.c,
        commitment: bsb22.commitment,
    })
    .expect_err("off-curve A");
    let wrong_rail = vanilla_compressed
        .to_p256_proof()
        .expect_err("vanilla proof on P256 rail");
    let malformed = json!({"proof":{"ar":["0x1"],"bs":[],"krs":[]}});
    let partial = json!({"proof":{
        "ar":gnark_proof(false)["ar"],
        "bs":gnark_proof(false)["bs"],
        "krs":gnark_proof(false)["krs"],
        "proof_commitment":gnark_proof(true)["proof_commitment"]
    }});
    let malformed_error = proof_response_error(malformed.clone())?;
    let partial_error = proof_response_error(partial.clone())?;
    Ok(json!({
        "inputs": {
            "curveGenerators": "ark_bn254::{G1Affine,G2Affine}::generator",
            "malformedResponse": malformed,
            "partialCommitmentResponse": partial
        },
        "expected": {
            "vanilla": {"uncompressed": proof_json(&vanilla), "compressed": compressed_json(&vanilla_compressed), "rail":"eddsa"},
            "bsb22": {"uncompressed": proof_json(&bsb22), "compressed": compressed_json(&bsb22_compressed), "rail":"p256"},
            "errors": {
                "offCurve": error(&off_curve),
                "wrongRail": error(&wrong_rail),
                "malformed": error(&malformed_error),
                "partialCommitment": error(&partial_error)
            }
        }
    }))
}

fn rpc_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    let (inputs, proofs) = proof_inputs(false, 1, 2)?;
    let transact = assemble(inputs, &proofs)?.with_proof(deterministic_transact_proof(false)?);
    let payer = Pubkey::new_from_array([51; 32]);
    let tree = Pubkey::new_from_array([52; 32]);
    let blockhash = Hash::new_from_array([53; 32]);
    let transact_ix = Transact {
        payer,
        tree,
        withdrawal: None,
        data: transact.clone(),
    }
    .instruction();
    let base = vec![
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        transact_ix.clone(),
    ];
    let priced = vec![
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        ComputeBudgetInstruction::set_compute_unit_price(7),
        transact_ix.clone(),
    ];
    let message_bytes = |instructions: &[solana_instruction::Instruction]| {
        let mut message = Message::new(instructions, Some(&payer));
        message.recent_blockhash = blockhash;
        bincode::serialize(&message).expect("serialize legacy message")
    };
    let parsed = ParsedInstruction {
        program_id: transact_ix.program_id,
        accounts: transact_ix
            .accounts
            .iter()
            .map(|account| account.pubkey)
            .collect(),
        data: transact_ix.data.clone(),
        stack_height: Some(1),
    };
    let unrelated = ParsedInstruction {
        program_id: Pubkey::new_from_array([54; 32]),
        accounts: vec![],
        data: vec![0],
        stack_height: Some(1),
    };
    let direct = transact_output_view_tags_from_instruction_groups(&ConfirmedInstructionGroups {
        groups: vec![InstructionGroup {
            outer: parsed.clone(),
            inner: vec![],
        }],
    })?;
    let inner = transact_output_view_tags_from_instruction_groups(&ConfirmedInstructionGroups {
        groups: vec![InstructionGroup {
            outer: unrelated,
            inner: vec![parsed],
        }],
    })?;
    let no_transact =
        transact_output_view_tags_from_instruction_groups(&ConfirmedInstructionGroups {
            groups: vec![],
        })
        .expect_err("missing transact");
    let wrong_signature = ClientError::IndexerTimeout;
    let lag = ClientError::IndexerNotCaughtUp {
        target: 100,
        latest: 99,
        attempts: 5,
    };
    let retry = IndexerPollConfig::new(4, 5, 12);
    let delays = retry
        .backoff()
        .map(|delay| delay.as_millis().to_string())
        .collect::<Vec<_>>();
    let merkle = &proofs[0].state;
    let nullifier = &proofs[0].nullifier;
    Ok(json!({
        "inputs": {
            "blockhashBytes": hex(blockhash.as_ref()),
            "computeUnitLimit": "1400000",
            "computeUnitPriceMicroLamports": "7",
            "feePayer": payer.to_string(),
            "tree": tree.to_string()
        },
        "expected": {
            "legacyMessages": {
                "limitOnlyBytes": hex(&message_bytes(&base)),
                "limitAndPriceBytes": hex(&message_bytes(&priced))
            },
            "confirmation": {
                "directTags": direct.iter().map(|tag| hex(tag)).collect::<Vec<_>>(),
                "innerTags": inner.iter().map(|tag| hex(tag)).collect::<Vec<_>>(),
                "missingTransactError": error(&no_transact),
                "wrongSignatureError": error(&wrong_signature)
            },
            "indexer": {
                "merkle": merkle_json(merkle),
                "nonInclusion": non_inclusion_json(nullifier),
                "orderedLeaves": [hex(&merkle.leaf), hex(&nullifier.leaf)],
                "reorderedLeaves": [hex(&nullifier.leaf), hex(&merkle.leaf)]
            },
            "retry": {
                "delaysMs": delays,
                "attempts": retry.num_retries.saturating_add(1).to_string(),
                "lagError": error(&lag)
            },
            "sourceLimitations": [{
                "symbol":"indexer::{convert_merkle_proof,convert_non_inclusion_proof}; wait_for_indexed_transaction_async; build_unsigned_solana_transaction",
                "reason":"These functions are private. The oracle invokes the same frozen public response types, Transact builder, Solana Message serializer, tag resolver, error variants, and retry schedule. Wall-clock and HTTP transport timing are represented as deterministic envelopes and outcomes."
            }]
        }
    }))
}

#[derive(Clone, Copy)]
enum WorkflowKind {
    Transfer,
    WithdrawSol,
    WithdrawSpl,
}

#[derive(Clone, Copy)]
enum WorkflowRail {
    Eddsa,
    P256,
    Mixed,
}

fn workflow_transfer_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    Ok(json!({
        "inputs": {
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "ed25519SecretBytes": hex(&ED25519_SECRET),
            "p256SecretBytes": hex(&P256_SECRET),
            "testOnlySecret": true,
            "viewingSeedBytes": hex(&VIEWING_SEED)
        },
        "expected": {
            "railCases": [
                workflow_case(WorkflowKind::Transfer, WorkflowRail::Eddsa)?,
                workflow_case(WorkflowKind::Transfer, WorkflowRail::P256)?,
                workflow_case(WorkflowKind::Transfer, WorkflowRail::Mixed)?
            ]
        }
    }))
}

fn workflow_withdraw_sol_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    Ok(json!({
        "inputs": {
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "ed25519SecretBytes": hex(&ED25519_SECRET),
            "testOnlySecret": true,
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "withdrawAmount": "30"
        },
        "expected": workflow_case(WorkflowKind::WithdrawSol, WorkflowRail::Eddsa)?
    }))
}

fn workflow_withdraw_spl_vectors() -> Result<Value, Box<dyn std::error::Error>> {
    Ok(json!({
        "inputs": {
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "p256SecretBytes": hex(&P256_SECRET),
            "testOnlySecret": true,
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "withdrawAmount": "30"
        },
        "expected": workflow_case(WorkflowKind::WithdrawSpl, WorkflowRail::Mixed)?
    }))
}

fn workflow_case(
    kind: WorkflowKind,
    rail: WorkflowRail,
) -> Result<Value, Box<dyn std::error::Error>> {
    let p256 = !matches!(rail, WorkflowRail::Eddsa);
    let sender = keypair(p256)?;
    let payer = if p256 {
        Address::new_from_array([44; 32])
    } else {
        Address::new_from_array(sender.signing_pubkey().confidential_view_tag()?)
    };
    let spl_mint = Address::new_from_array([74; 32]);
    let assets = AssetRegistry::new([(WORKFLOW_SPL_ASSET_ID, spl_mint)])?;
    let recipient = ShieldedKeypair::from_keys(
        SigningKey::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 9,
        ])?,
        ViewingKey::from_seed(&[75; 32], 9)?,
    )?;
    let inputs = workflow_inputs(&sender, rail, spl_mint);
    let mut transfer = ConfidentialTransfer::new(sender.shielded_address()?, inputs, payer);
    transfer.blinding_seed = BLINDING_SEED;
    match kind {
        WorkflowKind::Transfer => {
            transfer = transfer.with_shape(Shape::IN2_OUT3);
            transfer.send(&recipient.shielded_address()?, spl_mint, 60)?;
        }
        WorkflowKind::WithdrawSol => {
            transfer = transfer.with_shape(Shape::IN2_OUT2);
            transfer.withdraw(
                SOL_MINT,
                30,
                WithdrawalTarget::Sol {
                    user_sol_account: Address::new_from_array([80; 32]),
                },
            )?;
        }
        WorkflowKind::WithdrawSpl => {
            transfer = transfer.with_shape(Shape::IN2_OUT2);
            let spl_vault = pda::spl_asset_vault(&Pubkey::new_from_array(spl_mint.to_bytes()));
            transfer.withdraw(
                spl_mint,
                30,
                WithdrawalTarget::Spl {
                    user_spl_token: Address::new_from_array([81; 32]),
                    spl_token_interface: Address::new_from_array(spl_vault.to_bytes()),
                },
            )?;
        }
    }
    let prepared = transfer.prepare()?;
    let tx_viewing_key = ViewingKey::from_seed(&[78; 32], 10)?;
    let salt = [79; 16];
    let slots = encode_confidential_slots(&prepared.outputs, &assets, &tx_viewing_key, salt)?;
    let mut signed = prepared.finalize(tx_viewing_key.pubkey(), salt, slots)?;
    if p256 {
        signed.sign_p256(&sender)?;
    }
    let input_contexts = signed.input_utxo_hashes()?;
    let proofs = workflow_spend_proofs(&input_contexts);
    let incomplete_proofs = &proofs[..proofs.len() - 1];
    let incomplete_proof_error = match assemble(signed.clone(), incomplete_proofs) {
        Ok(_) => panic!("incomplete proofs were accepted"),
        Err(error) => error,
    };
    let assembled = assemble(signed.clone(), &proofs)?;
    let (prover_request, prover_result, compressed) =
        capture_prover_exchange(&assembled.prover_inputs)?;
    let prover_inputs = prover_inputs_json(&assembled.prover_inputs);
    let transact_data = assembled.with_proof(compressed.to_transact_proof());
    let withdrawal = workflow_withdrawal(kind, spl_mint);
    let tree = Pubkey::new_from_array([45; 32]);
    let payer_pubkey = Pubkey::new_from_array(payer.to_bytes());
    let instruction = Transact {
        payer: payer_pubkey,
        tree,
        withdrawal,
        data: transact_data.clone(),
    }
    .instruction();
    let blockhash = Hash::new_from_array([83; 32]);
    let instructions = [
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        instruction.clone(),
    ];
    let mut message = Message::new(&instructions, Some(&payer_pubkey));
    message.recent_blockhash = blockhash;
    let confirmation = workflow_confirmation(&instruction, matches!(rail, WorkflowRail::Eddsa))?;
    let malformed_proof = proof_response_error(json!({"proof":{"ar":["0x1"],"bs":[],"krs":[]}}))?;

    Ok(json!({
        "rail": match rail {
            WorkflowRail::Eddsa => "eddsa",
            WorkflowRail::P256 => "p256",
            WorkflowRail::Mixed => "mixed-p256"
        },
        "logicalInputs": {
            "assetRegistry": [{
                "assetId": WORKFLOW_SPL_ASSET_ID.to_string(),
                "mint": spl_mint.to_string()
            }],
            "payer": payer_pubkey.to_string(),
            "recipient": {
                "nullifierPublicKeyBytes": hex(&recipient.shielded_address()?.nullifier_pubkey),
                "signingPublicKeyBytes": hex(recipient.signing_pubkey().as_bytes()),
                "viewingPublicKeyBytes": hex(recipient.shielded_address()?.viewing_pubkey.as_bytes())
            },
            "splMint": spl_mint.to_string(),
            "tree": tree.to_string(),
            "publicSettlement": {
                "publicSolAmount": signed.external_data.public_sol_amount.map(|amount| amount.to_string()),
                "publicSplAmount": signed.external_data.public_spl_amount.map(|amount| amount.to_string()),
                "splTokenInterface": signed.external_data.spl_token_interface.to_string(),
                "userSolAccount": signed.external_data.user_sol_account.to_string(),
                "userSplTokenAccount": signed.external_data.user_spl_token.to_string()
            }
        },
        "proof": {
            "compressed": compressed_json(&compressed),
            "proverInputs": prover_inputs,
            "proverRequest": prover_request,
            "proverResult": proof_json(&prover_result),
            "spendProofs": proofs.iter().map(spend_proof_json).collect::<Vec<_>>()
        },
        "wire": {
            "instruction": instruction_json(&instruction),
            "transactDataBytes": hex(&transact_data.serialize()?),
            "unsignedMessageBytes": hex(&bincode::serialize(&message)?)
        },
        "stateTransition": {
            "externalRecipientBalanceDeltas": {
                "sol": signed.external_data.public_sol_amount.map(|amount| -amount).unwrap_or_default().to_string(),
                "spl": signed.external_data.public_spl_amount.map(|amount| -amount).unwrap_or_default().to_string()
            },
            "inputNullifierBytes": input_contexts.iter().map(|input| hex(&input.nullifier)).collect::<Vec<_>>(),
            "outputs": signed.output_utxos.iter().zip(&signed.external_data.resolved_owner_tags).map(|(output, owner_tag)| {
                Ok(json!({
                    "amount": output.amount.to_string(),
                    "asset": output.asset.to_string(),
                    "ownerTagBytes": hex(owner_tag),
                    "utxoHashBytes": hex(&output.hash()?)
                }))
            }).collect::<Result<Vec<_>, zolana_transaction::TransactionError>>()?,
            "replayError": shielded_pool_error_json(ShieldedPoolError::NullifierTreeUpdateFailed),
            "spentInputHashesBytes": input_contexts.iter().map(|input| hex(&input.utxo_hash)).collect::<Vec<_>>()
        },
        "confirmation": confirmation,
        "errors": {
            "accountOrder": shielded_pool_error_json(ShieldedPoolError::InvalidSettlementAccounts),
            "incompleteProofSet": error(&incomplete_proof_error),
            "malformedProof": error(&malformed_proof),
            "wrongSignatureConfirmation": error(&ClientError::IndexerTimeout)
        }
    }))
}

fn workflow_inputs(
    sender: &ShieldedKeypair,
    rail: WorkflowRail,
    spl_mint: Address,
) -> Vec<SppProofInputUtxo> {
    let p256_input = |asset: Address, amount: u64, position: u8| {
        SppProofInputUtxo::new(
            Utxo {
                owner: sender.signing_pubkey(),
                asset,
                amount,
                blinding: derive_blinding(&BLINDING_SEED, position),
                zone_program_id: None,
                data: Data::default(),
            },
            sender,
        )
    };
    let eddsa_input = |asset: Address, amount: u64, position: u8| {
        let (owner, nullifier_key) = if matches!(rail, WorkflowRail::Eddsa) {
            (sender.signing_pubkey(), sender.nullifier_key())
        } else {
            (
                PublicKey::from_ed25519(&[76; 32]),
                NullifierKey::from_secret([77; 31]),
            )
        };
        SppProofInputUtxo::new(
            Utxo {
                owner,
                asset,
                amount,
                blinding: derive_blinding(&BLINDING_SEED, position),
                zone_program_id: None,
                data: Data::default(),
            },
            nullifier_key,
        )
    };
    match rail {
        WorkflowRail::Eddsa => vec![
            eddsa_input(SOL_MINT, 100, 10),
            eddsa_input(spl_mint, 100, 11),
        ],
        WorkflowRail::P256 => vec![p256_input(SOL_MINT, 100, 10), p256_input(spl_mint, 100, 11)],
        WorkflowRail::Mixed => vec![
            p256_input(SOL_MINT, 100, 10),
            eddsa_input(spl_mint, 100, 11),
        ],
    }
}

fn workflow_spend_proofs(
    contexts: &[zolana_transaction::instructions::types::InputUtxoContext],
) -> Vec<SpendProof> {
    let tree = Address::new_from_array([45; 32]);
    contexts
        .iter()
        .enumerate()
        .map(|(index, context)| SpendProof {
            state: MerkleProof {
                leaf: context.utxo_hash,
                merkle_context: MerkleContext { tree_type: 1, tree },
                path: vec![field_byte(84 + index as u8); 32],
                leaf_index: index as u64,
                root: field_byte(86),
                root_seq: 87,
                root_index: 88 + index as u16,
            },
            nullifier: NonInclusionProof {
                leaf: context.nullifier,
                merkle_context: MerkleContext { tree_type: 2, tree },
                path: vec![field_byte(89 + index as u8); 40],
                low_element: field_byte(91),
                low_element_index: 0,
                high_element: field_byte(92),
                high_element_index: 1,
                root: field_byte(93),
                root_seq: 94,
                root_index: 95 + index as u16,
            },
        })
        .collect()
}

fn workflow_withdrawal(kind: WorkflowKind, spl_mint: Address) -> Option<TransactWithdrawal> {
    match kind {
        WorkflowKind::Transfer => None,
        WorkflowKind::WithdrawSol => Some(TransactWithdrawal::Sol(TransactSolWithdrawal {
            recipient: Pubkey::new_from_array([80; 32]),
        })),
        WorkflowKind::WithdrawSpl => Some(TransactWithdrawal::Spl(TransactSplWithdrawal {
            cpi_authority: Some(pda::shielded_pool_cpi_authority()),
            spl_token_interface: pda::spl_asset_vault(&Pubkey::new_from_array(spl_mint.to_bytes())),
            recipient: Pubkey::new_from_array([84; 32]),
            user_token_account: Pubkey::new_from_array([81; 32]),
            token_program: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
        })),
    }
}

fn capture_prover_exchange(
    inputs: &ProverInputs,
) -> Result<(Value, Proof, ProofCompressed), Box<dyn std::error::Error>> {
    let response = serde_json::to_vec(&json!({
        "proof": gnark_proof(matches!(inputs, ProverInputs::P256(_)))
    }))?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = thread::spawn(move || -> Result<Vec<u8>, String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        let request = read_http_body(&mut stream).map_err(|error| error.to_string())?;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        )
        .map_err(|error| error.to_string())?;
        stream
            .write_all(&response)
            .map_err(|error| error.to_string())?;
        Ok(request)
    });
    let client = ProverClient::new(format!("http://{address}"));
    let proof = match inputs {
        ProverInputs::Eddsa(value) => client.prove_transfer(value)?,
        ProverInputs::P256(value) => client.prove_transfer_p256(value)?,
    };
    let request = serde_json::from_slice(
        &server
            .join()
            .map_err(|_| "prover fixture server panicked")??,
    )?;
    let compressed = ProofCompressed::try_from(proof)?;
    Ok((request, proof, compressed))
}

fn workflow_confirmation(
    instruction: &solana_instruction::Instruction,
    account_tag: bool,
) -> Result<Value, Box<dyn std::error::Error>> {
    let parsed = ParsedInstruction {
        program_id: instruction.program_id,
        accounts: instruction
            .accounts
            .iter()
            .map(|account| account.pubkey)
            .collect(),
        data: instruction.data.clone(),
        stack_height: Some(1),
    };
    let direct = transact_output_view_tags_from_instruction_groups(&ConfirmedInstructionGroups {
        groups: vec![InstructionGroup {
            outer: parsed.clone(),
            inner: vec![],
        }],
    })?;
    let inner = transact_output_view_tags_from_instruction_groups(&ConfirmedInstructionGroups {
        groups: vec![InstructionGroup {
            outer: ParsedInstruction {
                program_id: Pubkey::new_from_array([85; 32]),
                accounts: vec![],
                data: vec![0],
                stack_height: Some(1),
            },
            inner: vec![parsed.clone()],
        }],
    })?;
    let tag_error = account_tag.then(|| {
        let mut invalid = parsed;
        invalid.accounts.clear();
        transact_output_view_tags_from_instruction_groups(&ConfirmedInstructionGroups {
            groups: vec![InstructionGroup {
                outer: invalid,
                inner: vec![],
            }],
        })
        .expect_err("missing owner-tag account")
    });
    Ok(json!({
        "directOutputTagsBytes": direct.iter().map(|tag| hex(tag)).collect::<Vec<_>>(),
        "innerOutputTagsBytes": inner.iter().map(|tag| hex(tag)).collect::<Vec<_>>(),
        "ownerTagError": tag_error.as_ref().map(error)
    }))
}

fn instruction_json(instruction: &solana_instruction::Instruction) -> Value {
    json!({
        "accounts": instruction.accounts.iter().map(|account| json!({
            "address": account.pubkey.to_string(),
            "signer": account.is_signer,
            "writable": account.is_writable
        })).collect::<Vec<_>>(),
        "dataBytes": hex(&instruction.data),
        "programId": instruction.program_id.to_string()
    })
}

fn spend_proof_json(proof: &SpendProof) -> Value {
    json!({
        "state": merkle_json(&proof.state),
        "nullifier": non_inclusion_json(&proof.nullifier)
    })
}

fn shielded_pool_error_json(error: ShieldedPoolError) -> Value {
    json!({
        "code": format!("{error:?}"),
        "customCode": (error as u32).to_string(),
        "details": error.to_string()
    })
}

fn merkle_json(proof: &MerkleProof) -> Value {
    json!({
        "leafBytes":hex(&proof.leaf),
        "pathBytes":proof.path.iter().map(|value|hex(value)).collect::<Vec<_>>(),
        "leafIndex":proof.leaf_index.to_string(),
        "rootBytes":hex(&proof.root),
        "rootSeq":proof.root_seq.to_string(),
        "rootIndex":proof.root_index.to_string(),
        "tree":proof.merkle_context.tree.to_string()
    })
}

fn non_inclusion_json(proof: &NonInclusionProof) -> Value {
    json!({
        "leafBytes":hex(&proof.leaf),
        "pathBytes":proof.path.iter().map(|value|hex(value)).collect::<Vec<_>>(),
        "lowElementBytes":hex(&proof.low_element),
        "lowElementIndex":proof.low_element_index.to_string(),
        "highElementBytes":hex(&proof.high_element),
        "highElementIndex":proof.high_element_index.to_string(),
        "rootBytes":hex(&proof.root),
        "rootSeq":proof.root_seq.to_string(),
        "rootIndex":proof.root_index.to_string(),
        "tree":proof.merkle_context.tree.to_string()
    })
}

fn error(error: &impl std::fmt::Debug) -> Value {
    let details = format!("{error:?}");
    let code = details.split(['(', ' ', '{']).next().unwrap_or("Unknown");
    json!({"code":code,"details":details})
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn field_byte(value: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    bytes
}
