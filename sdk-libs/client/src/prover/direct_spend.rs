use super::{Delivery, ProofCompressed, ProveRequest};
use crate::{
    error::ClientError,
    rpc::{MerkleProof, NonInclusionProof},
};
use serde::Serialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;
use zolana_hasher::{
    hash_chain::create_hash_chain_4_from_slice as chain, primitives::solana_owner_identity, Hasher,
    Poseidon,
};
use zolana_interface::direct_spend::{
    self as wire, certificate_id, field, Certificate, Payment, PaymentInputs, Root,
    CERTIFICATE_INPUTS, MAX_CERTIFICATES, MAX_INPUTS,
};
use zolana_keypair::NullifierKey;
use zolana_transaction::ProofInputUtxo;

type Field = [u8; 32];

pub const COMPUTE_BUDGET: crate::rpc::ComputeBudgetConfig =
    crate::rpc::ComputeBudgetConfig::new(1_400_000).with_heap_size(256 * 1024);

pub struct Request {
    kind: &'static str,
    inputs: usize,
    outputs: usize,
    witness: Value,
}

impl Request {
    pub fn with_gkr(mut self) -> Result<Self, ClientError> {
        if self.kind != "direct-payment" || !wire::GKR_PAYMENT_INPUTS.contains(&self.inputs) {
            return Err(invalid("GKR requires a supported direct payment"));
        }
        self.kind = "direct-payment-gkr";
        Ok(self)
    }
}

impl ProveRequest for Request {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        let _phase = crate::timing::Phase::start("direct_request_serialization", 0);
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            circuit_type: &'static str,
            n_inputs: usize,
            n_outputs: usize,
            witness: &'a Value,
        }
        serde_json::to_string(&Body {
            circuit_type: self.kind,
            n_inputs: self.inputs,
            n_outputs: self.outputs,
            witness: &self.witness,
        })
        .map(Zeroizing::new)
        .map_err(|error| invalid(&error.to_string()))
    }
    fn delivery(&self) -> Delivery {
        Delivery::InResponse
    }
}

pub struct Opening {
    pub id: Field,
    pub commitment: Field,
    pub asset: Field,
    pub amount: u128,
    pub randomness: Field,
}

pub struct CertificatePlan {
    pub statement: Certificate,
    pub opening: Opening,
    pub request: Request,
}

pub struct Input {
    note: ProofInputUtxo,
    proof: MerkleProof,
}

pub struct InputNote {
    note: ProofInputUtxo,
    commitment: Field,
}

impl InputNote {
    pub fn new(note: ProofInputUtxo) -> Result<Self, ClientError> {
        let commitment = note.hash()?;
        Ok(Self { note, commitment })
    }

    pub fn commitment(&self) -> Field {
        self.commitment
    }

    pub fn with_proof(self, proof: MerkleProof) -> Result<Input, ClientError> {
        if proof.leaf != self.commitment {
            return Err(invalid("membership proof leaf does not match its note"));
        }
        Ok(Input {
            note: self.note,
            proof,
        })
    }
}

impl Input {
    pub fn new(note: ProofInputUtxo, proof: MerkleProof) -> Result<Self, ClientError> {
        InputNote::new(note)?.with_proof(proof)
    }
}

pub struct Output {
    pub note: ProofInputUtxo,
    pub nullifier_pk: Field,
}

pub fn certificate(
    owner: Field,
    buffer: Field,
    tree: Field,
    tree_id: u16,
    key: &NullifierKey,
    inputs: &[Input],
    randomness: Field,
    capacity: usize,
) -> Result<CertificatePlan, ClientError> {
    let _phase = crate::timing::Phase::start("direct_certificate_witness", 0);
    if inputs.is_empty()
        || inputs.len() > capacity
        || ![CERTIFICATE_INPUTS, wire::INLINE_INPUTS, 144, MAX_INPUTS].contains(&capacity)
    {
        return Err(invalid("invalid certificate shape"));
    }
    let id = certificate_id(&buffer)?;
    let asset = inputs[0].note.asset;
    let root = Root {
        value: inputs[0].proof.root,
        index: inputs[0].proof.root_index,
    };
    let owner_key = solana_owner_identity(&owner)?;
    let nullifier_pk = key.pubkey()?;
    let expected_owner = Poseidon::hashv(&[&owner_key, &nullifier_pk])?;
    let mut total = 0u128;
    let mut notes = Vec::with_capacity(capacity);
    let mut nullifiers = Vec::with_capacity(capacity);
    for input in inputs {
        let note = &input.note;
        if note.asset != asset
            || note.tree_id != field(tree_id.into())
            || note.owner_hash != expected_owner
            || note.domain != field(3)
            || note.data_hash != [0; 32]
            || note.ring_data_hash != [0; 32]
            || note.ring_program_id != [0; 32]
            || input.proof.root != root.value
            || input.proof.root_index != root.index
            || input.proof.path.len() != 32
            || note.amount[..24] != [0; 24]
        {
            return Err(invalid(
                "certificate inputs must share one plain owner, asset, tree and root",
            ));
        }
        let amount = u64::from_be_bytes(note.amount[24..].try_into().unwrap());
        total += u128::from(amount);
        nullifiers.push(key.nullifier(&input.proof.leaf, &note.blinding)?);
        notes.push(json!({ "Amount": hex(&note.amount), "Blinding": hex(&note.blinding), "Index": hex(&field(input.proof.leaf_index)), "Path": fields(&input.proof.path) }));
    }
    let commitment = Poseidon::hashv(&[
        &field(0x44535631),
        &id,
        &asset,
        &amount_field(total),
        &randomness,
    ])?;
    let statement = Certificate {
        tree,
        state_root: root,
        nullifiers: nullifiers.clone(),
        value_commitment: commitment,
    };
    let public_hash = chain(&statement.fields(id, &owner, tree_id, capacity)?)?;
    nullifiers.resize(capacity, [0; 32]);
    notes.resize(capacity, json!({ "Amount": hex(&field(0)), "Blinding": hex(&field(0)), "Index": hex(&field(0)), "Path": fields(&[[0; 32]; 32]) }));
    let request = Request {
        kind: "input-certificate",
        inputs: capacity,
        outputs: 0,
        witness: json!({
            "ID": hex(&id), "TreeID": hex(&field(tree_id.into())), "StateRoot": hex(&root.value), "Owner": hex(&owner_key), "Count": hex(&field(inputs.len() as u64)),
            "Nullifiers": fields(&nullifiers), "ValueCommitment": hex(&commitment), "Asset": hex(&asset), "ValueRandomness": hex(&randomness),
            "NullifierSecret": hex(&super::field::right_align(&*key.secret())), "Notes": notes, "PublicInputHash": hex(&public_hash)
        }),
    };
    Ok(CertificatePlan {
        statement,
        opening: Opening {
            id,
            commitment,
            asset,
            amount: total,
            randomness,
        },
        request,
    })
}

pub fn freshness(
    statement: &Certificate,
    tree_id: u16,
    proofs: &[NonInclusionProof],
    capacity: usize,
) -> Result<(Root, Request), ClientError> {
    if !statement.validate(capacity)
        || ![CERTIFICATE_INPUTS, wire::INLINE_INPUTS, 144, MAX_INPUTS].contains(&capacity)
        || proofs.len() != statement.nullifiers.len()
    {
        return Err(invalid("invalid freshness shape"));
    }
    let root = Root {
        value: proofs[0].root,
        index: proofs[0].root_index,
    };
    let mut witnesses = Vec::with_capacity(capacity);
    for (proof, nullifier) in proofs.iter().zip(&statement.nullifiers) {
        if proof.leaf != *nullifier
            || proof.root != root.value
            || proof.root_index != root.index
            || proof.path.len() != 40
        {
            return Err(invalid(
                "freshness witnesses must match the certificate and root",
            ));
        }
        witnesses.push(json!({ "Low": hex(&proof.low_element), "Next": hex(&proof.high_element), "Index": hex(&field(proof.low_element_index)), "Path": fields(&proof.path) }));
    }
    witnesses.resize(capacity, json!({ "Low": hex(&field(0)), "Next": hex(&field(0)), "Index": hex(&field(0)), "Path": fields(&[[0; 32]; 40]) }));
    let mut nullifiers = statement.nullifiers.clone();
    nullifiers.resize(capacity, [0; 32]);
    let public_hash = chain(&statement.freshness_fields(root, tree_id, capacity)?)?;
    Ok((
        root,
        Request {
            kind: "nullifier-freshness",
            inputs: capacity,
            outputs: 0,
            witness: json!({
                "TreeID": hex(&field(tree_id.into())), "Root": hex(&root.value), "Count": hex(&field(proofs.len() as u64)), "Nullifiers": fields(&nullifiers), "Witnesses": witnesses, "PublicInputHash": hex(&public_hash)
            }),
        },
    ))
}

pub fn balance(
    payment: &Payment,
    owner: Field,
    buffer: Field,
    output_tree_id: u16,
    openings: &[&Opening],
    outputs: &[Output],
    capacity: usize,
) -> Result<Request, ClientError> {
    let _phase = crate::timing::Phase::start("direct_balance_witness", 0);
    if !payment.validate()
        || openings.is_empty()
        || openings.len() > capacity
        || ![1, MAX_CERTIFICATES].contains(&capacity)
        || outputs.len() != payment.outputs.len()
    {
        return Err(invalid("invalid balance shape"));
    }
    let asset = openings[0].asset;
    let mut values = Vec::with_capacity(capacity);
    let mut commitments = Vec::with_capacity(capacity);
    for opening in openings {
        if opening.asset != asset {
            return Err(invalid("a direct spend supports one asset"));
        }
        values.push(json!({ "ID": hex(&opening.id), "Commitment": hex(&opening.commitment), "Amount": hex(&amount_field(opening.amount)), "Randomness": hex(&opening.randomness) }));
        commitments.push([opening.id, opening.commitment]);
    }
    values.resize(capacity, json!({ "ID": hex(&field(0)), "Commitment": hex(&field(0)), "Amount": hex(&field(0)), "Randomness": hex(&field(0)) }));
    let mut output_witnesses = Vec::with_capacity(2);
    for (output, public) in outputs.iter().zip(&payment.outputs) {
        let note = &output.note;
        let owner_key = solana_owner_identity(&public.recipient)?;
        if note.asset != asset
            || note.tree_id != field(output_tree_id.into())
            || note.hash()? != public.utxo.utxo_hash
            || note.owner_hash != Poseidon::hashv(&[&owner_key, &output.nullifier_pk])?
        {
            return Err(invalid("payment output does not match its witness"));
        }
        output_witnesses.push(json!({ "OwnerKey": hex(&owner_key), "NullifierPK": hex(&output.nullifier_pk), "Amount": hex(&note.amount), "Blinding": hex(&note.blinding), "Hash": hex(&public.utxo.utxo_hash) }));
    }
    let intent = payment.intent(&owner, &buffer)?;
    let public_hash =
        chain(&payment.balance_fields(intent, output_tree_id, &commitments, capacity)?)?;
    Ok(Request {
        kind: "spend-balance",
        inputs: capacity,
        outputs: outputs.len(),
        witness: json!({ "Intent": hex(&intent), "OutputTreeID": hex(&field(output_tree_id.into())), "Asset": hex(&asset), "Values": values, "Outputs": output_witnesses, "PublicInputHash": hex(&public_hash) }),
    })
}

pub fn payment(
    certificate: Request,
    freshness: Request,
    balance: Request,
    statement: &Payment,
    owner: Field,
    buffer: Field,
    tree_id: u16,
    output_tree_id: u16,
    opening: &Opening,
) -> Result<Request, ClientError> {
    payment_request(
        certificate,
        Some(freshness),
        balance,
        statement,
        owner,
        buffer,
        tree_id,
        output_tree_id,
        opening,
        wire::PAYMENT_DOMAIN,
    )
}

pub fn admitted_payment(
    certificate: Request,
    balance: Request,
    statement: &Payment,
    owner: Field,
    buffer: Field,
    tree_id: u16,
    output_tree_id: u16,
    opening: &Opening,
) -> Result<Request, ClientError> {
    payment_request(
        certificate,
        None,
        balance,
        statement,
        owner,
        buffer,
        tree_id,
        output_tree_id,
        opening,
        wire::ADMITTED_PAYMENT_DOMAIN,
    )
}

pub fn admitted_dag_payment(
    certificate: Request,
    balance: Request,
    statement: &Payment,
    owner: Field,
    buffer: Field,
    tree_id: u16,
    output_tree_id: u16,
    opening: &Opening,
    inputs: &[Input],
) -> Result<Request, ClientError> {
    let _phase = crate::timing::Phase::start("direct_dag_witness", 0);
    if certificate.inputs != MAX_INPUTS
        || certificate.witness["Count"] != hex(&field(inputs.len() as u64))
        || inputs.iter().enumerate().any(|(index, input)| {
            let note = &certificate.witness["Notes"][index];
            note["Index"] != hex(&field(input.proof.leaf_index))
                || note["Amount"] != hex(&input.note.amount)
                || note["Blinding"] != hex(&input.note.blinding)
        })
    {
        return Err(invalid("DAG inputs do not match the certificate witness"));
    }
    let (levels, references) = occupied_dag(inputs)?;
    let mut request = payment_request(
        certificate,
        None,
        balance,
        statement,
        owner,
        buffer,
        tree_id,
        output_tree_id,
        opening,
        wire::ADMITTED_DAG_PAYMENT_DOMAIN,
    )?;
    for note in request.witness["Certificate"]["Notes"]
        .as_array_mut()
        .unwrap()
    {
        note["Path"] = json!([]);
    }
    request.kind = "direct-payment-admitted-dag10";
    request.witness = json!({
        "AdmittedPaymentCircuit": request.witness,
        "Levels": levels,
        "LeafRef": fields(&references),
    });
    Ok(request)
}

fn occupied_dag(inputs: &[Input]) -> Result<(Value, Vec<Field>), ClientError> {
    use std::collections::{btree_map::Entry, BTreeMap};

    if inputs.is_empty() || inputs.len() > MAX_INPUTS {
        return Err(invalid("invalid DAG input count"));
    }
    let mut levels: [BTreeMap<u64, ([Field; 2], Field)>; 32] =
        std::array::from_fn(|_| BTreeMap::new());
    let root = inputs[0].proof.root;
    for input in inputs {
        let proof = &input.proof;
        if proof.leaf_index >= 1 << 10 || proof.path.len() != 32 || proof.root != root {
            return Err(invalid("DAG payment requires one occupied H10 state root"));
        }
        let mut current = proof.leaf;
        for (level, sibling) in proof.path.iter().enumerate() {
            let pair = if proof.leaf_index >> level & 1 == 0 {
                [current, *sibling]
            } else {
                [*sibling, current]
            };
            current = match levels[level].entry(proof.leaf_index >> (level + 1)) {
                Entry::Occupied(node) => {
                    if node.get().0 != pair {
                        return Err(invalid("DAG membership paths disagree"));
                    }
                    node.get().1
                }
                Entry::Vacant(node) => {
                    let hash = Poseidon::hashv(&[&pair[0], &pair[1]])?;
                    node.insert((pair, hash));
                    hash
                }
            };
            if level >= 10 && pair[1] != Poseidon::zero_bytes()[level] {
                return Err(invalid("state root contains leaves outside H10"));
            }
        }
        if current != root {
            return Err(invalid("DAG membership path does not reach its state root"));
        }
    }
    let rows = levels
        .iter()
        .map(|nodes| {
            nodes
                .keys()
                .enumerate()
                .map(|(row, index)| (*index, row))
                .collect::<BTreeMap<_, _>>()
        })
        .collect::<Vec<_>>();
    let mut encoded = Vec::with_capacity(32);
    for (level, nodes) in levels.iter().enumerate() {
        let capacity = MAX_INPUTS.min(1 << 9usize.saturating_sub(level));
        if nodes.len() > capacity {
            return Err(invalid("membership paths exceed DAG capacity"));
        }
        let mut encoded_nodes = Vec::with_capacity(capacity);
        for (index, (pair, _)) in nodes.iter().cycle().take(capacity) {
            let parent = if level == 31 {
                0
            } else {
                rows[level + 1][&(index >> 1)] * 2 + (index & 1) as usize
            };
            encoded_nodes.push(json!({ "Left": hex(&pair[0]), "Right": hex(&pair[1]), "Parent": hex(&field(parent as u64)) }));
        }
        encoded.push(encoded_nodes);
    }
    let mut references = inputs
        .iter()
        .map(|input| {
            let index = input.proof.leaf_index;
            field((rows[0][&(index >> 1)] * 2) as u64 + (index & 1))
        })
        .collect::<Vec<_>>();
    references.resize(MAX_INPUTS, [0; 32]);
    Ok((json!(encoded), references))
}

fn payment_request(
    mut certificate: Request,
    mut freshness: Option<Request>,
    mut balance: Request,
    statement: &Payment,
    owner: Field,
    buffer: Field,
    tree_id: u16,
    output_tree_id: u16,
    opening: &Opening,
    domain: u64,
) -> Result<Request, ClientError> {
    let _phase = crate::timing::Phase::start("direct_fused_witness", 0);
    let PaymentInputs::Notes {
        certificate: inputs,
        freshness: root,
    } = &statement.inputs
    else {
        return Err(invalid("fused payment requires original notes"));
    };
    let capacity = certificate.inputs;
    let outputs = balance.outputs;
    if certificate.kind != "input-certificate"
        || balance.kind != "spend-balance"
        || balance.inputs != 1
    {
        return Err(invalid("invalid fused payment shape"));
    }
    let (kind, domain) = if let Some(request) = &freshness {
        if request.kind != "nullifier-freshness" || request.inputs != capacity {
            return Err(invalid("invalid fused freshness shape"));
        }
        if !wire::GKR_PAYMENT_INPUTS.contains(&capacity) || outputs != 2 {
            return Err(invalid("invalid fused payment shape"));
        }
        ("direct-payment", wire::PAYMENT_DOMAIN)
    } else {
        if root.index != 0 || root.value != [0; 32] {
            return Err(invalid(
                "admitted payment requires canonical zero freshness",
            ));
        }
        if !wire::ADMITTED_PAYMENT_SHAPES.contains(&(capacity, outputs)) {
            return Err(invalid("invalid admitted payment shape"));
        }
        ("direct-payment-admitted", domain)
    };
    let mut public = vec![field(domain)];
    public.extend(inputs.fields(certificate_id(&buffer)?, &owner, tree_id, capacity)?);
    if freshness.is_some() {
        public.extend(inputs.freshness_fields(*root, tree_id, capacity)?);
    }
    public.extend(statement.balance_fields(
        statement.intent(&owner, &buffer)?,
        output_tree_id,
        &[[opening.id, opening.commitment]],
        1,
    )?);
    for request in [&mut certificate, &mut balance]
        .into_iter()
        .chain(freshness.iter_mut())
    {
        request
            .witness
            .as_object_mut()
            .unwrap()
            .remove("PublicInputHash");
    }
    let mut witness = json!({ "Certificate": certificate.witness, "Balance": balance.witness, "PublicInputHash": hex(&chain(&public)?) });
    if let Some(freshness) = freshness {
        witness["Freshness"] = freshness.witness;
    }
    Ok(Request {
        kind,
        inputs: capacity,
        outputs,
        witness,
    })
}

/// `inline_spend` instruction data from a one-output admitted payment and its
/// committed proof.
pub fn inline_spend(
    payment: &Payment,
    owner: Field,
    proof: ProofCompressed,
) -> Result<wire::InlineSpend, ClientError> {
    let commitment = proof
        .commitment
        .ok_or_else(|| invalid("inline spend requires a committed proof"))?;
    wire::InlineSpend::from_payment(
        payment,
        &owner,
        wire::Proof {
            a: proof.a,
            b: proof.b,
            c: proof.c,
        },
        zolana_interface::verifying_keys::Bsb22Commitment {
            commitment: commitment.commitment,
            commitment_pok: commitment.commitment_pok,
        },
    )
    .map_err(invalid)
}

impl TryFrom<ProofCompressed> for wire::Proof {
    type Error = ClientError;
    fn try_from(proof: ProofCompressed) -> Result<Self, Self::Error> {
        if proof.commitment.is_some() {
            return Err(invalid("direct spend does not use a proof commitment"));
        }
        Ok(Self {
            a: proof.a,
            b: proof.b,
            c: proof.c,
        })
    }
}

fn hex(field: &Field) -> String {
    super::field::hex_fixed(field)
}
fn fields(values: &[Field]) -> Vec<String> {
    values.iter().map(hex).collect()
}
fn amount_field(value: u128) -> Field {
    let mut field = [0; 32];
    field[16..].copy_from_slice(&value.to_be_bytes());
    field
}
fn invalid(message: &str) -> ClientError {
    ClientError::Prover(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn membership_inputs() -> Vec<Input> {
        let mut tree = zolana_merkle_tree::MerkleTree::<Poseidon>::new(32, 0);
        let key = NullifierKey::from_secret([19; 31]);
        let owner_hash = Poseidon::hashv(&[
            &solana_owner_identity(&field(1)).unwrap(),
            &key.pubkey().unwrap(),
        ])
        .unwrap();
        let notes = (0..8)
            .map(|index| ProofInputUtxo {
                domain: field(3),
                tree_id: field(0),
                owner_hash,
                asset: field(2),
                amount: field(10),
                blinding: field(100 + index),
                data_hash: [0; 32],
                ring_data_hash: [0; 32],
                ring_program_id: [0; 32],
            })
            .collect::<Vec<_>>();
        for note in &notes {
            tree.append(&note.hash().unwrap()).unwrap();
        }
        notes
            .into_iter()
            .enumerate()
            .map(|(index, note)| {
                let committed = InputNote::new(note).unwrap();
                let proof = MerkleProof {
                    leaf: committed.commitment(),
                    root: tree.root(),
                    root_index: 0,
                    root_seq: 0,
                    leaf_index: index as u64,
                    merkle_context: crate::rpc::MerkleContext {
                        tree_type: 0,
                        tree: solana_address::Address::new_from_array([0; 32]),
                    },
                    path: tree.get_proof_of_leaf(index, true).unwrap(),
                };
                committed.with_proof(proof).unwrap()
            })
            .collect()
    }

    #[test]
    fn serialized_direct_witness_uses_fixed_32_byte_hex_fields() {
        fn check(value: &Value) {
            match value {
                Value::String(field) => {
                    assert_eq!(field.len(), 66, "{field}");
                    assert!(field.starts_with("0x"));
                    assert!(field[2..].bytes().all(|byte| byte.is_ascii_hexdigit()));
                }
                Value::Array(values) => values.iter().for_each(check),
                Value::Object(values) => values.values().for_each(check),
                _ => panic!("direct witness field must be a hex string: {value}"),
            }
        }
        let inputs = membership_inputs();
        let plan = certificate(
            field(1),
            field(2),
            field(3),
            0,
            &NullifierKey::from_secret([19; 31]),
            &inputs,
            field(4),
            MAX_INPUTS,
        )
        .unwrap();
        let body: Value = serde_json::from_str(&plan.request.body().unwrap()).unwrap();
        check(&body["witness"]);
        let (levels, references) = occupied_dag(&inputs).unwrap();
        check(&levels);
        check(&json!(fields(&references)));
    }

    #[test]
    fn committed_note_rejects_a_different_leaf() {
        let mut inputs = membership_inputs();
        let input = inputs.remove(0);
        let mut proof = input.proof;
        proof.leaf = field(9);
        assert!(Input::new(input.note, proof).is_err());
    }

    #[test]
    fn occupied_dag_preserves_private_paths() {
        let inputs = membership_inputs();
        let (levels, references) = occupied_dag(&inputs).unwrap();
        let decode = |value: &Value| {
            let integer =
                num_bigint::BigUint::parse_bytes(value.as_str().unwrap()[2..].as_bytes(), 16)
                    .unwrap();
            super::super::field::right_align_slice(&integer.to_bytes_be()).unwrap()
        };
        assert_eq!(levels.as_array().unwrap().len(), 32);
        assert_eq!(references.len(), MAX_INPUTS);
        for (input, reference) in inputs.iter().zip(&references) {
            let mut reference = u64::from_be_bytes(reference[24..].try_into().unwrap()) as usize;
            let mut current = input.proof.leaf;
            for level in 0..32 {
                let node = &levels[level][reference / 2];
                let pair = [decode(&node["Left"]), decode(&node["Right"])];
                assert_eq!(current, pair[reference & 1]);
                assert_eq!(
                    reference & 1,
                    (input.proof.leaf_index >> level & 1) as usize
                );
                current = Poseidon::hashv(&[&pair[0], &pair[1]]).unwrap();
                let parent = decode(&node["Parent"]);
                reference = u64::from_be_bytes(parent[24..].try_into().unwrap()) as usize;
            }
            assert_eq!(current, input.proof.root);
        }
    }

    #[test]
    fn occupied_dag_rejects_invalid_paths_and_occupied_upper_siblings() {
        let mut inputs = membership_inputs();
        inputs[0].proof.path[0] = field(9);
        assert!(occupied_dag(&inputs).is_err());
        let mut inputs = membership_inputs();
        inputs[0].proof.leaf_index = 1024;
        assert!(occupied_dag(&inputs).is_err());
        let mut inputs = membership_inputs();
        inputs.truncate(1);
        let proof = &mut inputs[0].proof;
        proof.path[10] = field(9);
        proof.root = proof.path.iter().fold(proof.leaf, |node, sibling| {
            Poseidon::hashv(&[&node, sibling]).unwrap()
        });
        assert!(occupied_dag(&inputs).is_err());
    }

    fn request(freshness: Root) -> Result<Request, ClientError> {
        let opening = Opening {
            id: field(1),
            commitment: field(2),
            asset: field(3),
            amount: 4,
            randomness: field(5),
        };
        let statement = Payment {
            inputs: PaymentInputs::Notes {
                certificate: Certificate {
                    tree: field(1),
                    state_root: Root {
                        index: 0,
                        value: field(2),
                    },
                    nullifiers: vec![field(3)],
                    value_commitment: opening.commitment,
                },
                freshness,
            },
            output_tree: field(4),
            expiry_slot: u64::MAX,
            max_forester_fee: 0,
            outputs: Vec::new(),
            tx_viewing_pk: [0; 33],
            salt: [0; 16],
        };
        let certificate = Request {
            kind: "input-certificate",
            inputs: 144,
            outputs: 0,
            witness: json!({ "PublicInputHash": "old", "Notes": [] }),
        };
        let balance = Request {
            kind: "spend-balance",
            inputs: 1,
            outputs: 2,
            witness: json!({ "PublicInputHash": "old", "Values": [] }),
        };
        admitted_payment(
            certificate,
            balance,
            &statement,
            field(6),
            field(7),
            0,
            0,
            &opening,
        )
    }

    #[test]
    fn admitted_request_has_no_freshness_witness() {
        let request = request(Root {
            index: 0,
            value: [0; 32],
        })
        .unwrap();
        let body: Value = serde_json::from_str(&request.body().unwrap()).unwrap();
        assert_eq!(body["circuitType"], "direct-payment-admitted");
        assert!(body["witness"].get("Freshness").is_none());
        assert!(body["witness"]["Certificate"]
            .get("PublicInputHash")
            .is_none());
        assert!(body["witness"]["Balance"].get("PublicInputHash").is_none());
    }

    #[test]
    fn admitted_request_rejects_nonzero_freshness() {
        assert!(request(Root {
            index: 1,
            value: [0; 32]
        })
        .is_err());
        assert!(request(Root {
            index: 0,
            value: field(1)
        })
        .is_err());
    }
}
