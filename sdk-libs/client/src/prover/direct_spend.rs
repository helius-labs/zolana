use super::{Delivery, ProofCompressed, ProveRequest};
use crate::{
    error::ClientError,
    rpc::{MerkleProof, NonInclusionProof},
};
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

impl ProveRequest for Request {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        Ok(Zeroizing::new(json!({ "circuitType": self.kind, "nInputs": self.inputs, "nOutputs": self.outputs, "witness": self.witness }).to_string()))
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
    pub note: ProofInputUtxo,
    pub proof: MerkleProof,
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
    if inputs.is_empty()
        || inputs.len() > capacity
        || ![CERTIFICATE_INPUTS, MAX_INPUTS].contains(&capacity)
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
            || note.hash()? != input.proof.leaf
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
        || ![CERTIFICATE_INPUTS, MAX_INPUTS].contains(&capacity)
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
    if !payment.validate()
        || openings.is_empty()
        || openings.len() > capacity
        || ![1, MAX_CERTIFICATES].contains(&capacity)
        || outputs.len() != 2
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
        outputs: 2,
        witness: json!({ "Intent": hex(&intent), "OutputTreeID": hex(&field(output_tree_id.into())), "Asset": hex(&asset), "Values": values, "Outputs": output_witnesses, "PublicInputHash": hex(&public_hash) }),
    })
}

pub fn payment(
    mut certificate: Request,
    mut freshness: Request,
    mut balance: Request,
    statement: &Payment,
    owner: Field,
    buffer: Field,
    tree_id: u16,
    output_tree_id: u16,
    opening: &Opening,
) -> Result<Request, ClientError> {
    let PaymentInputs::Notes {
        certificate: inputs,
        freshness: root,
    } = &statement.inputs
    else {
        return Err(invalid("fused payment requires original notes"));
    };
    if certificate.inputs != MAX_INPUTS || freshness.inputs != MAX_INPUTS || balance.inputs != 1 {
        return Err(invalid("invalid fused payment shape"));
    }
    let mut public = vec![field(wire::PAYMENT_DOMAIN)];
    public.extend(inputs.fields(certificate_id(&buffer)?, &owner, tree_id, MAX_INPUTS)?);
    public.extend(inputs.freshness_fields(*root, tree_id, MAX_INPUTS)?);
    public.extend(statement.balance_fields(
        statement.intent(&owner, &buffer)?,
        output_tree_id,
        &[[opening.id, opening.commitment]],
        1,
    )?);
    for request in [&mut certificate, &mut freshness, &mut balance] {
        request
            .witness
            .as_object_mut()
            .unwrap()
            .remove("PublicInputHash");
    }
    Ok(Request {
        kind: "direct-payment",
        inputs: MAX_INPUTS,
        outputs: 2,
        witness: json!({ "Certificate": certificate.witness, "Freshness": freshness.witness, "Balance": balance.witness, "PublicInputHash": hex(&chain(&public)?) }),
    })
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
    format!("0x{:064x}", num_bigint::BigUint::from_bytes_be(field))
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
