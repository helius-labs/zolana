//! The anonymous ring prover requests the TS SDK pins.

#[path = "common/input.rs"]
mod input_fixture;
#[path = "common/blindings.rs"]
mod output_blindings;

use serde_json::Value;
use solana_address::Address;
use spr_client::{
    prover::{
        attach_input_proofs,
        indexed::{IndexedTransferPreparation, IndexedTransferRail, Request},
        transact::anonymous_ring_eddsa::anonymous_signer_pk_hashes,
        AnonymousRingEddsaProver, ProveRequest, Shape,
    },
    MerkleContext, MerkleProof, NonInclusionProof, ProofAuthority, SpendProof,
    NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use spr_interface::{
    instruction::{
        instruction_data::transact::{Bsb22Commitment, CircuitId},
        OwnerTag, TransactOutput,
    },
    verifying_keys::AnonymousRingEddsaProofData,
};
use spr_keypair::{ShieldedKeypair, SigningKey};
use spr_transaction::{
    instructions::transact::SppProofInputs, utxo::SppProofInputUtxo, Data, ExternalData, Mint,
    SppProofOutputUtxo, Utxo,
};

use crate::{input_fixture::wallet_utxo, output_blindings::assign_output_blindings};

const VECTOR_JSON: &str = include_str!("../../../test-vectors/anonymous_ring_eddsa_request.json");

const OWNER_SEED: u8 = 0x11;
const RECIPIENT_SEED: u8 = 0x22;
const RING: [u8; 32] = [0x52; 32];
const TREE_ID: u16 = 0;
const OWNER_TAG: [u8; 32] = [0x08; 32];

fn field_bytes(byte: u8) -> [u8; 32] {
    core::array::from_fn(|index| if index == 0 { 0 } else { byte })
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_ed25519_bytes(&[seed; 32])
}

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(signing_key(seed)).expect("fixed-seed keypair")
}

fn proof_inputs(owner: &ShieldedKeypair, input_ring: Option<Address>) -> SppProofInputs {
    let ring = Address::new_from_array(RING);
    let input: SppProofInputUtxo = wallet_utxo(
        Utxo {
            owner: owner.signing_pubkey(),
            asset: Mint::SOL,
            amount: 7,
            blinding: field_bytes(0x31),
            ring_program_id: input_ring,
            data: Data::default(),
        },
        &owner.nullifier_key,
        TREE_ID,
        7,
        None,
        None,
    )
    .into();
    let output = |holder: &ShieldedKeypair, amount| {
        SppProofOutputUtxo::new(Mint::SOL, amount, holder.shielded_address().unwrap())
            .unwrap()
            .with_ring_program_id(ring)
    };
    let mut outputs = vec![output(&keypair(RECIPIENT_SEED), 4), output(owner, 3)];
    let blinding_seed = field_bytes(0x41);
    assign_output_blindings(&input.nullifier, &mut outputs, &blinding_seed);
    let external_data = ExternalData::new(
        *owner.viewing_pubkey().as_bytes(),
        [0x5a; 16],
        outputs
            .iter()
            .map(|output| TransactOutput {
                utxo_hash: output.hash(TREE_ID).unwrap(),
                owner_tag: OwnerTag::Inline(OWNER_TAG),
                data: None,
            })
            .collect(),
        vec![OWNER_TAG; outputs.len()],
        vec![],
    );
    SppProofInputs {
        input_utxos: vec![input],
        output_utxos: outputs,
        blinding_seed,
        output_tree_id: TREE_ID,
        external_data,
        payer: Address::new_from_array(owner.signing_pubkey().as_ed25519().unwrap()),
        cache_accounts: Default::default(),
    }
}

fn spend_proof(input: &SppProofInputUtxo) -> SpendProof {
    let context = MerkleContext {
        tree_type: 1,
        tree: spr_interface::pda::tree(TREE_ID),
    };
    SpendProof {
        state: MerkleProof {
            leaf: input.hash(),
            merkle_context: context.clone(),
            path: vec![field_bytes(0x53); STATE_TREE_HEIGHT],
            leaf_index: 7,
            root: field_bytes(0x54),
            root_seq: 11,
            root_index: 5,
        },
        nullifier: NonInclusionProof {
            leaf: input.nullifier,
            merkle_context: context,
            path: vec![field_bytes(0x56); NULLIFIER_TREE_HEIGHT],
            low_element: field_bytes(0x57),
            low_element_index: 3,
            high_element: field_bytes(0x58),
            high_element_index: 4,
            root: field_bytes(0x59),
            root_seq: 13,
            root_index: 9,
        },
    }
}

/// The plain request body and the wincode selector the transfer carries before its proof.
fn request_and_circuit(input_ring: Option<Address>) -> (Value, String) {
    let owner = keypair(OWNER_SEED);
    let key = signing_key(OWNER_SEED);
    let transaction = proof_inputs(&owner, input_ring);
    let proofs = [spend_proof(&transaction.input_utxos[0])];
    let mut result = AnonymousRingEddsaProver {
        signer_pk_hashes: anonymous_signer_pk_hashes(&transaction, &owner.signing_pubkey())
            .unwrap(),
        public_transfers: transaction.public_transfers().unwrap(),
        inputs: attach_input_proofs(transaction.input_utxos, &proofs, &[]).unwrap(),
        outputs: transaction.output_utxos,
        blinding_seed: transaction.blinding_seed,
        output_tree_id: TREE_ID,
        external_data: transaction.external_data,
        allow_dummy_inputs: true,
        owner: (&key).into(),
        ring_program_id: Some(Address::new_from_array(RING)),
        shape: Shape::IN1_OUT2,
    }
    .build()
    .unwrap();
    owner
        .complete_inputs(&mut result.inputs.transfer.inputs)
        .unwrap();
    let circuit = CircuitId::AnonymousRingEddsa(
        1,
        2,
        3,
        AnonymousRingEddsaProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
            default_owner_tag: result.default_owner_tag,
        },
    );
    (
        serde_json::from_str(&result.inputs.body().unwrap()).unwrap(),
        hex::encode(wincode::serialize(&circuit).unwrap()),
    )
}

fn indexed_request() -> Value {
    let owner = keypair(OWNER_SEED);
    let key = signing_key(OWNER_SEED);
    let prepared = IndexedTransferPreparation {
        transaction: proof_inputs(&owner, Some(Address::new_from_array(RING))),
        rail: IndexedTransferRail::AnonymousRingEddsa {
            ring: Address::new_from_array(RING),
            owner: (&key).into(),
        },
    }
    .prepare(&owner)
    .unwrap();
    serde_json::from_str(&prepared.body().unwrap()).unwrap()
}

#[test]
fn the_anonymous_ring_requests_match_the_vector() {
    let vector: Value = serde_json::from_str(VECTOR_JSON).unwrap();
    assert_eq!(vector, vector_json(vector["description"].clone()));
}

fn vector_json(description: Value) -> Value {
    let (request, circuit) = request_and_circuit(Some(Address::new_from_array(RING)));
    let (default_request, default_circuit) = request_and_circuit(None);
    serde_json::json!({
        "description": description,
        "request": request,
        "indexedRequest": indexed_request(),
        "circuit": circuit,
        "defaultRing": { "request": default_request, "circuit": default_circuit },
    })
}

#[test]
#[ignore = "regenerates test-vectors/anonymous_ring_eddsa_request.json; run with --nocapture and commit the output"]
fn print_the_anonymous_ring_request_vector() {
    let vector = vector_json(Value::String("The plain and indexed prover request bodies of a 1x2 anonymous ring transfer whose hidden owner spends a ring UTXO, after the owner completes its inputs, and the wincode circuit selector before the proof commitment. defaultRing holds the plain body and selector when the hidden owner spends a default-ring UTXO instead. Produced by sdk-libs/client/tests/anonymous_ring_eddsa_request.rs print_the_anonymous_ring_request_vector: cargo test -p spr-client --test anonymous_ring_eddsa_request print_the_anonymous_ring_request_vector -- --ignored --nocapture".to_string()));
    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}
