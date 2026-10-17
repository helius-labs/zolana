use zolana_program::{
    verifier::{public_hash, Field, VerifyError},
    CompressedProof,
};

use super::{
    circuit_hash, inputs, owner_hash, settlement, Settlement, Unconditional, PRIVATE_TX_HASH,
};

fn rendered(inputs: &Settlement) -> settlement::PublicInputs {
    settlement::PublicInputs {
        amount: inputs.amount,
        paid: inputs.paid,
        recipient: owner_hash(&inputs.recipient),
        signers: inputs.signers.map(|signer| owner_hash(&signer)),
        limits: inputs.limits,
    }
}

#[test]
fn the_public_hash_equals_the_circuit_hash() {
    let inputs = inputs();
    let recipient = owner_hash(&inputs.recipient);
    let [first, second] = inputs.signers.map(|signer| owner_hash(&signer));
    let [[a, b], [c, d]] = inputs.limits;
    let fields = [
        Field::Integer(u128::from(inputs.amount)),
        Field::Bool(inputs.paid),
        Field::Hash(&recipient),
        Field::Array(&[Field::Hash(&first), Field::Hash(&second)]),
        Field::Array(&[
            Field::Array(&[Field::Integer(a.into()), Field::Integer(b.into())]),
            Field::Array(&[Field::Integer(c.into()), Field::Integer(d.into())]),
        ]),
    ];
    assert_eq!(
        public_hash(&fields, &PRIVATE_TX_HASH),
        Ok(circuit_hash(&inputs))
    );
}

#[test]
fn no_fields_hash_the_private_transaction_hash_alone() {
    assert_eq!(
        public_hash(&[], &PRIVATE_TX_HASH),
        Ok(circuit_hash(&Unconditional))
    );
}

#[test]
fn the_rendered_public_inputs_hash_equals_the_circuit_hash() {
    let inputs = inputs();
    assert_eq!(
        rendered(&inputs).hash(&PRIVATE_TX_HASH),
        Ok(circuit_hash(&inputs))
    );
}

#[test]
fn a_hash_outside_the_field_is_refused() {
    assert_eq!(
        public_hash(&[Field::Hash(&[0xff; 32])], &PRIVATE_TX_HASH),
        Err(VerifyError::PublicInputs)
    );
}

#[test]
fn more_than_eleven_fields_are_refused() {
    assert_eq!(
        public_hash(&[Field::Bool(true); 12], &PRIVATE_TX_HASH),
        Err(VerifyError::PublicInputs)
    );
}

#[test]
fn the_rendered_verify_refuses_a_proof_that_is_not_on_the_curve() {
    let proof = CompressedProof {
        a: [0xff; 32],
        b: [0xff; 64],
        c: [0xff; 32],
    };
    assert_eq!(
        settlement::verify(&proof, &rendered(&inputs()), &PRIVATE_TX_HASH),
        Err(VerifyError::Proof)
    );
}
