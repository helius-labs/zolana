use zolana_program::{
    transaction_hash,
    verifier::{public_hash, Field, VerifyError},
    CompressedProof, PublicTransfer,
};

use super::{
    address_hash, circuit_hash, inputs, settlement, Settlement, Unconditional, PRIVATE_TX_HASH,
};

fn rendered(inputs: &Settlement) -> settlement::PublicInputs {
    settlement::PublicInputs {
        amount: inputs.amount,
        paid: inputs.paid,
        recipient: address_hash(&inputs.recipient),
        signers: inputs.signers.map(|signer| address_hash(&signer)),
        limits: inputs.limits,
    }
}

#[test]
fn the_public_hash_equals_the_circuit_hash() {
    let inputs = inputs();
    let recipient = address_hash(&inputs.recipient);
    let [first, second] = inputs.signers.map(|signer| address_hash(&signer));
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
fn a_viewing_key_change_changes_the_program_public_hash() {
    let first = inputs();
    let mut second = first.clone();
    second.recipient.viewing_pubkey = super::address(9).viewing_pubkey;
    assert_eq!(first.recipient.owner_hash(), second.recipient.owner_hash());
    assert_ne!(circuit_hash(&first), circuit_hash(&second));
}

#[test]
fn the_on_chain_address_hash_matches_the_client_address() {
    let recipient = super::address(6);
    assert_eq!(
        zolana_program::verifier::address_hash(
            &recipient.owner_hash().unwrap(),
            recipient.viewing_pubkey.as_bytes(),
        ),
        Ok(recipient.address_hash().unwrap())
    );
}

#[test]
fn a_public_transfer_changes_the_generated_verifier_statement() {
    let transfer = PublicTransfer {
        mint: solana_address::Address::default(),
        is_deposit: true,
        amount: 1,
        account: solana_address::Address::new_from_array([1u8; 32]),
    };
    let transfer_hash = transaction_hash(&PRIVATE_TX_HASH, &[transfer]).unwrap();
    let inputs = rendered(&inputs());
    assert_ne!(inputs.hash(&transfer_hash), inputs.hash(&PRIVATE_TX_HASH));
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
        settlement::Verifier {
            proof: &proof,
            public_inputs: rendered(&inputs()),
            private_tx_hash: &PRIVATE_TX_HASH,
            transfers: &[],
        }
        .verify(),
        Err(VerifyError::Proof)
    );
}

#[test]
fn verification_errors_propagate_in_program_handlers() {
    fn process() -> Result<(), solana_program_error::ProgramError> {
        settlement::Verifier {
            proof: &CompressedProof {
                a: [0xff; 32],
                b: [0xff; 64],
                c: [0xff; 32],
            },
            public_inputs: rendered(&inputs()),
            private_tx_hash: &PRIVATE_TX_HASH,
            transfers: &[],
        }
        .verify()?;
        Ok(())
    }

    assert_eq!(
        process(),
        Err(solana_program_error::ProgramError::InvalidArgument)
    );
}

#[test]
fn invalid_public_inputs_propagate_as_invalid_instruction_data() {
    fn process() -> Result<(), solana_program_error::ProgramError> {
        let mut public_inputs = rendered(&inputs());
        public_inputs.recipient = [0xff; 32];
        settlement::Verifier {
            proof: &CompressedProof {
                a: [0xff; 32],
                b: [0xff; 64],
                c: [0xff; 32],
            },
            public_inputs,
            private_tx_hash: &PRIVATE_TX_HASH,
            transfers: &[],
        }
        .verify()?;
        Ok(())
    }

    assert_eq!(
        process(),
        Err(solana_program_error::ProgramError::InvalidInstructionData)
    );
}
