use pinocchio::ProgramResult;
use shielded_pool_program::instructions::transact::validate_circuit;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{
            CircuitId, InputUtxo, OwnerTag, TransactIxData, TransactIxDataRef, TransactOutput,
            TransactProof,
        },
        tag::InstructionTag,
    },
};

fn validate(
    circuit: CircuitId,
    instruction: InstructionTag,
    actual_inputs: usize,
    actual_outputs: usize,
    signer_index: u8,
) -> ProgramResult {
    let ix = TransactIxData {
        expiry_unix_ts: 0,
        private_tx_hash: [0u8; 32],
        circuit,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        proof: TransactProof::zeroed(),
        inputs: (0..actual_inputs)
            .map(|_| InputUtxo {
                nullifier_hash: [0u8; 32],
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 0,
                eddsa_signer_index: signer_index,
            })
            .collect(),
        interface_transfers: Vec::new(),
        data_hash: None,
        zone_data_hash: None,
        outputs: (0..actual_outputs)
            .map(|_| TransactOutput {
                utxo_hash: [0u8; 32],
                owner_tag: OwnerTag::Inline([0u8; 32]),
                data: None,
            })
            .collect(),
        messages: Vec::new(),
    };
    let bytes = ix.serialize().unwrap();
    let borrowed = TransactIxDataRef::from_bytes(&bytes).unwrap();
    validate_circuit(&borrowed, instruction)
}

#[test]
fn selector_family_must_match_instruction() {
    for (circuit, instruction) in [
        (
            CircuitId::ConfidentialEddsa(2, 3, 3),
            InstructionTag::Transact,
        ),
        (CircuitId::ZoneEddsa(2, 3, 3), InstructionTag::ZoneTransact),
        (
            CircuitId::ZoneAuthority(2, 2, 3),
            InstructionTag::ZoneAuthorityTransact,
        ),
    ] {
        assert_eq!(
            validate(circuit, instruction, 2, circuit.num_outputs() as usize, 0),
            Ok(())
        );
    }

    assert_eq!(
        validate(
            CircuitId::ZoneEddsa(2, 3, 3),
            InstructionTag::Transact,
            2,
            3,
            0,
        ),
        Err(ShieldedPoolError::MismatchedCircuitType.into())
    );
}

#[test]
fn selector_dimensions_and_signer_indices_are_fail_closed() {
    let valid = CircuitId::ConfidentialEddsa(2, 3, 3);
    let invalid_shape = Err(ShieldedPoolError::InvalidTransactShape.into());

    assert_eq!(
        validate(valid, InstructionTag::Transact, 1, 3, 0),
        invalid_shape
    );
    assert_eq!(
        validate(
            CircuitId::ConfidentialEddsa(2, 3, 2),
            InstructionTag::Transact,
            2,
            3,
            0,
        ),
        invalid_shape
    );
    assert_eq!(
        validate(
            CircuitId::ConfidentialEddsa(6, 6, 3),
            InstructionTag::Transact,
            6,
            6,
            0,
        ),
        invalid_shape
    );
    assert_eq!(
        validate(valid, InstructionTag::Transact, 2, 3, u8::MAX),
        invalid_shape
    );
}
