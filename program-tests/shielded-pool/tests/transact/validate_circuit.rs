use pinocchio::ProgramResult;
use shielded_pool_program::instructions::transact::validate_circuit_type;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{
            Bsb22Commitment, CircuitId, InputUtxo, OwnerTag, RingP256ProofData, TransactIxData,
            TransactIxDataRef, TransactOutput, TransactProof, TreeContext,
        },
        tag::InstructionTag,
    },
};

fn validate(
    circuit: CircuitId,
    instruction: InstructionTag,
    actual_inputs: usize,
    actual_outputs: usize,
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
                tree_index: 0,
            })
            .collect(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: (0..actual_outputs)
            .map(|_| TransactOutput {
                utxo_hash: [0u8; 32],
                owner_tag: OwnerTag::Inline([0u8; 32]),
                data: None,
            })
            .collect(),
        messages: Vec::new(),
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }],
    };
    let bytes = ix.serialize().unwrap();
    let borrowed = TransactIxDataRef::from_bytes(&bytes).unwrap();
    validate_circuit_type(&borrowed, instruction)
}

#[test]
fn selector_family_must_match_instruction() {
    let commitment = Bsb22Commitment {
        commitment: [1u8; 32],
        commitment_pok: [2u8; 32],
    };
    for (circuit, instruction) in [
        (
            CircuitId::ConfidentialEddsa(2, 3, 3),
            InstructionTag::Transact,
        ),
        (
            CircuitId::RingP256(
                2,
                3,
                3,
                RingP256ProofData {
                    bsb22_commitment: commitment,
                    default_owner_tag: None,
                },
            ),
            InstructionTag::RingTransact,
        ),
        (CircuitId::RingEddsa(2, 3, 3), InstructionTag::RingTransact),
        (
            CircuitId::RingAuthority(2, 2, 3),
            InstructionTag::RingAuthorityTransact,
        ),
    ] {
        assert_eq!(
            validate(circuit, instruction, 2, circuit.num_outputs() as usize),
            Ok(())
        );
    }

    assert_eq!(
        validate(
            CircuitId::RingEddsa(2, 3, 3),
            InstructionTag::Transact,
            2,
            3,
        ),
        Err(ShieldedPoolError::MismatchedCircuitType.into())
    );
}

#[test]
fn selector_dimensions_are_fail_closed() {
    let valid = CircuitId::ConfidentialEddsa(2, 3, 3);
    let invalid_shape = Err(ShieldedPoolError::InvalidTransactShape.into());

    assert_eq!(
        validate(valid, InstructionTag::Transact, 1, 3),
        invalid_shape
    );
    assert_eq!(
        validate(
            CircuitId::ConfidentialEddsa(2, 3, 2),
            InstructionTag::Transact,
            2,
            3,
        ),
        invalid_shape
    );
    assert_eq!(
        validate(
            CircuitId::ConfidentialEddsa(6, 6, 3),
            InstructionTag::Transact,
            6,
            6,
        ),
        invalid_shape
    );
    assert_eq!(
        validate(
            CircuitId::ConfidentialEddsa(36, 2, 3),
            InstructionTag::Transact,
            36,
            2,
        ),
        Ok(())
    );
    assert_eq!(
        validate(
            CircuitId::RingEddsa(36, 2, 3),
            InstructionTag::RingTransact,
            36,
            2,
        ),
        Ok(())
    );
    assert_eq!(
        validate(
            CircuitId::ConfidentialEddsa(36, 3, 3),
            InstructionTag::Transact,
            36,
            3,
        ),
        invalid_shape
    );
    assert_eq!(
        validate(
            CircuitId::RingAuthority(36, 2, 3),
            InstructionTag::RingAuthorityTransact,
            36,
            2,
        ),
        invalid_shape
    );
    let p256 = CircuitId::RingP256(
        2,
        3,
        3,
        RingP256ProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: [1u8; 32],
                commitment_pok: [2u8; 32],
            },
            default_owner_tag: None,
        },
    );
    assert_eq!(validate(p256, InstructionTag::RingTransact, 2, 3), Ok(()));
}

/// A cached selector rides the same instruction as its rail: the cache picks no
/// circuit, so it cannot move a spend between the default and ring tags. Ring
/// authority has no cached twin at all.
#[test]
fn a_cached_selector_is_accepted_exactly_where_its_rail_is() {
    use zolana_interface::verifying_keys::CachedInputs;
    const CACHE: CachedInputs = CachedInputs { input_bitmap: 3 };
    let p256_proof_data = RingP256ProofData {
        bsb22_commitment: Bsb22Commitment {
            commitment: [1u8; 32],
            commitment_pok: [2u8; 32],
        },
        default_owner_tag: None,
    };
    let cases = [
        (
            CircuitId::ConfidentialEddsaCached(2, 2, 3, CACHE),
            InstructionTag::Transact,
        ),
        (
            CircuitId::RingEddsaCached(2, 2, 3, CACHE),
            InstructionTag::RingTransact,
        ),
        (
            CircuitId::RingP256Cached(2, 2, 3, p256_proof_data, CACHE),
            InstructionTag::RingTransact,
        ),
    ];
    for (circuit, accepted_by) in cases {
        assert_eq!(validate(circuit, accepted_by, 2, 2), Ok(()));
        for instruction in [
            InstructionTag::Transact,
            InstructionTag::RingTransact,
            InstructionTag::RingAuthorityTransact,
        ] {
            if instruction == accepted_by {
                continue;
            }
            assert_eq!(
                validate(circuit, instruction, 2, 2),
                Err(ShieldedPoolError::MismatchedCircuitType.into()),
                "{circuit:?} on {instruction:?}"
            );
        }
    }
}

#[test]
fn cached_input_bitmap_must_select_only_declared_inputs() {
    use zolana_interface::verifying_keys::CachedInputs;
    for input_bitmap in [0, 4, 1 << 36] {
        let circuit = CircuitId::ConfidentialEddsaCached(2, 2, 3, CachedInputs { input_bitmap });
        assert_eq!(
            validate(circuit, InstructionTag::Transact, 2, 2),
            Err(ShieldedPoolError::InvalidCacheBitmap.into())
        );
        let ring = CircuitId::RingEddsaCached(2, 2, 3, CachedInputs { input_bitmap });
        assert_eq!(
            validate(ring, InstructionTag::RingTransact, 2, 2),
            Err(ShieldedPoolError::InvalidCacheBitmap.into())
        );
    }
}
