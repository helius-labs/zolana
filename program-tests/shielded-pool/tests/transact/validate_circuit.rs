use pinocchio::ProgramResult;
use shielded_pool_program::instructions::transact::{control_cosigner, validate_circuit_type};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{
            AnonymousParties, AnonymousRingEddsaProofData, Bsb22Commitment, CircuitId, InputUtxo,
            OwnerTag, TransactIxData, TransactIxDataRef, TransactOutput, TransactProof,
            TreeContext,
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
    validate_with(
        circuit,
        instruction,
        actual_inputs,
        actual_outputs,
        [1u8; 32],
        [1u8; 32],
    )
}

/// `nullifier` and `utxo_hash` fill every sent input and output; zero marks
/// compact padding, which the instruction never carries.
fn validate_with(
    circuit: CircuitId,
    instruction: InstructionTag,
    actual_inputs: usize,
    actual_outputs: usize,
    nullifier: [u8; 32],
    utxo_hash: [u8; 32],
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
                nullifier_hash: nullifier,
                tree_index: 0,
            })
            .collect(),
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        outputs: (0..actual_outputs)
            .map(|_| TransactOutput {
                utxo_hash,
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
            CircuitId::ConfidentialEddsa(2, 4, 3),
            InstructionTag::Transact,
        ),
        (
            CircuitId::AnonymousRingEddsa(
                2,
                4,
                3,
                AnonymousRingEddsaProofData {
                    bsb22_commitment: commitment,
                    default_owner_tag: None,
                },
            ),
            InstructionTag::RingTransact,
        ),
        (
            CircuitId::ConfidentialRingEddsa(2, 4, 3),
            InstructionTag::RingTransact,
        ),
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
            CircuitId::ConfidentialRingEddsa(2, 4, 3),
            InstructionTag::Transact,
            2,
            4,
        ),
        Err(ShieldedPoolError::MismatchedCircuitType.into())
    );
}

#[test]
fn selector_dimensions_are_fail_closed() {
    let valid = CircuitId::ConfidentialEddsa(2, 4, 3);
    let invalid_shape = Err(ShieldedPoolError::InvalidTransactShape.into());

    for (inputs, outputs) in [(0, 4), (3, 4), (2, 5)] {
        assert_eq!(
            validate(valid, InstructionTag::Transact, inputs, outputs),
            invalid_shape,
            "{inputs} inputs, {outputs} outputs"
        );
    }
    assert_eq!(
        validate(
            CircuitId::ConfidentialEddsa(2, 4, 2),
            InstructionTag::Transact,
            2,
            4,
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
    for (inputs, outputs) in [(1, 1), (2, 3), (3, 3), (4, 3), (5, 3), (36, 2), (51, 2)] {
        assert_eq!(
            validate(
                CircuitId::ConfidentialEddsa(inputs, outputs, 3),
                InstructionTag::Transact,
                inputs as usize,
                outputs as usize,
            ),
            invalid_shape,
            "removed shape {inputs}x{outputs}"
        );
    }
    assert_eq!(
        validate(
            CircuitId::ConfidentialEddsa(49, 2, 3),
            InstructionTag::Transact,
            49,
            2,
        ),
        Ok(())
    );
    assert_eq!(
        validate(
            CircuitId::ConfidentialRingEddsa(49, 2, 3),
            InstructionTag::RingTransact,
            49,
            2,
        ),
        Ok(())
    );
    assert_eq!(
        validate(
            CircuitId::ConfidentialEddsa(49, 4, 3),
            InstructionTag::Transact,
            49,
            4,
        ),
        invalid_shape
    );
    assert_eq!(
        validate(
            CircuitId::RingAuthority(49, 2, 3),
            InstructionTag::RingAuthorityTransact,
            49,
            2,
        ),
        invalid_shape
    );
    for width in [1, 3] {
        assert_eq!(
            validate(
                CircuitId::RingAuthority(width, width, 3),
                InstructionTag::RingAuthorityTransact,
                width as usize,
                width as usize,
            ),
            invalid_shape,
            "ring authority {width}x{width}"
        );
    }
    let anonymous = CircuitId::AnonymousRingEddsa(
        2,
        4,
        3,
        AnonymousRingEddsaProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: [1u8; 32],
                commitment_pok: [2u8; 32],
            },
            default_owner_tag: None,
        },
    );
    assert_eq!(
        validate(anonymous, InstructionTag::RingTransact, 2, 4),
        Ok(())
    );
}

/// The instruction carries at least one input and at most the circuit's slots;
/// the missing suffix is compact padding. A sent zero would be indistinguishable
/// from that padding, so it is rejected.
#[test]
fn compact_padding_shortens_the_instruction_and_a_sent_zero_is_rejected() {
    let circuit = CircuitId::ConfidentialEddsa(2, 4, 3);
    for (inputs, outputs) in [(1, 4), (2, 1), (1, 0)] {
        assert_eq!(
            validate(circuit, InstructionTag::Transact, inputs, outputs),
            Ok(()),
            "{inputs} inputs, {outputs} outputs"
        );
    }
    assert_eq!(
        validate_with(
            circuit,
            InstructionTag::Transact,
            1,
            0,
            [0u8; 32],
            [1u8; 32]
        ),
        Err(ShieldedPoolError::ZeroInputNullifier.into())
    );
    assert_eq!(
        validate_with(
            circuit,
            InstructionTag::Transact,
            1,
            1,
            [1u8; 32],
            [0u8; 32]
        ),
        Err(ShieldedPoolError::ZeroOutputUtxoHash.into())
    );
}

/// A cached selector rides the same instruction as its rail: the cache picks no
/// circuit, so it cannot move a spend between the default and ring tags. Ring
/// authority has no cached twin at all.
#[test]
fn a_cached_selector_is_accepted_exactly_where_its_rail_is() {
    use zolana_interface::verifying_keys::CacheAccess;
    const CACHE: CacheAccess = CacheAccess {
        read_bitmap: 3,
        write_slots: CacheAccess::NO_WRITES,
    };
    let proof_data = AnonymousRingEddsaProofData {
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
            CircuitId::ConfidentialRingEddsaCached(2, 2, 3, CACHE),
            InstructionTag::RingTransact,
        ),
        (
            CircuitId::AnonymousRingEddsaCached(2, 2, 3, proof_data, CACHE),
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

fn cache_writes(
    pairs: &[(u8, u8)],
) -> [zolana_interface::verifying_keys::CacheWrite;
       zolana_interface::verifying_keys::MAX_CACHE_WRITES] {
    use zolana_interface::verifying_keys::{CacheAccess, CacheWrite};
    let mut out = CacheAccess::NO_WRITES;
    for (entry, (output, slot)) in out.iter_mut().zip(pairs) {
        *entry = CacheWrite {
            output: *output,
            slot: *slot,
        };
    }
    out
}

/// With compact padding the instruction sends fewer slots than the circuit
/// has. Cache reads and writes are checked against the sent slots, so a read
/// count or a write target that only the compact padding would cover is
/// rejected.
#[test]
fn a_cached_selector_counts_only_the_sent_slots() {
    use zolana_interface::verifying_keys::CacheAccess;
    for (read_bitmap, write_slots, valid) in [
        (0b1, CacheAccess::NO_WRITES, true),
        (0b11, CacheAccess::NO_WRITES, false),
        (0, cache_writes(&[(0, 5)]), true),
        (0, cache_writes(&[(1, 5)]), false),
        (0, cache_writes(&[(2, 5)]), false),
    ] {
        let access = CacheAccess {
            read_bitmap,
            write_slots,
        };
        let expected = if valid {
            Ok(())
        } else {
            Err(ShieldedPoolError::InvalidCacheBitmap.into())
        };
        assert_eq!(
            validate(
                CircuitId::ConfidentialEddsaCached(2, 4, 3, access),
                InstructionTag::Transact,
                1,
                1
            ),
            expected,
            "{access:?}"
        );
    }
}

#[test]
fn a_cached_selector_must_fit_the_inputs_the_outputs_and_the_cache() {
    use zolana_interface::verifying_keys::{CacheAccess, CacheWrite};
    let mut gap = cache_writes(&[(0, 1)]);
    if let Some(entry) = gap.get_mut(2) {
        *entry = CacheWrite { output: 1, slot: 2 };
    }
    for (read_bitmap, write_slots, valid) in [
        (0, CacheAccess::NO_WRITES, false),
        (0b111, CacheAccess::NO_WRITES, false),
        (1 << 36, CacheAccess::NO_WRITES, false),
        (4, CacheAccess::NO_WRITES, true),
        (1 << 30 | 1, CacheAccess::NO_WRITES, true),
        (0, cache_writes(&[(1, 30)]), true),
        (0, cache_writes(&[(1, 9), (0, 3)]), true),
        (0, cache_writes(&[(0, 3), (1, 3)]), false),
        (0, cache_writes(&[(0, 3), (0, 4)]), false),
        (0, cache_writes(&[(2, 3)]), false),
        (0, cache_writes(&[(0, 36)]), false),
        (0, gap, false),
    ] {
        let access = CacheAccess {
            read_bitmap,
            write_slots,
        };
        let expected = if valid {
            Ok(())
        } else {
            Err(ShieldedPoolError::InvalidCacheBitmap.into())
        };
        assert_eq!(
            validate(
                CircuitId::ConfidentialEddsaCached(2, 2, 3, access),
                InstructionTag::Transact,
                2,
                2
            ),
            expected,
            "{access:?}"
        );
        assert_eq!(
            validate(
                CircuitId::ConfidentialRingEddsaCached(2, 2, 3, access),
                InstructionTag::RingTransact,
                2,
                2
            ),
            expected,
            "{access:?}"
        );
    }
}

fn anonymous_circuit() -> CircuitId {
    CircuitId::AnonymousRingEddsa(
        2,
        2,
        3,
        AnonymousRingEddsaProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: [0u8; 32],
                commitment_pok: [0u8; 32],
            },
            default_owner_tag: None,
        },
    )
}

/// The ring program appends its configured co-signer only on the anonymous rail.
#[test]
fn anonymous_control_tail_is_exactly_one_address_on_the_anonymous_rail() {
    let tail = [7u8; 32];
    assert_eq!(
        control_cosigner(anonymous_circuit(), &tail).unwrap(),
        Some(&tail)
    );
    for bad in [&[][..], &tail[..31], &[tail, tail].concat()[..]] {
        assert_eq!(
            control_cosigner(anonymous_circuit(), bad),
            Err(ShieldedPoolError::InvalidAnonymousControlTail.into())
        );
    }
    let public = CircuitId::ConfidentialRingEddsa(2, 2, 3);
    assert_eq!(control_cosigner(public, &[]).unwrap(), None);
    assert_eq!(
        control_cosigner(public, &tail),
        Err(ShieldedPoolError::InvalidAnonymousControlTail.into())
    );
}

/// The circuit keeps the hidden owner apart from the payer, the co-signer and the
/// one exit account. A zero co-signer is absent, two exit accounts are refused.
#[test]
fn anonymous_parties_publish_tagged_identities_and_one_exit() {
    let payer = [1u8; 32];
    let cosigner = [2u8; 32];
    let exit = [3u8; 32];
    let identity = |address: &[u8; 32]| solana_owner_identity(address).unwrap();
    let parties = AnonymousParties {
        payer: &payer,
        cosigner: Some(&cosigner),
        exit_destination: AnonymousParties::exit_destination([&exit, &exit].into_iter()).unwrap(),
    };
    assert_eq!(
        parties.identities().unwrap(),
        [identity(&payer), identity(&cosigner), identity(&exit)]
    );
    let absent = AnonymousParties {
        payer: &payer,
        cosigner: Some(&[0u8; 32]),
        exit_destination: AnonymousParties::exit_destination(std::iter::empty()).unwrap(),
    };
    assert_eq!(
        absent.identities().unwrap(),
        [identity(&payer), [0u8; 32], [0u8; 32]]
    );
    assert_eq!(
        AnonymousParties::exit_destination([&exit, &payer].into_iter()),
        Err(ShieldedPoolError::AnonymousExitDestinationsDiffer)
    );
}
