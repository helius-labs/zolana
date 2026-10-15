use zolana_interface::{
    shape::{Shape, RING_AUTHORITY_WIDTHS, RING_ED25519_SHAPES, SPP_SUPPORTED_SHAPES},
    verifying_keys::{Bsb22Commitment, CacheAccess, CircuitId, OutputOwnerMode, RingP256ProofData},
    N_PUBLIC_SLOTS,
};

const CACHE: CacheAccess = CacheAccess {
    read_bitmap: 1,
    write_slots: CacheAccess::NO_WRITES,
};

const PUBLIC_ASSET_SLOTS: u8 = N_PUBLIC_SLOTS as u8;
const COMMITMENT: Bsb22Commitment = Bsb22Commitment {
    commitment: [4u8; 32],
    commitment_pok: [5u8; 32],
};
const P256_PROOF_DATA: RingP256ProofData = RingP256ProofData {
    bsb22_commitment: COMMITMENT,
    default_owner_tag: None,
};

#[test]
fn accessors_and_behavior_match_variants() {
    let cached = CircuitId::ConfidentialEddsaCached(2, 3, 3, CACHE);
    assert_eq!(cached.shape(), (2, 3, 3));
    assert!(cached.is_confidential());
    assert!(!cached.is_ring());
    assert!(cached.requires_input_signatures());
    assert_eq!(cached.output_owner_mode(), OutputOwnerMode::All);
    assert_eq!(cached.cache_access(), Some(CACHE));

    let ring_cached = CircuitId::RingEddsaCached(2, 3, 3, CACHE);
    assert!(ring_cached.is_ring());
    assert!(!ring_cached.is_p256());
    assert_eq!(ring_cached.cache_access(), Some(CACHE));
    assert_eq!(
        ring_cached.output_owner_mode(),
        OutputOwnerMode::ConfidentialMarked
    );

    let p256_cached = CircuitId::RingP256Cached(2, 3, 3, P256_PROOF_DATA, CACHE);
    assert!(p256_cached.is_ring());
    assert!(p256_cached.is_p256());
    assert_eq!(p256_cached.cache_access(), Some(CACHE));
    assert_eq!(p256_cached.bsb22_commitment(), Some(&COMMITMENT));
    assert_eq!(
        p256_cached.output_owner_mode(),
        OutputOwnerMode::ConfidentialMarked
    );

    // A cached selector is its rail plus a selection, and nothing else.
    for (rail, twin) in [
        (
            CircuitId::ConfidentialEddsa(2, 3, 3),
            CircuitId::ConfidentialEddsaCached(2, 3, 3, CACHE),
        ),
        (
            CircuitId::RingEddsa(2, 3, 3),
            CircuitId::RingEddsaCached(2, 3, 3, CACHE),
        ),
        (
            CircuitId::RingP256(2, 3, 3, P256_PROOF_DATA),
            CircuitId::RingP256Cached(2, 3, 3, P256_PROOF_DATA, CACHE),
        ),
    ] {
        assert_eq!(twin.uncached(), rail);
        assert_eq!(twin.shape(), rail.shape());
        assert_eq!(twin.output_owner_mode(), rail.output_owner_mode());
        assert_eq!(twin.is_supported(), rail.is_supported());
        assert_eq!(twin.is_ring(), rail.is_ring());
        assert_eq!(twin.is_p256(), rail.is_p256());
        assert_eq!(twin.is_confidential(), rail.is_confidential());
        assert!(rail.cache_access().is_none());
    }
    assert!(CircuitId::RingAuthority(2, 2, 3).cache_access().is_none());
    let confidential = CircuitId::ConfidentialEddsa(2, 3, 3);
    assert_eq!(confidential.shape(), (2, 3, 3));
    assert!(confidential.is_confidential());
    assert!(!confidential.is_ring());
    assert!(confidential.requires_input_signatures());
    assert_eq!(confidential.output_owner_mode(), OutputOwnerMode::All);

    let ring = CircuitId::RingEddsa(1, 8, 3);
    assert!(ring.is_ring());
    assert!(ring.is_confidential());
    assert!(!ring.is_authority());
    assert!(ring.requires_input_signatures());
    assert_eq!(
        ring.output_owner_mode(),
        OutputOwnerMode::ConfidentialMarked
    );

    let authority = CircuitId::RingAuthority(4, 4, 3);
    assert!(authority.is_ring());
    assert!(authority.is_authority());
    assert!(!authority.requires_input_signatures());
    assert_eq!(authority.output_owner_mode(), OutputOwnerMode::None);

    let p256 = CircuitId::RingP256(2, 3, 3, P256_PROOF_DATA);
    assert_eq!(p256.shape(), (2, 3, 3));
    assert!(p256.is_ring());
    assert!(p256.is_confidential());
    assert!(p256.is_p256());
    assert!(p256.requires_input_signatures());
    assert_eq!(
        p256.output_owner_mode(),
        OutputOwnerMode::ConfidentialMarked
    );
    assert_eq!(p256.bsb22_commitment(), Some(&COMMITMENT));
    assert_eq!(p256.default_p256_owner_tag(), None);
    assert!(p256.signs_message_digest());
    assert!(!ring.signs_message_digest());

    let ed25519 = CircuitId::RingEd25519(2, 4, 3, COMMITMENT);
    assert_eq!(ed25519.shape(), (2, 4, 3));
    assert!(ed25519.is_ring());
    assert!(ed25519.is_confidential());
    assert!(!ed25519.is_p256());
    assert!(!ed25519.is_authority());
    assert!(ed25519.signs_message_digest());
    assert!(ed25519.requires_input_signatures());
    assert_eq!(ed25519.uncached(), ed25519);
    assert!(ed25519.cache_access().is_none());
    assert_eq!(ed25519.bsb22_commitment(), Some(&COMMITMENT));
    assert_eq!(ed25519.default_p256_owner_tag(), None);
    assert_eq!(
        ed25519.output_owner_mode(),
        OutputOwnerMode::ConfidentialMarked
    );
}

/// Appending a selector moves no existing tag. Each variant keeps its
/// declaration index, and RingEd25519 carries only its BSB22 commitment.
#[test]
fn circuit_id_tags_are_stable() {
    let selectors = [
        CircuitId::ConfidentialEddsa(2, 2, 3),
        CircuitId::RingEddsa(2, 2, 3),
        CircuitId::RingAuthority(2, 2, 3),
        CircuitId::RingP256(2, 2, 3, P256_PROOF_DATA),
        CircuitId::ConfidentialEddsaCached(2, 2, 3, CACHE),
        CircuitId::RingEddsaCached(2, 2, 3, CACHE),
        CircuitId::RingP256Cached(2, 2, 3, P256_PROOF_DATA, CACHE),
        CircuitId::RingEd25519(2, 2, 3, COMMITMENT),
    ];
    for (tag, circuit) in selectors.into_iter().enumerate() {
        let bytes = wincode::serialize(&circuit).unwrap();
        assert_eq!(bytes[..2], (tag as u16).to_le_bytes(), "{circuit:?}");
    }
    let bytes = wincode::serialize(&CircuitId::RingEd25519(2, 4, 3, COMMITMENT)).unwrap();
    let mut expected = 7u16.to_le_bytes().to_vec();
    expected.extend_from_slice(&[2, 4, 3]);
    expected.extend_from_slice(&COMMITMENT.commitment);
    expected.extend_from_slice(&COMMITMENT.commitment_pok);
    assert_eq!(bytes, expected);
    let mut unknown = bytes;
    unknown[0] = 8;
    assert!(wincode::deserialize_exact::<CircuitId>(&unknown).is_err());
}

#[test]
fn supported_shapes_are_fail_closed() {
    assert!(CircuitId::ConfidentialEddsa(2, 4, 3).is_supported());
    assert!(CircuitId::RingEddsa(1, 8, 3).is_supported());
    assert!(CircuitId::RingP256(2, 4, 3, P256_PROOF_DATA).is_supported());
    assert!(CircuitId::RingAuthority(4, 4, 3).is_supported());
    assert!(CircuitId::ConfidentialEddsa(49, 2, 3).is_supported());
    assert!(CircuitId::RingEddsa(49, 2, 3).is_supported());
    assert!(CircuitId::RingP256(49, 2, 3, P256_PROOF_DATA).is_supported());
    assert!(CircuitId::ConfidentialEddsa(8, 16, 3).is_supported());
    assert!(!CircuitId::RingAuthority(49, 2, 3).is_supported());
    assert!(!CircuitId::ConfidentialEddsa(49, 4, 3).is_supported());
    assert!(!CircuitId::ConfidentialEddsa(51, 2, 3).is_supported());
    assert!(!CircuitId::ConfidentialEddsa(6, 6, 3).is_supported());
    assert!(!CircuitId::RingEddsa(2, 4, 2).is_supported());
    assert!(!CircuitId::RingAuthority(2, 4, 3).is_supported());
    for (n_inputs, n_outputs) in [(1, 1), (2, 3), (3, 3), (4, 3), (5, 3), (36, 2)] {
        assert!(
            !CircuitId::ConfidentialEddsa(n_inputs, n_outputs, 3).is_supported(),
            "{n_inputs}x{n_outputs} was removed"
        );
    }
    for n in [1, 3] {
        assert!(!CircuitId::RingAuthority(n, n, 3).is_supported(), "{n}x{n}");
    }
}

#[test]
fn every_supported_shape_is_supported_on_every_owner_signed_rail() {
    for shape in SPP_SUPPORTED_SHAPES {
        let n_inputs = u8::try_from(shape.n_inputs()).expect("fits u8");
        let n_outputs = u8::try_from(shape.n_outputs()).expect("fits u8");
        for circuit in [
            CircuitId::ConfidentialEddsa(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS),
            CircuitId::ConfidentialEddsaCached(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, CACHE),
            CircuitId::RingEddsa(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS),
            CircuitId::RingP256(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, P256_PROOF_DATA),
        ] {
            assert!(circuit.is_supported(), "{circuit:?}");
        }
    }
}

/// RingEd25519 is supported only on its own shapes, and only once their keys
/// are generated into this crate.
#[cfg(feature = "verifying-keys")]
#[test]
fn ring_ed25519_is_supported_only_on_its_shapes_with_keys() {
    assert_eq!(
        RING_ED25519_SHAPES,
        [
            Shape::IN2_OUT2,
            Shape::IN2_OUT4,
            Shape::IN3_OUT4,
            Shape::IN4_OUT2
        ]
    );
    for shape in SPP_SUPPORTED_SHAPES {
        let n_inputs = u8::try_from(shape.n_inputs()).expect("fits u8");
        let n_outputs = u8::try_from(shape.n_outputs()).expect("fits u8");
        let circuit = CircuitId::RingEd25519(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, COMMITMENT);
        let listed = RING_ED25519_SHAPES.contains(&shape);
        assert_eq!(shape.is_ring_ed25519(), listed, "{circuit:?}");
        assert_eq!(
            circuit.is_supported(),
            listed && circuit.verifying_key().is_some(),
            "{circuit:?}"
        );
        assert!(listed || circuit.verifying_key().is_none(), "{circuit:?}");
    }
    assert!(!CircuitId::RingEd25519(2, 2, PUBLIC_ASSET_SLOTS - 1, COMMITMENT).is_supported());
}

#[cfg(feature = "verifying-keys")]
#[test]
fn every_supported_shape_resolves_exactly_one_key() {
    for shape in SPP_SUPPORTED_SHAPES {
        let n_inputs = u8::try_from(shape.n_inputs()).expect("fits u8");
        let n_outputs = u8::try_from(shape.n_outputs()).expect("fits u8");
        for circuit in [
            CircuitId::ConfidentialEddsa(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS),
            CircuitId::ConfidentialEddsaCached(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, CACHE),
            CircuitId::RingEddsa(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS),
            CircuitId::RingEddsaCached(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, CACHE),
            CircuitId::RingP256(n_inputs, n_outputs, PUBLIC_ASSET_SLOTS, P256_PROOF_DATA),
            CircuitId::RingP256Cached(
                n_inputs,
                n_outputs,
                PUBLIC_ASSET_SLOTS,
                P256_PROOF_DATA,
                CACHE,
            ),
        ] {
            assert!(circuit.is_supported());
            assert!(circuit.verifying_key().is_some());
            // The cache publishes values, not a circuit: a cached spend resolves
            // its rail's own key, so no cached key is generated into this crate.
            let rail = circuit.uncached();
            assert!(core::ptr::eq(
                circuit.verifying_key().expect("cached key"),
                rail.verifying_key().expect("rail key"),
            ));
        }
    }
    for width in RING_AUTHORITY_WIDTHS {
        let n = u8::try_from(width).expect("fits u8");
        let circuit = CircuitId::RingAuthority(n, n, PUBLIC_ASSET_SLOTS);
        assert!(circuit.is_supported());
        assert!(circuit.verifying_key().is_some());
    }
    assert!(CircuitId::ConfidentialEddsa(2, 3, PUBLIC_ASSET_SLOTS - 1)
        .verifying_key()
        .is_none());
    assert!(CircuitId::RingAuthority(49, 2, PUBLIC_ASSET_SLOTS)
        .verifying_key()
        .is_none());
}
