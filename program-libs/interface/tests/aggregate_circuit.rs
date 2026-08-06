//! Fail-closed behaviour of the `aggregate_transact` selector.
//!
//! The selector alone names the circuit a batch proved. A selector that
//! resolves to the wrong key, or to a key at all when it should not, lets a
//! batch claim to have proved one rail while the proof verified another.

use zolana_interface::{
    verifying_keys::{AggregateCircuitId, CircuitId, InnerCircuitKind, MAX_AGGREGATE_BATCH},
    N_PUBLIC_SLOTS,
};

const SLOTS: u8 = N_PUBLIC_SLOTS as u8;

fn p256(batch: u8) -> AggregateCircuitId {
    AggregateCircuitId {
        kind: InnerCircuitKind::RingP256,
        num_inputs: 2,
        num_outputs: 3,
        num_public_asset_slots: SLOTS,
        batch,
    }
}

#[test]
fn the_shipped_catalogue_resolves_to_a_key() {
    let selector = p256(2);
    assert!(selector.is_supported());
    assert!(selector.verifying_key().is_some());
}

#[test]
fn a_batch_outside_the_bounds_has_no_key() {
    for batch in [0, 1, MAX_AGGREGATE_BATCH + 1, u8::MAX] {
        let selector = p256(batch);
        assert!(!selector.is_supported(), "batch {batch} was accepted");
        assert!(
            selector.verifying_key().is_none(),
            "batch {batch} has a key"
        );
    }
}

/// Support and a generated key must agree in both directions, or a batch
/// resolves to no key after passing validation.
#[test]
fn support_and_keys_agree() {
    for kind in InnerCircuitKind::ALL {
        for batch in 0..=MAX_AGGREGATE_BATCH + 1 {
            let selector = AggregateCircuitId {
                kind,
                ..p256(batch)
            };
            assert_eq!(
                selector.is_supported(),
                selector.verifying_key().is_some(),
                "{kind:?} batch {batch}"
            );
        }
    }
}

#[test]
fn an_unshipped_rail_has_no_key() {
    let kind = InnerCircuitKind::RingAuthority;
    let selector = AggregateCircuitId { kind, ..p256(2) };
    assert!(!selector.is_supported(), "{kind:?} was accepted");
    assert!(selector.verifying_key().is_none(), "{kind:?} has a key");
}

#[test]
fn an_unshipped_shape_has_no_key() {
    for (n_in, n_out) in [(1, 1), (1, 2), (2, 2), (3, 3), (5, 4), (1, 8)] {
        let selector = AggregateCircuitId {
            num_inputs: n_in,
            num_outputs: n_out,
            ..p256(2)
        };
        assert!(!selector.is_supported(), "{n_in}x{n_out} was accepted");
        assert!(selector.verifying_key().is_none());
    }
}

#[test]
fn a_wrong_public_slot_count_has_no_key() {
    for slots in [0, 1, 2, 4] {
        let selector = AggregateCircuitId {
            num_public_asset_slots: slots,
            ..p256(2)
        };
        assert!(!selector.is_supported(), "{slots} slots were accepted");
    }
}

/// Rail and shape must both match, or the batch settles legs the outer key
/// never proved.
#[test]
fn a_leg_must_match_the_batch_rail_and_shape() {
    let dummy = zolana_interface::verifying_keys::RingP256ProofData {
        bsb22_commitment: zolana_interface::verifying_keys::Bsb22Commitment {
            commitment: [0u8; 32],
            commitment_pok: [0u8; 32],
        },
        default_owner_tag: None,
    };
    let leg_for = |kind: InnerCircuitKind| match kind {
        InnerCircuitKind::ConfidentialEddsa => CircuitId::ConfidentialEddsa(2, 3, SLOTS),
        InnerCircuitKind::RingEddsa => CircuitId::RingEddsa(2, 3, SLOTS),
        InnerCircuitKind::RingAuthority => CircuitId::RingAuthority(2, 3, SLOTS),
        InnerCircuitKind::RingP256 => CircuitId::RingP256(2, 3, SLOTS, dummy),
    };

    for batch_kind in InnerCircuitKind::ALL {
        let batch = AggregateCircuitId {
            kind: batch_kind,
            ..p256(2)
        };
        for leg_kind in InnerCircuitKind::ALL {
            assert_eq!(
                batch.accepts_leg(leg_for(leg_kind)),
                batch_kind == leg_kind,
                "batch {batch_kind:?} leg {leg_kind:?}"
            );
        }
    }

    // Right rail, wrong shape.
    let batch = p256(2);
    assert!(!batch.accepts_leg(CircuitId::RingP256(1, 3, SLOTS, dummy)));
    assert!(!batch.accepts_leg(CircuitId::RingP256(2, 2, SLOTS, dummy)));
    assert!(!batch.accepts_leg(CircuitId::RingP256(2, 3, SLOTS + 1, dummy)));
}

/// A leg keeps the discriminator it would carry alone. Changing these makes
/// every existing proof unaggregatable.
#[test]
fn a_leg_keeps_its_solo_instruction_tag() {
    use zolana_interface::event::tag;

    assert_eq!(
        InnerCircuitKind::ConfidentialEddsa.solo_tag(),
        tag::TRANSACT
    );
    assert_eq!(InnerCircuitKind::RingEddsa.solo_tag(), tag::RING_TRANSACT);
    assert_eq!(InnerCircuitKind::RingP256.solo_tag(), tag::RING_TRANSACT);
    assert_eq!(
        InnerCircuitKind::RingAuthority.solo_tag(),
        tag::RING_AUTHORITY_TRANSACT
    );
}
