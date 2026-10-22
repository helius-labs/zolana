use zolana_hasher::primitives::BN254_SCALAR_MODULUS_BE;

use super::*;
use crate::encryption::{seal_stream, StreamSchedule};

fn field(byte: u8) -> [u8; 32] {
    let mut field = [byte; 32];
    field[0] = 0;
    field
}

/// Seals raw bytes as the transaction secret, no clamping runs on the way in.
fn envelope(secret: [u8; 32], auditor: &X25519Keypair) -> AuditEnvelope {
    let ephemeral = X25519Keypair::new();
    let mut sealed = secret;
    seal_stream(
        &ephemeral,
        &auditor.pubkey(),
        StreamSchedule::Audit,
        &mut sealed,
    )
    .unwrap();
    AuditEnvelope {
        eph_u: ephemeral.pubkey().u(),
        sealed,
    }
}

/// Byte `at` of the block packed from field `start` sits behind the zero lead byte of its chunk.
fn packed_byte(fields: &mut [[u8; 32]], start: usize, at: usize) -> &mut u8 {
    &mut fields[start + at / 31][1 + at % 31]
}

fn delivered() -> (AuditDisclosure, [bool; 8]) {
    let ring = |byte| DeliveredOutputOpening::Ring {
        owner_key: [byte; 32],
        nullifier_pk: Some(field(byte)),
    };
    let exit = |byte, amount| DeliveredOutputOpening::Exit {
        nullifier_pk: Some(field(byte)),
        asset: field(byte + 1),
        amount,
    };
    let outputs = vec![
        ring(0xb0),
        exit(0x20, 0),
        DeliveredOutputOpening::Dummy,
        ring(0xb3),
        exit(0x24, 40),
        DeliveredOutputOpening::Dummy,
        ring(0xb6),
        ring(0xb7),
    ];
    let exits = [false, true, false, false, true, false, false, false];
    let disclosure = AuditDisclosure::Delivered {
        layout: DeliveredLayout {
            outputs: 8,
            exits: true,
            key_escrow: false,
        },
        seed_out: Some(field(1)),
        outputs,
    };
    (disclosure, exits)
}

fn anonymous_outputs() -> Vec<AnonymousOutputOpening> {
    vec![
        AnonymousOutputOpening::Ring {
            owner_key: [0xb5; 32],
            nullifier_pk: field(0x25),
            recipient_u: [0x15; 32],
        },
        AnonymousOutputOpening::Exit {
            nullifier_pk: field(0x26),
            asset: field(0x27),
            amount: 0,
        },
        AnonymousOutputOpening::Dummy,
        AnonymousOutputOpening::Ring {
            owner_key: [0xa1; 32],
            nullifier_pk: field(0x5a),
            recipient_u: [0x17; 32],
        },
    ]
}

/// The entry key, the transfer spends a default-ring note.
fn anonymous() -> (AuditDisclosure, [bool; 4]) {
    let disclosure = AuditDisclosure::Anonymous(AnonymousDisclosure {
        layout: AnonymousLayout {
            key: AnonymousAuditKey::Entry,
            inputs: 2,
            outputs: 4,
            exits: true,
        },
        seed_out: Some(field(1)),
        sender_key: [0xa1; 32],
        outputs: anonymous_outputs(),
        inputs: AnonymousInputs::Openings {
            sender_nullifier_pk: field(0x5a),
            inputs: vec![
                Some(AnonymousInputOpening {
                    asset: field(0x60),
                    amount: 5000,
                    blinding: field(0x61),
                }),
                None,
            ],
        },
    });
    (disclosure, [false, true, false, false])
}

/// The commitment key over ring notes, no output exits.
fn anonymous_commitment() -> (AuditDisclosure, [bool; 4]) {
    let mut outputs = anonymous_outputs();
    outputs[1] = AnonymousOutputOpening::Dummy;
    let disclosure = AuditDisclosure::Anonymous(AnonymousDisclosure {
        layout: AnonymousLayout {
            key: AnonymousAuditKey::Commitment { class: 4 },
            inputs: 2,
            outputs: 4,
            exits: false,
        },
        seed_out: None,
        sender_key: [0xa1; 32],
        outputs,
        inputs: AnonymousInputs::Commitments(vec![Some(field(0x62)), None]),
    });
    (disclosure, [false; 4])
}

fn packed(key_escrow: bool, data_free: bool) -> (AuditDisclosure, [bool; 3]) {
    let opening = |byte: u8| PackedOutputOpening {
        owner_key: [byte; 32],
        nullifier_pk: (!key_escrow).then(|| field(byte)),
        asset: field(byte + 1),
        amount: u64::from(byte),
        data_hash: if data_free { [0; 32] } else { field(byte + 2) },
        ring_data_hash: [0; 32],
    };
    let disclosure = AuditDisclosure::Packed {
        layout: PackedLayout {
            outputs: 3,
            exits: true,
            key_escrow,
            data_free,
        },
        seed_out: Some(field(1)),
        outputs: vec![Some(opening(0x30)), None, Some(opening(0x40))],
    };
    (disclosure, [false, false, true])
}

fn decode(disclosure: &AuditDisclosure, exits: &[bool], fields: &[[u8; 32]]) -> AuditDisclosure {
    AuditDisclosure::decode(
        PublishedOutputs {
            layout: disclosure.layout(),
            exits,
        },
        fields,
    )
    .unwrap()
}

#[test]
fn the_envelope_opens_to_the_sealed_key_under_a_fresh_ephemeral_key() {
    let auditor = X25519Keypair::new();
    let tx_key = ViewingKey::new();
    let first = AuditEnvelope::seal(&tx_key, &auditor.pubkey()).unwrap();
    let second = AuditEnvelope::seal(&tx_key, &auditor.pubkey()).unwrap();
    assert_ne!(first.envelope.eph_u, second.envelope.eph_u);
    assert_ne!(first.envelope.sealed, second.envelope.sealed);
    for sealed in [first, second] {
        assert_eq!(
            sealed.envelope.open(&auditor).unwrap().pubkey(),
            tx_key.pubkey()
        );
    }
}

/// Every alias clamps onto the published key.
#[test]
fn an_unclamped_envelope_secret_is_refused() {
    let auditor = X25519Keypair::new();
    let key = ViewingKey::from_bytes(&[0x48; 32]);
    let clamped = *key.secret_bytes();
    assert_eq!(
        envelope(clamped, &auditor).open(&auditor).unwrap().pubkey(),
        key.pubkey()
    );
    let mut low_bit = clamped;
    low_bit[0] |= 1;
    let mut high_bit = clamped;
    high_bit[31] |= 0x80;
    let mut cleared = clamped;
    cleared[31] &= !0x40;
    for alias in [low_bit, high_bit, cleared] {
        assert_eq!(ViewingKey::from_bytes(&alias).pubkey(), key.pubkey());
        assert!(matches!(
            envelope(alias, &auditor).open(&auditor),
            Err(AuditError::NonCanonicalViewingKey)
        ));
    }
}

#[test]
fn the_exit_flags_select_each_slot_kind() {
    let (disclosure, exits) = delivered();
    let fields = disclosure.fields().unwrap();
    assert_eq!(fields.len(), disclosure.layout().field_count());
    assert_eq!(decode(&disclosure, &exits, &fields), disclosure);
    let (anonymous, exits) = anonymous();
    let fields = anonymous.fields().unwrap();
    assert_eq!(fields.len(), anonymous.layout().field_count());
    assert_eq!(decode(&anonymous, &exits, &fields), anonymous);
    let mut flipped = exits;
    flipped[1] = false;
    let AuditDisclosure::Anonymous(decoded) = decode(&anonymous, &flipped, &fields) else {
        panic!("anonymous layout");
    };
    assert!(matches!(
        decoded.outputs[1],
        AnonymousOutputOpening::Ring { .. }
    ));
}

#[test]
fn a_disclosure_field_above_the_modulus_is_refused() {
    let (disclosure, exits) = delivered();
    let mut fields = disclosure.fields().unwrap();
    fields[1] = BN254_SCALAR_MODULUS_BE;
    let published = PublishedOutputs {
        layout: disclosure.layout(),
        exits: &exits,
    };
    assert!(matches!(
        AuditDisclosure::decode(published, &fields),
        Err(AuditError::DisclosureField)
    ));
    let pad = DisclosurePad::new(&ViewingKey::new(), &[7; 16]).unwrap();
    assert!(matches!(
        pad.decrypt(&fields),
        Err(AuditError::DisclosureField)
    ));
    assert!(matches!(
        pad.encrypt(&fields),
        Err(AuditError::DisclosureField)
    ));
    let AuditDisclosure::Delivered {
        layout,
        seed_out,
        mut outputs,
    } = disclosure
    else {
        panic!("delivered layout");
    };
    outputs[1] = DeliveredOutputOpening::Exit {
        nullifier_pk: Some(field(0x20)),
        asset: BN254_SCALAR_MODULUS_BE,
        amount: 1,
    };
    assert!(matches!(
        AuditDisclosure::Delivered {
            layout,
            seed_out,
            outputs
        }
        .fields(),
        Err(AuditError::DisclosureField)
    ));
}

#[test]
fn the_pad_masks_every_field_and_unmasks_to_the_plaintext() {
    let (disclosure, _) = delivered();
    let plaintext = disclosure.fields().unwrap();
    let pad = DisclosurePad::new(&ViewingKey::new(), &[7; 16]).unwrap();
    let published = pad.encrypt(&plaintext).unwrap();
    assert!(published
        .iter()
        .zip(&plaintext)
        .all(|(published, plaintext)| published != plaintext));
    assert_eq!(pad.decrypt(&published).unwrap(), plaintext);
    let other = DisclosurePad::new(&ViewingKey::new(), &[7; 16]).unwrap();
    assert_ne!(other.decrypt(&published).unwrap(), plaintext);
}

#[test]
fn nonzero_padding_is_refused() {
    let refused = |disclosure: &AuditDisclosure, exits: &[bool], fields: &[[u8; 32]]| {
        AuditDisclosure::decode(
            PublishedOutputs {
                layout: disclosure.layout(),
                exits,
            },
            fields,
        )
    };
    let (delivered, exits) = delivered();
    let fields = delivered.fields().unwrap();
    // Slot 0 is a ring output, slot 2 a dummy, the block starts behind 9 fields.
    let ring_tail = 32;
    let dummy_byte = 2 * DELIVERED_SLOT_BYTES + 5;
    let block_end = 8 * DELIVERED_SLOT_BYTES;
    for at in [ring_tail, dummy_byte, block_end] {
        let mut padded = fields.clone();
        *packed_byte(&mut padded, 9, at) = 1;
        assert!(matches!(
            refused(&delivered, &exits, &padded),
            Err(AuditError::DisclosurePadding)
        ));
    }
    let mut lead = fields.clone();
    lead[9][0] = 1;
    assert!(matches!(
        refused(&delivered, &exits, &lead),
        Err(AuditError::DisclosurePadding)
    ));

    let (anonymous, exits) = anonymous();
    let fields = anonymous.fields().unwrap();
    // The output block starts behind 6 fields, the amounts behind its 10.
    let exit_padding = DISCLOSURE_SENDER_KEY_BYTES + ANONYMOUS_SLOT_BYTES + KEY_AND_AMOUNT_BYTES;
    let mut padded = fields.clone();
    *packed_byte(&mut padded, 6, exit_padding) = 1;
    // One malformed slot decodes unreadable, the others still open.
    let Ok(AuditDisclosure::Anonymous(decoded)) = refused(&anonymous, &exits, &padded) else {
        panic!("a decoded anonymous disclosure");
    };
    let AuditDisclosure::Anonymous(published) = &anonymous else {
        panic!("an anonymous disclosure");
    };
    let mut expected = published.outputs.clone();
    expected[1] = AnonymousOutputOpening::Unreadable;
    assert_eq!(decoded.outputs, expected);
    let unpublished_amount = 2 * DISCLOSURE_INPUT_AMOUNT_BYTES + 7;
    let mut padded = fields;
    *packed_byte(&mut padded, 16, unpublished_amount) = 1;
    assert!(matches!(
        refused(&anonymous, &exits, &padded),
        Err(AuditError::DisclosurePadding)
    ));
}

#[test]
fn a_disclosure_off_its_layout_is_refused() {
    let (disclosure, exits) = delivered();
    let fields = disclosure.fields().unwrap();
    let layout = disclosure.layout();
    assert!(matches!(
        AuditDisclosure::decode(
            PublishedOutputs {
                layout,
                exits: &exits[1..],
            },
            &fields,
        ),
        Err(AuditError::DisclosureLayout)
    ));
    assert!(matches!(
        AuditDisclosure::decode(
            PublishedOutputs {
                layout,
                exits: &exits,
            },
            &fields[1..],
        ),
        Err(AuditError::DisclosureLayout)
    ));
    let AuditDisclosure::Anonymous(mut anonymous) = anonymous_commitment().0 else {
        panic!("anonymous layout");
    };
    anonymous.layout.key = AnonymousAuditKey::Commitment { class: 1 };
    assert!(matches!(
        AuditDisclosure::Anonymous(anonymous).fields(),
        Err(AuditError::DisclosureLayout)
    ));
}

/// Every flag drops exactly its fields, a disclosure carrying a dropped one is off its layout.
#[test]
fn every_layout_round_trips_through_the_positions_its_flags_fix() {
    for (key_escrow, data_free) in [(false, false), (true, false), (false, true), (true, true)] {
        let (disclosure, exits) = packed(key_escrow, data_free);
        let fields = disclosure.fields().unwrap();
        assert_eq!(fields.len(), disclosure.layout().field_count());
        assert_eq!(decode(&disclosure, &exits, &fields), disclosure);
    }
    let (commitment, exits) = anonymous_commitment();
    let fields = commitment.fields().unwrap();
    assert_eq!(decode(&commitment, &exits, &fields), commitment);
    let AuditDisclosure::Packed {
        layout,
        seed_out,
        mut outputs,
    } = packed(true, true).0
    else {
        panic!("packed layout");
    };
    let mut keyed = outputs.clone();
    keyed[0] = keyed[0].map(|opening| PackedOutputOpening {
        nullifier_pk: Some(field(0x30)),
        ..opening
    });
    outputs[2] = outputs[2].map(|opening| PackedOutputOpening {
        data_hash: field(0x42),
        ..opening
    });
    for outputs in [keyed, outputs] {
        assert!(matches!(
            AuditDisclosure::Packed {
                layout,
                seed_out,
                outputs,
            }
            .fields(),
            Err(AuditError::DisclosureLayout)
        ));
    }
    let AuditDisclosure::Delivered {
        mut layout,
        seed_out,
        outputs,
    } = delivered().0
    else {
        panic!("delivered layout");
    };
    layout.exits = false;
    assert!(matches!(
        AuditDisclosure::Delivered {
            layout,
            seed_out,
            outputs,
        }
        .fields(),
        Err(AuditError::DisclosureLayout)
    ));
}
