use super::*;
use crate::types::UtxoOwner;

fn note(byte: u8) -> ([u8; 32], KnownUtxo) {
    let utxo = KnownUtxo {
        owner_key: [0xa1; 32],
        owner: UtxoOwner::Keyed {
            nullifier_pk: [byte; 32],
        },
        asset: [byte; 32],
        mint: None,
        amount: u64::from(byte),
        blinding: [byte; 32],
        data_hash: [0; 32],
        ring_data_hash: [0; 32],
        tree_id: 1,
    };
    ([byte; 32], utxo)
}

#[test]
fn the_inputs_under_one_prefix_open_only_when_its_notes_match_their_count() {
    let prefix = InputPrefix::of(&[0x01; 32]).unwrap();
    let notes = || PrefixNotes {
        prefix,
        notes: vec![note(0x10), note(0x20)],
    };
    let opened = |(commitment, utxo)| InputOpening::Opened(ring_input(commitment, utxo));
    assert_eq!(
        notes().assign(2).unwrap(),
        [opened(note(0x10)), opened(note(0x20))]
    );
    assert_eq!(
        notes().assign(1).unwrap(),
        [InputOpening::Ambiguous {
            candidates: vec![[0x10; 32], [0x20; 32]]
        }]
    );
    assert!(matches!(
        notes().assign(3),
        Err(AuditError::UnseenInputPrefix { prefix: unseen }) if unseen == prefix.get()
    ));
}
