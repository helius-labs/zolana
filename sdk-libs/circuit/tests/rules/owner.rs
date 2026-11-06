use spr_circuit::protocol::TokenUtxos;
use spr_circuit::{CircuitErrorKind, Field, SigningPubkey, UtxoOwner, checked};

use crate::support::{SOL, SOLANA_TAG, assert_requirement, utxo};

const OWNER_TAG: (&str, &str, &str) = (
    "owner.rs",
    "impl UtxoOwner {",
    "require_eq(self.key.tag, SOLANA_OWNER_TAG)",
);

fn tagged(tag: u8) -> UtxoOwner {
    UtxoOwner::new(SigningPubkey::new(tag, [7; 32]), Field::one())
}

#[test]
fn the_owner_hash_accepts_exactly_the_solana_tag() {
    for tag in (0..=u8::MAX).filter(|tag| *tag != SOLANA_TAG) {
        let (path, anchor, call) = OWNER_TAG;
        assert_requirement(checked(|| tagged(tag).hash()), path, anchor, call);
    }
    assert!(checked(|| tagged(SOLANA_TAG).hash()).is_ok());
}

#[test]
fn a_token_input_of_another_tag_is_refused_by_the_owner_hash() {
    let (path, anchor, call) = OWNER_TAG;
    assert_requirement(
        checked(|| TokenUtxos::new_mut(&[utxo(tagged(b'X'), SOL, 5)]).map(drop)),
        path,
        anchor,
        call,
    );
}

#[test]
fn decoding_refuses_other_tags_and_noncanonical_nullifier_keys() {
    let mut one = [0; 32];
    one[31] = 1;
    assert_eq!(
        [
            UtxoOwner::from_preimage(b'X', &[7; 32], &one)
                .unwrap_err()
                .kind()
                .clone(),
            UtxoOwner::from_preimage(SOLANA_TAG, &[7; 32], &[0xff; 32])
                .unwrap_err()
                .kind()
                .clone(),
        ],
        [
            CircuitErrorKind::InvalidInput("owner tag is not S"),
            CircuitErrorKind::NonCanonicalField,
        ]
    );
    let owner = UtxoOwner::from_preimage(SOLANA_TAG, &[7; 32], &one).unwrap();
    assert_eq!(owner.preimage(), (SOLANA_TAG, [7; 32], one));
}

#[test]
fn owner_equality_covers_the_key_and_the_nullifier_key() {
    let owner = tagged(SOLANA_TAG);
    let other_key = UtxoOwner::new(SigningPubkey::new(SOLANA_TAG, [8; 32]), Field::one());
    let other_nullifier_key = UtxoOwner::new(*owner.key(), Field::from(2u64));
    assert_eq!(
        [
            owner == tagged(SOLANA_TAG),
            owner == other_key,
            owner == other_nullifier_key
        ],
        [true, false, false]
    );
}
