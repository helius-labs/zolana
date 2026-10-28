#![cfg(feature = "serde")]

use serde_json::json;
use spr_circuit::{Field, UtxoOwner};

#[test]
fn owner_wire_preserves_the_committed_preimage() {
    let mut nullifier = [0u8; 32];
    nullifier[31] = 1;
    let owner = UtxoOwner::from_preimage(b'S', &[7; 32], &nullifier).unwrap();
    let expected = json!({"key":{"tag":b'S',"bytes":vec![7;32]},"nullifierPk":"1"});
    assert_eq!(serde_json::to_value(owner).unwrap(), expected);
    let decoded: UtxoOwner = serde_json::from_value(expected).unwrap();
    assert_eq!(decoded.preimage(), owner.preimage());
}

#[test]
fn owner_wire_rejects_unsupported_tags_and_modular_aliases() {
    for (tag, value) in [
        (b'X', "0"),
        (
            b'S',
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        ),
    ] {
        let value = json!({"key":{"tag":tag,"bytes":vec![0;32]},"nullifierPk":value});
        assert!(serde_json::from_value::<UtxoOwner>(value).is_err());
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Scalar {
    #[serde(with = "spr_circuit::field_serde")]
    value: Field,
}

#[test]
fn scalar_wire_uses_the_canonical_field_value() {
    let encoded = serde_json::to_value(Scalar {
        value: Field::from(42u64),
    })
    .unwrap();
    assert_eq!(encoded, json!({"value":"42"}));
    let decoded: Scalar = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.value, Field::from(42u64));
}

#[test]
fn scalar_wire_rejects_alternate_encodings() {
    for value in ["01", " 1", "1 ", "0x1", "+1", "-1", ""] {
        assert!(serde_json::from_value::<Scalar>(json!({"value":value})).is_err());
    }
}
