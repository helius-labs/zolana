use xark::input::{from_fields, leaves, write_fields};
use spr_circuit::{ArrayVec, CircuitErrorKind, Field, Input, protocol::Utxo};

fn encoded<T: Input>(inputs: &T) -> Vec<Field> {
    let mut fields = vec![Field::zero(); T::LEN];
    write_fields(inputs, &mut fields);
    fields
}

#[test]
fn copying_inputs_preserves_the_active_slice_and_canonical_dummy_padding() {
    let utxo = Utxo {
        amount: 42,
        ..Utxo::default()
    };
    let inputs = ArrayVec::<Utxo, 3>::new([utxo]).unwrap();
    let duplicate = inputs;
    let expected = [utxo, Utxo::dummy(), Utxo::dummy()];
    assert_eq!(
        (inputs.len(), duplicate.len(), leaves(&duplicate, "inputs")),
        (1, 1, leaves(&expected, "inputs")),
    );

    let decoded: ArrayVec<Utxo, 3> = from_fields(&encoded(&inputs));
    assert_eq!(
        (decoded.len(), leaves(&decoded, "inputs")),
        (3, leaves(&expected, "inputs")),
    );
}

#[test]
fn zero_capacity_inputs_have_an_empty_encoding_and_reject_any_item() {
    let empty = ArrayVec::<u64, 0>::new([]).unwrap();
    assert_eq!((empty.len(), encoded(&empty)), (0, vec![]));
    assert_eq!(
        ArrayVec::<u64, 0>::new([1]).unwrap_err().kind(),
        &CircuitErrorKind::TooManyItems {
            capacity: 0,
            found: 1
        },
    );
}
