//! The anonymous classes are the ones `test-vectors/ring_keyed_shapes.json` lists, the Go base
//! keys test reads the same file.

use custom_ring_interface::{
    AnonymousSpend, ANONYMOUS_AUDIT_CLASSES, ANONYMOUS_ENTRY_CLASS, ANONYMOUS_ENTRY_OUTPUTS,
};
use zolana_interface::shape::SPP_SUPPORTED_SHAPES;

fn vector() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../test-vectors/ring_keyed_shapes.json")).unwrap()
}

#[test]
fn the_anonymous_classes_are_the_shared_vector() {
    let vector = vector();
    let classes: Vec<(usize, Vec<usize>)> = ANONYMOUS_AUDIT_CLASSES
        .iter()
        .map(|(outputs, classes)| (*outputs, classes.to_vec()))
        .collect();
    let pinned: Vec<(usize, Vec<usize>)> = vector["anonymous_audit_classes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                serde_json::from_value(row["outputs"].clone()).unwrap(),
                serde_json::from_value(row["classes"].clone()).unwrap(),
            )
        })
        .collect();
    assert_eq!(classes, pinned);
    let entry = &vector["anonymous_entry"];
    assert_eq!(entry["class"], ANONYMOUS_ENTRY_CLASS);
    assert_eq!(
        serde_json::from_value::<Vec<usize>>(entry["outputs"].clone()).unwrap(),
        ANONYMOUS_ENTRY_OUTPUTS
    );
}

/// The anonymous rail publishes every input of its shape, so a class serves a shape's whole input count.
#[test]
fn a_class_serves_exactly_the_listed_anonymous_shapes() {
    let pinned: Vec<[usize; 2]> =
        serde_json::from_value(vector()["anonymous_ring"].clone()).unwrap();
    let served: Vec<[usize; 2]> = SPP_SUPPORTED_SHAPES
        .into_iter()
        .filter(|shape| {
            AnonymousSpend {
                inputs: shape.n_inputs(),
                outputs: shape.n_outputs(),
                spends_default_ring: false,
            }
            .audit_key()
            .is_some()
        })
        .map(|shape| [shape.n_inputs(), shape.n_outputs()])
        .collect();
    assert_eq!(served, pinned);
}
