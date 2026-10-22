//! `shape_keyed` names exactly the shapes `test-vectors/ring_keyed_shapes.json` lists per rail.

use custom_ring_interface::RingRail;
use custom_ring_sdk::shape_keyed;
use zolana_client::SPP_SUPPORTED_SHAPES;

#[test]
fn every_rail_keys_the_shapes_the_shared_vector_lists() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../../test-vectors/ring_keyed_shapes.json")).unwrap();
    for (rail, list) in [
        (RingRail::Confidential, "confidential_ring"),
        (RingRail::Anonymous, "anonymous_ring"),
        (RingRail::Delegate, "ring_authority"),
    ] {
        let pinned: Vec<[usize; 2]> = serde_json::from_value(vector[list].clone()).unwrap();
        let keyed: Vec<[usize; 2]> = SPP_SUPPORTED_SHAPES
            .into_iter()
            .filter(|shape| shape_keyed(rail, *shape))
            .map(|shape| [shape.n_inputs(), shape.n_outputs()])
            .collect();
        assert_eq!(keyed, pinned, "{list}");
    }
}
