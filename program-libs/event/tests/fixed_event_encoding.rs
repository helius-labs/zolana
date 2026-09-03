//! The stack-array encoders must agree with Borsh byte for byte.
//!
//! The program writes these events without allocating, while indexers decode
//! them with the Borsh derive. If the two ever disagree the event stream is
//! silently misread, so pin the agreement rather than assuming it.

use zolana_event::{
    encode_merge_event, encode_transact_event, tag, EventKind, MergeEvent, TransactEvent,
};

#[test]
fn transact_event_stack_encoding_matches_borsh() {
    let event = TransactEvent {
        first_input_queue_seq: 0x0102_0304_0506_0708,
        first_output_leaf_index: 0x1112_1314_1516_1718,
    };
    let encoded = encode_transact_event(&event);

    assert_eq!(encoded[0], tag::EMIT_EVENT);
    assert_eq!(encoded[1], EventKind::Transact as u8);
    assert_eq!(&encoded[2..], borsh::to_vec(&event).unwrap().as_slice());
    assert_eq!(encoded.len(), 2 + TransactEvent::LEN);
}

#[test]
fn merge_event_stack_encoding_matches_borsh() {
    let event = MergeEvent {
        first_input_queue_seq: 7,
        first_output_leaf_index: 9,
        output_view_tag: [0xab; 32],
    };
    let encoded = encode_merge_event(&event);

    assert_eq!(encoded[0], tag::EMIT_EVENT);
    assert_eq!(encoded[1], EventKind::Merge as u8);
    assert_eq!(&encoded[2..], borsh::to_vec(&event).unwrap().as_slice());
    assert_eq!(encoded.len(), 2 + MergeEvent::LEN);
}
