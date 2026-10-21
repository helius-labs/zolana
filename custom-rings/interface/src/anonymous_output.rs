//! The ring output body length and the stream schedule it shares with the auditor envelope.

pub use zolana_event::RING_DELIVERED_BODY_LEN;

/// The stream schedule tag the recipient body shares with the auditor envelope, the Go `auditEncInfo`.
pub const AUDIT_STREAM_INFO: &[u8; 10] = b"CRING/adt1";
