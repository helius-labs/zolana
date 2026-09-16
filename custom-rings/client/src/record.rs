use thiserror::Error;
use zolana_event::MessageData;
use zolana_interface::event::confidential_encrypted_output_body;
use zolana_ring_policy::{spend_record_message_tag, SpendRecord};
use zolana_transaction::OutputSlot;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("malformed spend record carrier")]
pub struct MalformedRecordCarrier;

/// A registration publishes its record in the slot, a successor in one tagged message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordCarrier {
    Inline(SpendRecord),
    Sidecar(SpendRecord),
}

impl RecordCarrier {
    /// `Ok(None)` for a slot carrying no record.
    pub fn decode(
        slot: &OutputSlot,
        messages: &[MessageData],
    ) -> Result<Option<Self>, MalformedRecordCarrier> {
        if let Some(record) = SpendRecord::from_output_data(&slot.payload) {
            return Ok((record.version == 0).then_some(Self::Inline(record)));
        }
        let tag = spend_record_message_tag(&slot.view_tag).map_err(|_| MalformedRecordCarrier)?;
        let mut tagged = messages.iter().filter(|message| message.view_tag == tag);
        let Some(message) = tagged.next() else {
            return Ok(None);
        };
        if tagged.next().is_some() || confidential_encrypted_output_body(&slot.payload).is_none() {
            return Err(MalformedRecordCarrier);
        }
        SpendRecord::from_output_data(&message.data)
            .map(|record| Some(Self::Sidecar(record)))
            .ok_or(MalformedRecordCarrier)
    }

    pub fn record(self) -> SpendRecord {
        match self {
            Self::Inline(record) | Self::Sidecar(record) => record,
        }
    }
}
