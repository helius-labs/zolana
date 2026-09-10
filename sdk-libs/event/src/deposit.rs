use zolana_event::{decode_output_data, EventDecodeError, GeneralEvent, ProoflessOutput};

pub fn proofless_output(event: &GeneralEvent) -> Result<ProoflessOutput, EventDecodeError> {
    let output = event
        .outputs
        .first()
        .ok_or(EventDecodeError::MissingOutput)?;
    let proofless = decode_output_data(&output.data)?;
    require_deposit(event)?;
    Ok(proofless)
}

/// Decode every output of a batched proofless `deposit` event, in slot order.
pub fn proofless_outputs(event: &GeneralEvent) -> Result<Vec<ProoflessOutput>, EventDecodeError> {
    if event.outputs.is_empty() {
        return Err(EventDecodeError::MissingOutput);
    }
    require_deposit(event)?;
    event
        .outputs
        .iter()
        .map(|output| decode_output_data(&output.data))
        .collect()
}

fn require_deposit(event: &GeneralEvent) -> Result<(), EventDecodeError> {
    if event.spl_transfers.is_empty()
        || !event
            .spl_transfers
            .iter()
            .all(|transfer| transfer.is_deposit)
    {
        return Err(EventDecodeError::MissingDepositSplTransfer);
    }
    Ok(())
}
