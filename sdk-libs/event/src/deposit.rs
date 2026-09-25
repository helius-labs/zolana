use borsh::BorshDeserialize;
use zolana_event::{
    EncryptedRingDepositOutput, GeneralEvent, OutputDataEncoding, ProoflessOutput,
    ENCRYPTED_RING_DEPOSIT_SCHEME,
};

use crate::EventDecodeError;

/// Inverse of [`zolana_event::encode_output_data`]: a proofless deposit output payload.
pub fn decode_output_data(data: &[u8]) -> Result<ProoflessOutput, EventDecodeError> {
    let OutputDataEncoding::Plaintext(blob) = OutputDataEncoding::try_from_slice(data)
        .map_err(|_| EventDecodeError::InvalidOutputData)?
    else {
        return Err(EventDecodeError::InvalidOutputData);
    };
    let (&scheme, body) = blob
        .split_first()
        .ok_or(EventDecodeError::InvalidOutputData)?;
    if scheme != 0 {
        return Err(EventDecodeError::InvalidOutputData);
    }
    ProoflessOutput::try_from_slice(body).map_err(|_| EventDecodeError::InvalidOutputData)
}

/// Inverse of [`zolana_event::encode_encrypted_ring_deposit_output`].
pub fn decode_encrypted_ring_deposit_output_data(
    data: &[u8],
) -> Result<EncryptedRingDepositOutput, EventDecodeError> {
    let OutputDataEncoding::Encrypted(blob) = OutputDataEncoding::try_from_slice(data)
        .map_err(|_| EventDecodeError::InvalidOutputData)?
    else {
        return Err(EventDecodeError::InvalidOutputData);
    };
    let (&scheme, body) = blob
        .split_first()
        .ok_or(EventDecodeError::InvalidOutputData)?;
    if scheme != ENCRYPTED_RING_DEPOSIT_SCHEME {
        return Err(EventDecodeError::InvalidOutputData);
    }
    EncryptedRingDepositOutput::try_from_slice(body)
        .map_err(|_| EventDecodeError::InvalidOutputData)
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
