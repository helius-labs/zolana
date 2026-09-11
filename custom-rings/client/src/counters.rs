//! The counters ride the transfer in a message under the transaction viewing key.

use thiserror::Error;
use zolana_event::MessageData;
use zolana_keypair::{
    constants::{P256_PUBKEY_LEN, SALT_LEN},
    KeypairError, P256Pubkey, ViewingKey,
};
use zolana_ring_policy::{SpendCounters, SPEND_COUNTERS_LEN};

/// Off every output index, the same key never encrypts two slots alike.
pub const SPEND_COUNTERS_SLOT_INDEX: u32 = u32::MAX;

#[derive(Debug, Error)]
pub enum SpendCountersError {
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error("the counters message is malformed")]
    Malformed,
}

/// `recipient_pk(33) || ciphertext`, opened by the transaction key alone.
pub fn encrypt_counters(
    tx: &ViewingKey,
    recipient: &P256Pubkey,
    salt: [u8; SALT_LEN],
    counters: &SpendCounters,
) -> Result<Vec<u8>, KeypairError> {
    let ciphertext = tx.encrypt_slot(
        recipient,
        &counters.to_bytes(),
        salt,
        SPEND_COUNTERS_SLOT_INDEX,
    )?;
    let mut body = Vec::with_capacity(P256_PUBKEY_LEN + ciphertext.len());
    body.extend_from_slice(recipient.as_bytes());
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

pub fn decrypt_counters(
    tx: &ViewingKey,
    body: &[u8],
    salt: [u8; SALT_LEN],
) -> Result<SpendCounters, SpendCountersError> {
    let (recipient, ciphertext) = body
        .split_at_checked(P256_PUBKEY_LEN)
        .ok_or(SpendCountersError::Malformed)?;
    let recipient = P256Pubkey::from_bytes(
        recipient
            .try_into()
            .map_err(|_| SpendCountersError::Malformed)?,
    )?;
    let bytes =
        tx.decrypt_slot_ephemeral(&recipient, ciphertext, salt, SPEND_COUNTERS_SLOT_INDEX)?;
    if bytes.len() != SPEND_COUNTERS_LEN {
        return Err(SpendCountersError::Malformed);
    }
    SpendCounters::from_bytes(&bytes).ok_or(SpendCountersError::Malformed)
}

pub fn counters_message(namespace: [u8; 32], body: Vec<u8>) -> MessageData {
    MessageData {
        view_tag: namespace,
        data: body,
    }
}

pub fn find_counters_message<'a>(
    messages: &'a [MessageData],
    namespace: &[u8; 32],
) -> Option<&'a MessageData> {
    messages
        .iter()
        .find(|message| &message.view_tag == namespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counters_round_trip_under_the_transaction_key() {
        let tx = ViewingKey::new();
        let recipient = ViewingKey::new().pubkey();
        let salt = [7u8; SALT_LEN];
        let mut counters = SpendCounters::zero(&[[1u8; 32]]);
        counters.salt = [2u8; 32];
        counters.spent[0] = 4242;
        let body = encrypt_counters(&tx, &recipient, salt, &counters).expect("encrypt");
        assert_eq!(
            decrypt_counters(&tx, &body, salt).expect("decrypt"),
            counters
        );
        // The stream cipher authenticates nothing, the commitment check does.
        assert_ne!(
            decrypt_counters(&ViewingKey::new(), &body, salt).ok(),
            Some(counters)
        );
        assert_ne!(
            decrypt_counters(&tx, &body, [8u8; SALT_LEN]).ok(),
            Some(counters)
        );
    }
}
