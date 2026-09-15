//! Encrypted spend counters share the transfer's audited viewing key.

use thiserror::Error;
use zolana_event::MessageData;
use zolana_keypair::{
    constants::{P256_PUBKEY_LEN, SALT_LEN},
    KeypairError, P256Pubkey, ViewingKey,
};
use zolana_ring_policy::SpendCounters;

/// Counter messages use a nonce domain outside all UTXO output slots.
const SPEND_COUNTERS_SLOT_INDEX: u32 = u32::MAX;

#[derive(Debug, Error)]
pub enum SpendCountersError {
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error("the counters message is malformed")]
    Malformed,
}

#[must_use]
pub struct CountersSeal<'a> {
    pub tx: &'a ViewingKey,
    pub recipient: &'a P256Pubkey,
    pub salt: [u8; SALT_LEN],
    pub counters: &'a SpendCounters,
}

impl CountersSeal<'_> {
    pub fn encrypt(self) -> Result<Vec<u8>, KeypairError> {
        let ciphertext = self.tx.encrypt_slot(
            self.recipient,
            &self.counters.to_bytes(),
            self.salt,
            SPEND_COUNTERS_SLOT_INDEX,
        )?;
        let mut body = Vec::with_capacity(P256_PUBKEY_LEN + ciphertext.len());
        body.extend_from_slice(self.recipient.as_bytes());
        body.extend_from_slice(&ciphertext);
        Ok(body)
    }
}

#[must_use]
pub struct SealedCounters<'a> {
    pub body: &'a [u8],
    pub salt: [u8; SALT_LEN],
}

impl SealedCounters<'_> {
    /// Unauthenticated until the record commitment matches.
    pub fn open(self, tx: &ViewingKey) -> Result<SpendCounters, SpendCountersError> {
        let (recipient, ciphertext) = self
            .body
            .split_at_checked(P256_PUBKEY_LEN)
            .ok_or(SpendCountersError::Malformed)?;
        let recipient = P256Pubkey::from_bytes(
            recipient
                .try_into()
                .map_err(|_| SpendCountersError::Malformed)?,
        )?;
        let bytes = tx.decrypt_slot_ephemeral(
            &recipient,
            ciphertext,
            self.salt,
            SPEND_COUNTERS_SLOT_INDEX,
        )?;
        SpendCounters::from_bytes(&bytes).ok_or(SpendCountersError::Malformed)
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
        let mut counters = SpendCounters::zero(&[[1u8; 32]]).expect("one asset");
        counters.salt = [2u8; 32];
        counters.spent[0] = 4242;
        let body = CountersSeal {
            tx: &tx,
            recipient: &recipient,
            salt,
            counters: &counters,
        }
        .encrypt()
        .expect("encrypt");
        let open = |tx: &ViewingKey, salt| SealedCounters { body: &body, salt }.open(tx).ok();
        assert_eq!(open(&tx, salt), Some(counters));
        // The stream cipher authenticates nothing, the commitment check does.
        assert_ne!(open(&ViewingKey::new(), salt), Some(counters));
        assert_ne!(open(&tx, [8u8; SALT_LEN]), Some(counters));
    }
}
