//! Encrypted spend counters share the transfer's audited viewing key.

use thiserror::Error;
use zolana_event::MessageData;
use zolana_keypair::{
    constants::{P256_PUBKEY_LEN, SALT_LEN},
    KeypairError, P256Pubkey, ViewingKey,
};
use zolana_ring_policy::{SpendCounters, SPEND_COUNTERS_BODY_LEN};

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
        if self.body.len() != SPEND_COUNTERS_BODY_LEN
            || !self.body.starts_with(tx.pubkey().as_bytes())
        {
            return Err(SpendCountersError::Malformed);
        }
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
) -> Result<Option<&'a MessageData>, SpendCountersError> {
    let mut matches = messages
        .iter()
        .filter(|message| &message.view_tag == namespace);
    let message = matches.next();
    if matches.next().is_some() {
        return Err(SpendCountersError::Malformed);
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counters_round_trip_under_the_transaction_key() {
        let tx = ViewingKey::new();
        let recipient = tx.pubkey();
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
    #[test]
    fn counter_disclosure_matches_the_circuit_and_typescript() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/spend-counters.json"))
                .unwrap();
        let hex_field = |name: &str| hex::decode(vector[name].as_str().unwrap()).unwrap();
        let tx = ViewingKey::from_bytes(&hex_field("secret").try_into().unwrap()).unwrap();
        let salt = hex_field("transactionSalt").try_into().unwrap();
        let mut counters = SpendCounters::EMPTY;
        counters.salt = hex_field("counterSalt").try_into().unwrap();
        counters.assets[0][31] = 1;
        counters.assets[1][31] = 2;
        counters.spent[0] = 42;
        counters.spent[1] = u64::MAX;
        let body = CountersSeal {
            tx: &tx,
            recipient: &tx.pubkey(),
            salt,
            counters: &counters,
        }
        .encrypt()
        .unwrap();
        assert_eq!(body, hex_field("body"));
        let hash = zolana_ring_policy::spend_counters_disclosure_hash(
            &salt,
            body.as_slice().try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(hash).trim_start_matches('0'),
            vector["hash"].as_str().unwrap()
        );
        for changed in [&body[1..], &body[..body.len() - 1]] {
            assert!(SealedCounters {
                body: changed,
                salt
            }
            .open(&tx)
            .is_err());
        }
        let message = MessageData {
            view_tag: [7; 32],
            data: body,
        };
        assert!(find_counters_message(&[message.clone(), message], &[7; 32]).is_err());
    }
}
