//! Spend counters ride the transfer's audited viewing key.

use zolana_event::MessageData;
use zolana_keypair::{constants::SALT_LEN, P256Pubkey, ViewingKey};
use zolana_ring_policy::{SpendCounters, SPEND_COUNTERS_BODY_LEN};

use crate::AuditError;

/// A nonce domain outside every output slot index.
const SPEND_COUNTERS_SLOT_INDEX: u32 = u32::MAX;

/// `recipient || ciphertext`, the body of the counters message.
pub fn seal_counters(
    tx: &ViewingKey,
    recipient: &P256Pubkey,
    salt: [u8; SALT_LEN],
    counters: &SpendCounters,
) -> Result<Vec<u8>, AuditError> {
    let ciphertext = tx.encrypt_slot(
        recipient,
        &counters.to_bytes(),
        salt,
        SPEND_COUNTERS_SLOT_INDEX,
    )?;
    Ok([recipient.as_bytes().as_slice(), &ciphertext].concat())
}

/// Unauthenticated until the record commitment matches.
pub fn open_counters(
    body: &[u8],
    salt: [u8; SALT_LEN],
    tx: &ViewingKey,
) -> Result<SpendCounters, AuditError> {
    let recipient = tx.pubkey();
    let ciphertext = body
        .strip_prefix(recipient.as_bytes().as_slice())
        .filter(|_| body.len() == SPEND_COUNTERS_BODY_LEN)
        .ok_or(AuditError::MalformedCounters)?;
    let bytes =
        tx.decrypt_slot_ephemeral(&recipient, ciphertext, salt, SPEND_COUNTERS_SLOT_INDEX)?;
    SpendCounters::from_bytes(&bytes).ok_or(AuditError::MalformedCounters)
}

/// The one message tagged by the bare namespace, `None` without one.
pub fn find_counters_message<'a>(
    messages: &'a [MessageData],
    namespace: &[u8; 32],
) -> Result<Option<&'a MessageData>, AuditError> {
    let mut tagged = messages
        .iter()
        .filter(|message| &message.view_tag == namespace);
    let message = tagged.next();
    match tagged.next() {
        Some(_) => Err(AuditError::MalformedCounters),
        None => Ok(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counters_round_trip_under_the_transaction_key() {
        let tx = ViewingKey::new();
        let salt = [7u8; SALT_LEN];
        let mut counters = SpendCounters::zero(&[[1u8; 32]]).expect("one asset");
        counters.salt = [2u8; 32];
        counters.spent[0] = 4242;
        let body = seal_counters(&tx, &tx.pubkey(), salt, &counters).expect("encrypt");
        let open = |tx: &ViewingKey, salt| open_counters(&body, salt, tx).ok();
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
        let body = seal_counters(&tx, &tx.pubkey(), salt, &counters).unwrap();
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
            assert!(open_counters(changed, salt, &tx).is_err());
        }
        let message = MessageData {
            view_tag: [7; 32],
            data: body,
        };
        assert!(find_counters_message(&[message.clone(), message], &[7; 32]).is_err());
    }
}
