//! Deposits publish asset, amount and ring in the clear, only the blinding and memo stay sealed.

use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_event::{EncryptedRingDepositOutput, OutputDataEncoding, ENCRYPTED_RING_DEPOSIT_SCHEME};

/// One deposit slot of a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingDeposit {
    /// The note's owner tag, the account the value was shielded for.
    pub depositor: [u8; 32],
    pub asset: Address,
    pub amount: u64,
}

/// The deposits of `ring` in one indexed transaction, in slot order.
pub fn ring_deposits_in(
    slots: impl IntoIterator<Item = ([u8; 32], Vec<u8>)>,
    ring: Address,
) -> Vec<RingDeposit> {
    slots
        .into_iter()
        .filter_map(|(view_tag, payload)| deposit_of(&view_tag, &payload, ring))
        .collect()
}

fn deposit_of(view_tag: &[u8; 32], payload: &[u8], ring: Address) -> Option<RingDeposit> {
    let OutputDataEncoding::Encrypted(blob) = OutputDataEncoding::try_from_slice(payload).ok()?
    else {
        return None;
    };
    let (&ENCRYPTED_RING_DEPOSIT_SCHEME, body) = blob.split_first()? else {
        return None;
    };
    let output = EncryptedRingDepositOutput::try_from_slice(body).ok()?;
    (output.ring_program_id == ring.to_bytes()).then(|| RingDeposit {
        depositor: *view_tag,
        asset: Address::new_from_array(output.asset),
        amount: output.amount,
    })
}

#[cfg(test)]
mod tests {
    use custom_ring_interface::RingDepositAuditCapsule;
    use zolana_keypair::ViewingKey;

    use crate::deposit_payload;
    use zolana_transaction::serialization::ring_deposit::RingDepositPlaintext;

    #[test]
    fn recipient_opens_plain_and_auditor_wrapped_ciphertexts() {
        let recipient = ViewingKey::new();
        let plaintext = RingDepositPlaintext {
            blinding: [7; 32],
            utxo_data: Some(vec![1, 2]),
            memo: Some(vec![3]),
            ring_data: vec![4],
        };
        let mut encrypted = plaintext.encrypt(&recipient.pubkey()).unwrap();
        assert_eq!(
            RingDepositPlaintext::decrypt(&encrypted, &recipient).unwrap(),
            plaintext
        );
        assert_eq!(deposit_payload(&encrypted.ciphertext).unwrap(), None);
        encrypted.ciphertext = RingDepositAuditCapsule {
            slot_index: 7,
            eph_pk: &[2; 33],
            ciphertext: &[3; custom_ring_interface::RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN],
            recipient_ciphertext: &encrypted.ciphertext,
        }
        .encode();
        let wrapped = encrypted.ciphertext.clone();
        encrypted.ciphertext = deposit_payload(&wrapped).unwrap().unwrap().to_vec();
        assert_eq!(
            RingDepositPlaintext::decrypt(&encrypted, &recipient).unwrap(),
            plaintext
        );
        assert!(deposit_payload(
            &wrapped[..custom_ring_interface::RING_DEPOSIT_AUDIT_PREFIX_LEN - 1]
        )
        .is_err());
    }
}
