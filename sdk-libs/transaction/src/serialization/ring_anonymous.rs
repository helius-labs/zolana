//! Scheme-9 slots over the body layout and stream secret of `custom_ring_interface::anonymous_output`.

pub use custom_ring_interface::AnonymousOutputPlaintext as RingAnonymousOutputPlaintext;
use custom_ring_interface::{
    anonymous_output_body, recipient_stream_secret, ANONYMOUS_OUTPUT_BODY_LEN,
    ANONYMOUS_OUTPUT_PLAINTEXT_LEN, AUDIT_STREAM_INFO,
};
use solana_address::Address;
use zolana_event::{MessageData, OutputDataEncoding};
use zolana_keypair::{
    constants::SALT_LEN, random_blinding, random_salt, symmetric_apply_audit, viewing_key::ViewTag,
    PublicKey, ViewingKey, X25519Keypair, X25519Pubkey,
};

use crate::{error::TransactionError, utxo::Utxo, AssetRegistry, Data};

/// A decrypted scheme-9 note with the counterparty pseudonym the wallet records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingAnonymousOutput {
    pub utxo: Utxo,
    /// `None` for a bad pair hint, the note itself stands.
    pub pair_pk: Option<X25519Pubkey>,
}

impl RingAnonymousOutput {
    /// `ring` is the public ring of the transaction, the opening names none.
    pub fn from_opening(
        opening: RingAnonymousOutputPlaintext,
        owner: PublicKey,
        ring: Address,
        assets: &AssetRegistry,
    ) -> Result<Self, TransactionError> {
        Ok(Self {
            utxo: Utxo {
                owner,
                asset: assets.mint(&Address::new_from_array(opening.asset_address))?,
                amount: opening.amount,
                blinding: opening.blinding,
                ring_program_id: Some(ring),
                data: Data::default(),
            },
            pair_pk: pair_hint(opening.pair_u),
        })
    }
}

/// `None` unless `pair_u` is a canonical contributory X25519 key, the circuit only bounds its bytes.
pub(crate) fn pair_hint(pair_u: [u8; 32]) -> Option<X25519Pubkey> {
    let pair_pk = X25519Pubkey::from_u(pair_u).ok()?;
    // Clamped secrets are cofactor multiples below 8q, so one fixed secret rejects exactly the low-order keys every secret rejects.
    X25519Keypair::from_bytes(&[0; 32]).ecdh(&pair_pk).ok()?;
    Some(pair_pk)
}

/// The slot byte a change tag and a recipient key stream index.
pub fn anonymous_slot_index(slot_index: usize) -> Result<u8, TransactionError> {
    u8::try_from(slot_index).map_err(|_| TransactionError::AnonymousSlotIndex { slot_index })
}

/// The public context of one scheme-9 slot, each party adds its own X25519 secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingAnonymousSlot {
    pub tx_viewing_pk: X25519Pubkey,
    pub recipient_pk: X25519Pubkey,
    pub salt: [u8; SALT_LEN],
    pub slot: u8,
}

impl RingAnonymousSlot {
    /// `tx` is the transaction viewing key `tx_viewing_pk` publishes.
    pub fn seal(
        &self,
        tx: &ViewingKey,
        opening: &RingAnonymousOutputPlaintext,
    ) -> Result<[u8; ANONYMOUS_OUTPUT_BODY_LEN], TransactionError> {
        let mut bytes = opening.to_bytes();
        self.apply(&tx.ecdh(&self.recipient_pk)?, &mut bytes)?;
        Ok(anonymous_output_body(&bytes))
    }

    /// The recipient's opening of the bytes after the scheme byte.
    pub fn open(
        &self,
        viewing: &ViewingKey,
        ciphertext: &[u8],
    ) -> Result<RingAnonymousOutputPlaintext, TransactionError> {
        self.open_with(&viewing.ecdh(&self.tx_viewing_pk)?, ciphertext)
    }

    /// The auditor's opening, `recipient_pk` comes from the proved disclosure.
    pub fn open_with_tx_key(
        &self,
        tx: &ViewingKey,
        ciphertext: &[u8],
    ) -> Result<RingAnonymousOutputPlaintext, TransactionError> {
        self.open_with(&tx.ecdh(&self.recipient_pk)?, ciphertext)
    }

    fn open_with(
        &self,
        dh: &[u8; 32],
        ciphertext: &[u8],
    ) -> Result<RingAnonymousOutputPlaintext, TransactionError> {
        let mut bytes: [u8; ANONYMOUS_OUTPUT_PLAINTEXT_LEN] =
            ciphertext
                .try_into()
                .map_err(|_| TransactionError::InvalidLength {
                    expected: ANONYMOUS_OUTPUT_PLAINTEXT_LEN,
                    actual: ciphertext.len(),
                })?;
        self.apply(dh, &mut bytes)?;
        Ok(RingAnonymousOutputPlaintext::from_bytes(&bytes)?)
    }

    /// The slot stream in place, one agreement `dh` serves every slot of a transaction.
    pub fn apply(
        &self,
        dh: &[u8; 32],
        body: &mut [u8; ANONYMOUS_OUTPUT_PLAINTEXT_LEN],
    ) -> Result<(), TransactionError> {
        let secret = recipient_stream_secret(
            dh,
            self.tx_viewing_pk.as_bytes(),
            self.recipient_pk.as_bytes(),
            &self.salt,
            self.slot,
        )?;
        Ok(symmetric_apply_audit(&secret, AUDIT_STREAM_INFO, body)?)
    }
}

/// The published slot of a body, real or padding.
pub fn ring_anonymous_message(
    body: &[u8; ANONYMOUS_OUTPUT_BODY_LEN],
    view_tag: ViewTag,
) -> Result<MessageData, TransactionError> {
    let data = borsh::to_vec(&OutputDataEncoding::Encrypted(body.to_vec()))
        .map_err(|error| TransactionError::Serialize(error.to_string()))?;
    Ok(MessageData { view_tag, data })
}

/// A padding slot, its body is fresh randomness under the real scheme byte.
pub fn ring_anonymous_padding(view_tag: ViewTag) -> Result<MessageData, TransactionError> {
    let mut ciphertext = [0u8; ANONYMOUS_OUTPUT_PLAINTEXT_LEN];
    for (byte, random) in ciphertext
        .iter_mut()
        .zip(std::iter::repeat_with(random_salt).flatten())
    {
        *byte = random;
    }
    ring_anonymous_message(&anonymous_output_body(&ciphertext), view_tag)
}

/// A padding tag, `0x00 || 31 random bytes` like every derived tag.
pub fn ring_anonymous_padding_tag() -> ViewTag {
    random_blinding()
}
