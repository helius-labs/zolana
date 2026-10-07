use zeroize::Zeroizing;
use zolana_hasher::primitives::{pack_be, right_align};

use crate::{
    constants::P256_PUBKEY_LEN,
    derivation::{DOMAIN_MERGE_DERIVED_BLINDING, MERGE_ENVELOPE_INFO, MERGE_SECRET_TAG},
    encryption::symmetric_apply,
    error::KeypairError,
    hash::poseidon,
    pubkey::P256Pubkey,
    viewing_key::ViewingKey,
};

const MERGE_AMOUNT_LEN: usize = 8;

const MERGE_MINT_LEN: usize = 32;

pub const MERGE_ENVELOPE_CIPHERTEXT_LEN: usize = MERGE_AMOUNT_LEN + MERGE_MINT_LEN;

pub struct MergeEnvelopeEncryption<'a> {
    pub recipient: &'a P256Pubkey,
    pub ephemeral: &'a ViewingKey,
    pub amount: u64,
    pub mint: [u8; MERGE_MINT_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptedMergeEnvelope {
    pub ephemeral_pk: [u8; P256_PUBKEY_LEN],
    pub ciphertext: [u8; MERGE_ENVELOPE_CIPHERTEXT_LEN],
    pub output_blinding: [u8; 32],
}

impl MergeEnvelopeEncryption<'_> {
    pub fn encrypt(&self) -> Result<EncryptedMergeEnvelope, KeypairError> {
        let ephemeral_pk = self.ephemeral.pubkey();
        let shared_x = Zeroizing::new(self.ephemeral.ecdh(self.recipient)?);
        let secret = merge_shared_secret(&shared_x, &ephemeral_pk, self.recipient)?;
        let mut ciphertext = [0u8; MERGE_ENVELOPE_CIPHERTEXT_LEN];
        let (amount, mint) = ciphertext.split_at_mut(MERGE_AMOUNT_LEN);
        amount.copy_from_slice(&self.amount.to_be_bytes());
        mint.copy_from_slice(&self.mint);
        symmetric_apply(&secret, MERGE_ENVELOPE_INFO, &mut ciphertext)?;
        Ok(EncryptedMergeEnvelope {
            ephemeral_pk: *ephemeral_pk.as_bytes(),
            ciphertext,
            output_blinding: merge_derived_blinding(&secret)?,
        })
    }
}

pub struct MergeEnvelopeDecryption<'a> {
    pub viewing_key: &'a ViewingKey,
    pub ephemeral_pk: &'a P256Pubkey,
    pub ciphertext: &'a [u8; MERGE_ENVELOPE_CIPHERTEXT_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecryptedMergeEnvelope {
    pub amount: u64,
    pub mint: [u8; MERGE_MINT_LEN],
    pub output_blinding: [u8; 32],
}

impl DecryptedMergeEnvelope {
    pub const LEN: usize = MERGE_AMOUNT_LEN + MERGE_MINT_LEN + 32;

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut bytes = [0u8; Self::LEN];
        let (amount, rest) = bytes.split_at_mut(MERGE_AMOUNT_LEN);
        let (mint, output_blinding) = rest.split_at_mut(MERGE_MINT_LEN);
        amount.copy_from_slice(&self.amount.to_be_bytes());
        mint.copy_from_slice(&self.mint);
        output_blinding.copy_from_slice(&self.output_blinding);
        bytes
    }

    pub fn from_bytes(bytes: &[u8; Self::LEN]) -> Self {
        let (plaintext, blinding) = bytes.split_at(MERGE_ENVELOPE_CIPHERTEXT_LEN);
        let (amount, mint) = split_plaintext(plaintext);
        let mut output_blinding = [0u8; 32];
        output_blinding.copy_from_slice(blinding);
        Self {
            amount,
            mint,
            output_blinding,
        }
    }
}

impl MergeEnvelopeDecryption<'_> {
    pub fn decrypt(&self) -> Result<DecryptedMergeEnvelope, KeypairError> {
        let recipient = self.viewing_key.pubkey();
        let shared_x = Zeroizing::new(self.viewing_key.ecdh(self.ephemeral_pk)?);
        let secret = merge_shared_secret(&shared_x, self.ephemeral_pk, &recipient)?;
        let mut plaintext = *self.ciphertext;
        symmetric_apply(&secret, MERGE_ENVELOPE_INFO, &mut plaintext)?;
        let (amount, mint) = split_plaintext(&plaintext);
        Ok(DecryptedMergeEnvelope {
            amount,
            mint,
            output_blinding: merge_derived_blinding(&secret)?,
        })
    }
}

fn split_plaintext(plaintext: &[u8]) -> (u64, [u8; MERGE_MINT_LEN]) {
    let (amount, mint) = plaintext.split_at(MERGE_AMOUNT_LEN);
    let mut amount_bytes = [0u8; MERGE_AMOUNT_LEN];
    amount_bytes.copy_from_slice(amount);
    let mut mint_bytes = [0u8; MERGE_MINT_LEN];
    mint_bytes.copy_from_slice(mint);
    (u64::from_be_bytes(amount_bytes), mint_bytes)
}

pub fn merge_shared_secret(
    shared_x: &[u8; 32],
    ephemeral_pk: &P256Pubkey,
    recipient: &P256Pubkey,
) -> Result<Zeroizing<[u8; 32]>, KeypairError> {
    let [shared_lo, shared_hi] = pack_be::<32, 2>(shared_x);
    let [ephemeral_lo, ephemeral_hi] = pack_be::<P256_PUBKEY_LEN, 2>(ephemeral_pk.as_bytes());
    let [recipient_lo, recipient_hi] = pack_be::<P256_PUBKEY_LEN, 2>(recipient.as_bytes());
    Ok(Zeroizing::new(poseidon(&[
        &right_align(MERGE_SECRET_TAG),
        &shared_lo,
        &shared_hi,
        &ephemeral_lo,
        &ephemeral_hi,
        &recipient_lo,
        &recipient_hi,
    ])?))
}

fn merge_derived_blinding(shared_secret: &[u8; 32]) -> Result<[u8; 32], KeypairError> {
    poseidon(&[
        &right_align(&DOMAIN_MERGE_DERIVED_BLINDING.to_be_bytes()),
        shared_secret,
    ])
}
