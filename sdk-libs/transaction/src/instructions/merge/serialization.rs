use solana_address::Address;
use zolana_hasher::{
    primitives::{pack_be, right_align, PACK_BE_CHUNK_BYTES},
    Hasher, Poseidon,
};
use zolana_keypair::{constants::SALT_LEN, viewing_key::Salt, PublicKey};

use super::DOMAIN_MERGE_OUTPUT_CIPHERTEXT;
use crate::{
    data::Data,
    error::TransactionError,
    field::{field_add, field_sub},
    utxo::Utxo,
    Mint,
};

use zolana_event::MERGE_OUTPUT_BODY_LEN;
use zolana_interface::instruction::instruction_data::merge_transact::MERGE_OUTPUT_CIPHERTEXT_ELEMENTS;

/// The ciphertext elements a merge instruction carries.
pub type MergeOutputCiphertext = [[u8; 32]; MERGE_OUTPUT_CIPHERTEXT_ELEMENTS];

/// The amount and mint that a merge proof encrypts for the owner.
/// Ownership and blinding derive from the owner's keys and the first nullifier.
/// The authenticated publication supplies the ring program and ring data hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeOutputPlaintext {
    pub amount: u64,
    pub mint: Address,
}

impl MergeOutputPlaintext {
    /// Encrypts `[amount, mint chunk 0, mint chunk 1]` under the per-merge key
    /// (`DeriveRequest::MergeOutputKey`) and the per-proof salt, as the circuit
    /// does.
    pub fn encrypt(
        &self,
        key: &[u8; 32],
        salt: &Salt,
    ) -> Result<MergeOutputCiphertext, TransactionError> {
        let [chunk_0, chunk_1] = pack_be::<32, 2>(self.mint.as_array());
        let fields = [right_align(&self.amount.to_be_bytes()), chunk_0, chunk_1];
        Ok(apply_pads(&fields, &pads(key, salt)?, field_add))
    }

    /// Decrypts `salt || ciphertext` with the per-merge key. The cipher is
    /// unauthenticated: an element outside its slot's range is how a ciphertext
    /// encrypted under another key shows up. The caller still checks the rebuilt
    /// output against the published commitment.
    pub fn decrypt(body: &[u8], key: &[u8; 32]) -> Result<Self, TransactionError> {
        let (salt, ciphertext) = split_body(body)?;
        // Almost every wrong key produces a field element that cannot be a u64.
        // Reject it before deriving the two mint pads for this candidate.
        let amount = split_low::<8>(&field_sub(&ciphertext[0], &pad(key, &salt, 0)?), 0)?;
        let chunk_0 = field_sub(&ciphertext[1], &pad(key, &salt, 1)?);
        let chunk_1 = field_sub(&ciphertext[2], &pad(key, &salt, 2)?);
        let mint_head = split_low::<PACK_BE_CHUNK_BYTES>(&chunk_0, 1)?;
        let [mint_tail] = split_low::<1>(&chunk_1, 2)?;
        let mut mint = [0u8; 32];
        let (head, tail) = mint.split_at_mut(PACK_BE_CHUNK_BYTES);
        head.copy_from_slice(&mint_head);
        tail.copy_from_slice(&[mint_tail]);
        Ok(Self {
            amount: u64::from_be_bytes(amount),
            mint: Address::new_from_array(mint),
        })
    }

    /// The merged output, with the blinding from
    /// `DeriveRequest::MergeOutputBlinding` and the asset resolved from `mint`.
    pub fn into_utxo(
        self,
        owner: PublicKey,
        asset: Mint,
        blinding: [u8; 32],
        ring_program_id: Option<Address>,
    ) -> Utxo {
        Utxo {
            owner,
            asset,
            amount: self.amount,
            blinding,
            ring_program_id,
            data: Data::default(),
        }
    }
}

/// `pad_i = Poseidon("TMOC", key, salt, i)`, mirroring the circuit's
/// `PoseidonCtr`.
fn pads(key: &[u8; 32], salt: &Salt) -> Result<MergeOutputCiphertext, TransactionError> {
    let mut pads = [[0u8; 32]; MERGE_OUTPUT_CIPHERTEXT_ELEMENTS];
    for (index, entry) in (0u32..).zip(pads.iter_mut()) {
        *entry = pad(key, salt, index)?;
    }
    Ok(pads)
}

fn pad(key: &[u8; 32], salt: &Salt, index: u32) -> Result<[u8; 32], TransactionError> {
    Ok(Poseidon::hashv(&[
        &right_align(&DOMAIN_MERGE_OUTPUT_CIPHERTEXT.to_be_bytes()),
        key,
        &right_align(salt),
        &right_align(&index.to_be_bytes()),
    ])?)
}

fn apply_pads(
    elements: &MergeOutputCiphertext,
    pads: &MergeOutputCiphertext,
    op: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
) -> MergeOutputCiphertext {
    let mut out = [[0u8; 32]; MERGE_OUTPUT_CIPHERTEXT_ELEMENTS];
    for ((out, element), pad) in out.iter_mut().zip(elements).zip(pads) {
        *out = op(element, pad);
    }
    out
}

/// Splits a merge output body into its salt and ciphertext elements.
fn split_body(body: &[u8]) -> Result<(Salt, MergeOutputCiphertext), TransactionError> {
    let invalid = || TransactionError::InvalidLength {
        expected: MERGE_OUTPUT_BODY_LEN,
        actual: body.len(),
    };
    let (salt, rest) = body.split_first_chunk::<SALT_LEN>().ok_or_else(invalid)?;
    let (elements, []) = rest.as_chunks::<32>() else {
        return Err(invalid());
    };
    let ciphertext = MergeOutputCiphertext::try_from(elements).map_err(|_| invalid())?;
    Ok((*salt, ciphertext))
}

/// The low `N` bytes of a 32-byte big-endian element whose high bytes are zero.
fn split_low<const N: usize>(
    element: &[u8; 32],
    index: usize,
) -> Result<[u8; N], TransactionError> {
    element
        .split_last_chunk::<N>()
        .filter(|(high, _)| high.iter().all(|byte| *byte == 0))
        .map(|(_, low)| *low)
        .ok_or(TransactionError::InvalidMergeOutputPlaintext { index })
}
