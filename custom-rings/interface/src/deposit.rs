use crate::deposit_audit::{MAX_RING_DEPOSIT_AUDIT_SLOTS, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN};
use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice,
    primitives::{hash_bytes, right_align, PACK_BE_CHUNK_BYTES},
    HasherError,
};

use crate::{pack33_to_2fe, COMPRESSED_P256_KEY_LEN};

/// Binds a disclosure proof to one ring, destination tree and exact SPP deposit
/// instruction.
pub struct DepositContext<'a> {
    pub program_id: &'a [u8; 32],
    pub tree: &'a [u8; 32],
    pub spp_data: &'a [u8],
}

impl DepositContext<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let chunks: Vec<_> = self
            .spp_data
            .chunks(PACK_BE_CHUNK_BYTES)
            .map(|chunk| {
                let mut field = [0; 32];
                field[32 - chunk.len()..].copy_from_slice(chunk);
                field
            })
            .collect();
        // The length distinguishes equal field encodings of different byte
        // strings.
        create_hash_chain_from_slice(&[
            hash_bytes(self.program_id)?,
            hash_bytes(self.tree)?,
            right_align(&(self.spp_data.len() as u64).to_be_bytes()),
            create_hash_chain_from_slice(&chunks)?,
        ])
    }
}

/// Commits deposited owner hashes and their encrypted openings to the pinned
/// auditor.
pub struct DepositPublicInput<'a> {
    pub context_hash: &'a [u8; 32],
    pub owner_utxo_hashes: &'a [[u8; 32]],
    pub ciphertexts: &'a [[u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]],
    pub auditor_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    pub eph_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
}

impl DepositPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let count = self.owner_utxo_hashes.len();
        if !(1..=MAX_RING_DEPOSIT_AUDIT_SLOTS).contains(&count) || self.ciphertexts.len() != count {
            return Err(HasherError::InvalidNumFields);
        }
        let auditor = pack33_to_2fe(self.auditor_pk);
        let ephemeral = pack33_to_2fe(self.eph_pk);
        let mut chain = [[0; 32]; 3 + MAX_RING_DEPOSIT_AUDIT_SLOTS * 2 + 4];
        chain[0] = right_align(b"CRDP");
        chain[1] = *self.context_hash;
        chain[2] = right_align(&(count as u64).to_be_bytes());
        for (slot, (owner, ciphertext)) in self
            .owner_utxo_hashes
            .iter()
            .zip(self.ciphertexts)
            .enumerate()
        {
            chain[3 + slot * 2] = *owner;
            chain[4 + slot * 2] = hash_bytes(ciphertext)?;
        }
        let keys = 3 + MAX_RING_DEPOSIT_AUDIT_SLOTS * 2;
        chain[keys..].copy_from_slice(&[auditor.lo, auditor.hi, ephemeral.lo, ephemeral.hi]);
        create_hash_chain_from_slice(&chain)
    }
}
