use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice, primitives::right_align, Hasher, HasherError,
    Poseidon,
};
use zolana_interface::merge_utils::ciphertext_hash;

use crate::{base_public_input::pack33_to_2fe, AUDIT_CIPHERTEXT_LEN, COMPRESSED_P256_KEY_LEN};

/// Chain order pinned by `custom_ring/policy/register_key.go`.
pub struct RegisterKeyPublicInput<'a> {
    pub registry_old_root: &'a [u8; 32],
    pub registry_new_root: &'a [u8; 32],
    pub member: &'a [u8; 32],
    pub nullifier_pk: &'a [u8; 32],
    pub auditor_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    pub eph_pk: &'a [u8; COMPRESSED_P256_KEY_LEN],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    pub new_index: u64,
}

impl RegisterKeyPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let auditor = pack33_to_2fe(self.auditor_pk);
        let eph = pack33_to_2fe(self.eph_pk);
        let ct_hash = ciphertext_hash(self.ciphertext)?;
        create_hash_chain_from_slice(&[
            *self.registry_old_root,
            *self.registry_new_root,
            *self.member,
            *self.nullifier_pk,
            auditor.lo,
            auditor.hi,
            eph.lo,
            eph.hi,
            ct_hash,
            right_align(&self.new_index.to_be_bytes()),
        ])
    }
}

/// Occupies the nullifier slot of the member's registry leaf.
pub struct RegisteredKey<'a> {
    pub nullifier_pk: &'a [u8; 32],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
}

impl RegisteredKey<'_> {
    pub fn commitment(&self) -> Result<[u8; 32], HasherError> {
        let ct_hash = ciphertext_hash(self.ciphertext)?;
        Poseidon::hashv(&[self.nullifier_pk, &ct_hash])
    }
}
