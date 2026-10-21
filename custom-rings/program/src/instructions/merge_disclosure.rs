use custom_ring_interface::{
    key_catalog::RingCircuit, merge_disclosure_field_count, CustomRingError,
    MergeAnonymousPublicInput, MergeDisclosureRef, RingProgramConfig, VIEWING_PUBKEY_TAG,
};
use pinocchio::{Address, ProgramResult};
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::instruction::instruction_data::merge_transact::{
    merge_circuit_width, MergeOutputEncryption, MergeTransactIxDataRef,
};

use crate::instructions::verifier::{ring_key, RingProof};

/// An anonymous merge names its owner only to the auditor, the proof binds that opening to the SPP body.
#[must_use]
pub(crate) struct MergeAudit<'a> {
    pub program_id: &'a Address,
    pub config: &'a RingProgramConfig,
    pub anonymous: bool,
    pub disclosure: Option<MergeDisclosureRef<'a>>,
    pub spp_body: &'a [u8],
}

impl MergeAudit<'_> {
    #[inline(never)]
    pub fn verify(self) -> ProgramResult {
        let disclosure = match (self.anonymous, self.disclosure) {
            (false, None) => return Ok(()),
            (false, Some(_)) => return Err(CustomRingError::InvalidMergeDisclosure.into()),
            (true, None) => return Err(CustomRingError::MissingMergeDisclosure.into()),
            (true, Some(disclosure)) => disclosure,
        };
        let merge = MergeTransactIxDataRef::from_bytes(self.spp_body)
            .map_err(|_| CustomRingError::InvalidInstructionData)?;
        let width = merge_circuit_width(merge.nullifiers.len())
            .ok_or(CustomRingError::InvalidInstructionData)?;
        if disclosure.fields.len() != merge_disclosure_field_count(width) {
            return Err(CustomRingError::MergeDisclosureWidth.into());
        }
        if disclosure.eph_pk[0] != VIEWING_PUBKEY_TAG {
            return Err(CustomRingError::InvalidMergeDisclosure.into());
        }
        let first_nullifier = merge
            .nullifiers
            .first()
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let MergeOutputEncryption::PoseidonCtrV1 { salt, .. } = &merge.output_encryption;
        let public_input = MergeAnonymousPublicInput {
            private_tx_hash: merge.private_tx_hash,
            output_utxo_hash: merge.output_utxo_hash,
            first_nullifier,
            ring_id: &hash_bytes(self.program_id.as_array()).map_err(CustomRingError::from)?,
            auditor_pk: &self.config.auditor_pubkey,
            eph_pk: disclosure.eph_pk,
            ciphertext: disclosure.ciphertext,
            salt,
            fields: disclosure.fields,
        }
        .hash()
        .map_err(CustomRingError::from)?;
        let width = u8::try_from(width).map_err(|_| CustomRingError::InvalidInstructionData)?;
        RingProof {
            proof: disclosure.proof,
            statement: public_input,
            key: ring_key(RingCircuit::AnonymousMerge { width })?,
        }
        .verify()
    }
}
