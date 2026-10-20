use custom_ring_interface::{
    merge_anonymous_verifying_key, merge_disclosure_field_count, CustomRingError,
    CustomRingMergeIxDataRef, MergeAnonymousPublicInput, RingMode, VIEWING_PUBKEY_TAG,
};
use pinocchio::{Address, ProgramResult};
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::instruction::instruction_data::merge_transact::{
    merge_circuit_width, MergeOutputEncryption,
};

use crate::instructions::{loader::AuditedConfig, verifier::verify_groth16};

/// An anonymous merge names its owner only to the auditor, the proof binds that opening to the SPP body.
#[inline(never)]
pub(crate) fn verify_merge_disclosure(
    program_id: &Address,
    config: &AuditedConfig,
    request: &CustomRingMergeIxDataRef<'_>,
    member_registry_root: &[u8; 32],
) -> ProgramResult {
    let disclosure = match (config.mode == RingMode::Anonymous, &request.disclosure) {
        (false, None) => return Ok(()),
        (false, Some(_)) => return Err(CustomRingError::InvalidMergeDisclosure.into()),
        (true, None) => return Err(CustomRingError::MissingMergeDisclosure.into()),
        (true, Some(disclosure)) => disclosure,
    };
    let merge = &request.merge;
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
        ring_id: &hash_bytes(program_id.as_array()).map_err(CustomRingError::from)?,
        member_registry_root,
        auditor_pk: &config.auditor_pubkey,
        eph_pk: disclosure.eph_pk,
        ciphertext: disclosure.ciphertext,
        salt,
        fields: disclosure.fields,
    }
    .hash()
    .map_err(CustomRingError::from)?;
    let key = merge_anonymous_verifying_key(width).ok_or(CustomRingError::UnsupportedCircuit)?;
    verify_groth16(disclosure.proof, public_input, key)
}
