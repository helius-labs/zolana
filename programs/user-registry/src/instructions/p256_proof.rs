use pinocchio::{sysvars::instructions::Instructions, AccountView, Address, ProgramResult};
use zolana_user_registry_interface::{
    instruction::{p256_key_binding_message, P256_KEY_BINDING_MESSAGE_LEN},
    SECP256R1_PROGRAM_ID,
};

use crate::error::{fail, UserRegistryError};

// secp256r1 precompile wire layout: u8 num_signatures, u8 padding, one 14-byte
// offsets record per signature, then the referenced data blobs.
const SIGNATURE_OFFSETS_START: usize = 2;
const SIGNATURE_OFFSETS_SIZE: usize = 14;
const DATA_START: usize = SIGNATURE_OFFSETS_START + SIGNATURE_OFFSETS_SIZE;
const PUBKEY_SIZE: usize = 33;
const SIGNATURE_SIZE: usize = 64;
const PUBKEY_OFFSET: usize = DATA_START;
const SIGNATURE_OFFSET: usize = PUBKEY_OFFSET + PUBKEY_SIZE;
const MESSAGE_OFFSET: usize = SIGNATURE_OFFSET + SIGNATURE_SIZE;
const PROOF_DATA_LEN: usize = MESSAGE_OFFSET + P256_KEY_BINDING_MESSAGE_LEN;

/// Canonical head of a self-contained proof: exactly one signature whose
/// offsets record points at the trailing pubkey/signature/message blobs.
///
/// The `u16::MAX` instruction-index fields mean "the current instruction";
/// pinning them and every offset stops the precompile from reading the key,
/// signature, or message out of any other instruction in the transaction.
const CANONICAL_HEAD: [u8; DATA_START] = {
    let offsets = [
        SIGNATURE_OFFSET as u16,             // signature_offset
        u16::MAX,                            // signature_instruction_index
        PUBKEY_OFFSET as u16,                // public_key_offset
        u16::MAX,                            // public_key_instruction_index
        MESSAGE_OFFSET as u16,               // message_data_offset
        P256_KEY_BINDING_MESSAGE_LEN as u16, // message_data_size
        u16::MAX,                            // message_instruction_index
    ];
    let mut head = [0u8; DATA_START];
    head[0] = 1; // num_signatures
    let mut i = 0;
    while i < offsets.len() {
        let le = offsets[i].to_le_bytes();
        head[SIGNATURE_OFFSETS_START + i * 2] = le[0];
        head[SIGNATURE_OFFSETS_START + i * 2 + 1] = le[1];
        i += 1;
    }
    head
};

/// Validate the canonical, self-contained secp256r1 precompile instruction
/// immediately preceding the current registry instruction.
pub fn verify_p256_key_binding(
    instructions_account: &AccountView,
    user_record: &Address,
    owner: &Address,
    owner_p256: &[u8; 33],
) -> ProgramResult {
    let instructions = Instructions::try_from(instructions_account)
        .map_err(|_| fail(UserRegistryError::InvalidInstructionsSysvar))?;
    let proof = instructions
        .get_instruction_relative(-1)
        .map_err(|_| fail(UserRegistryError::MissingP256Proof))?;

    if proof.get_program_id() != &Address::from(SECP256R1_PROGRAM_ID)
        || proof.num_account_metas() != 0
    {
        return Err(fail(UserRegistryError::InvalidP256Proof));
    }

    let expected_message = p256_key_binding_message(
        &(*user_record.as_array()).into(),
        &(*owner.as_array()).into(),
        owner_p256,
    );

    // Everything except the signature itself is pinned: layout, offsets, key,
    // and bound message. The signature is what the precompile verifies.
    let data = proof.get_instruction_data();
    if data.len() != PROOF_DATA_LEN
        || data[..DATA_START] != CANONICAL_HEAD
        || data[PUBKEY_OFFSET..SIGNATURE_OFFSET] != owner_p256[..]
        || data[MESSAGE_OFFSET..] != expected_message
    {
        return Err(fail(UserRegistryError::InvalidP256Proof));
    }

    Ok(())
}
