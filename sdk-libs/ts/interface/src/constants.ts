/**
 * Fixed layout parameters of the merge instruction data, mirroring
 * `program-libs/interface/src/instruction/instruction_data/merge_transact.rs`.
 * Kept in a leaf module so the codecs can enforce them without importing the
 * package root, which imports the codecs.
 */

/** Input slots a merge proof spends. The shape is fixed at 8-in/1-out. */
export const MERGE_INPUT_COUNT = 8;

/**
 * Byte length of `encrypted_utxo`: borsh tag(1) || vec len u32-le(4) ||
 * scheme(1) || tx_viewing_pk(33) || ciphertext(71).
 */
export const MERGE_ENCRYPTED_UTXO_LENGTH = 110;

/** The borsh `OutputDataEncoding::VerifiablyEncrypted` discriminant. */
export const MERGE_ENCRYPTED_UTXO_TYPE_PREFIX = 2;
