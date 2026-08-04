import { ciphertextHash } from "../../interface/merge-utils.js";

import { type Bytes32, checkedBytes, copyBytes } from "../bytes.js";
import { wrapKeypairError } from "../error.js";
import type { NullifierKey } from "../nullifier-key.js";
import { poseidon } from "../poseidon.js";
import { P256PublicKey } from "../public-key.js";
import {
  MERGE_INFO as MERGE_INFO_BYTES,
  decryptVerifiableSecret,
  encryptVerifiableSecret,
  packMergePublicKey,
} from "./core.js";

export { MAX_INFO_LENGTH, symmetricApply } from "./core.js";

export const MERGE_INFO = copyBytes(MERGE_INFO_BYTES);
const DOMAIN_MERGE_OUTPUT_BLINDING = 0x544d_4f42;
const DOMAIN_MERGE_DUMMY_NULLIFIER = 0x544d_444e;

export interface MergeCiphertextPublicInputs {
  readonly txViewingPublicKeyLow: Bytes32;
  readonly txViewingPublicKeyHigh: Bytes32;
  readonly ciphertextHash: Bytes32;
}

export function encryptVerifiable(
  txViewingSecret: Bytes32,
  userViewingPublicKey: P256PublicKey,
  plaintext: Uint8Array,
): Readonly<{ ciphertext: Uint8Array; txViewingPublicKey: P256PublicKey }> {
  return encryptVerifiableSecret(
    checkedBytes<Bytes32>(txViewingSecret, 32, "transaction viewing secret"),
    userViewingPublicKey,
    plaintext,
  );
}

export function decryptVerifiable(
  userViewingSecret: Bytes32,
  txViewingPublicKey: P256PublicKey,
  ciphertext: Uint8Array,
): Uint8Array {
  return decryptVerifiableSecret(
    checkedBytes<Bytes32>(userViewingSecret, 32, "user viewing secret"),
    txViewingPublicKey,
    ciphertext,
  );
}

export function mergePublicContribution(
  txViewingPublicKey: P256PublicKey,
  ciphertext: Uint8Array,
): MergeCiphertextPublicInputs {
  const [txViewingPublicKeyLow, txViewingPublicKeyHigh] = packMergePublicKey(txViewingPublicKey);
  return {
    txViewingPublicKeyLow,
    txViewingPublicKeyHigh,
    ciphertextHash: mergeCiphertextHash(ciphertext),
  };
}

export function mergeCiphertextHash(ciphertext: Uint8Array): Bytes32 {
  try {
    return ciphertextHash(ciphertext);
  } catch (error) {
    throw wrapKeypairError("KEYPAIR_POSEIDON", error);
  }
}

export function mergeOutputBlinding(nullifierKey: NullifierKey, firstNullifier: Bytes32): Bytes32 {
  return poseidon([
    fieldU32(DOMAIN_MERGE_OUTPUT_BLINDING),
    rightAlign(nullifierKey.secretBytes()),
    checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
  ]) as Bytes32;
}

export function mergeDummyNullifier(
  nullifierKey: NullifierKey,
  firstNullifier: Bytes32,
  slotIndex: number,
): Bytes32 {
  if (!Number.isInteger(slotIndex) || slotIndex < 0 || slotIndex > 0xff) {
    throw new RangeError("merge dummy slot index must fit in u8");
  }
  return poseidon([
    fieldU32(DOMAIN_MERGE_DUMMY_NULLIFIER),
    rightAlign(nullifierKey.secretBytes()),
    checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
    fieldU32(slotIndex),
  ]) as Bytes32;
}

function fieldU32(value: number): Bytes32 {
  const field = new Uint8Array(32);
  new DataView(field.buffer).setUint32(28, value, false);
  return field as Bytes32;
}

function rightAlign(bytes: Uint8Array): Bytes32 {
  const field = new Uint8Array(32);
  field.set(bytes, 32 - bytes.length);
  return field as Bytes32;
}
