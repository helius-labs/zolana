import { ciphertextHash } from "@zolana/interface";

import { type Bytes32, checkedBytes, copyBytes } from "../bytes.js";
import { wrapKeypairError } from "../error.js";
import { P256PublicKey } from "../public-key.js";
import {
  MERGE_INFO as MERGE_INFO_BYTES,
  decryptVerifiableSecret,
  encryptVerifiableSecret,
  packMergePublicKey,
} from "./core.js";

export const MERGE_INFO = copyBytes(MERGE_INFO_BYTES);

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
    throw wrapKeypairError("KEYPAIR_HASH", error);
  }
}
