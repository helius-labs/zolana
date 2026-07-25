import { ctr } from "@noble/ciphers/aes.js";
import { p256 } from "@noble/curves/nist.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { concatBytes, copyBytes, u32be } from "./bytes.js";
import { ENC_INFO_TRANSFER, HPKE_PREFIX } from "./constants.js";
import { wrapKeypairError } from "./error.js";
import { P256PublicKey } from "./public-key.js";

const encoder = new TextEncoder();

export function ecdhX(secret: Uint8Array, counterparty: P256PublicKey): Uint8Array {
  try {
    return p256.getSharedSecret(secret, counterparty.toBytes(), true).subarray(1, 33);
  } catch (error) {
    throw wrapKeypairError("KEYPAIR_INVALID_PUBLIC_KEY", error);
  }
}

function deriveKeyNonce(
  dh: Uint8Array,
  ephemeralPublicKey: P256PublicKey,
  recipientPublicKey: P256PublicKey,
  salt: Uint8Array,
  slotIndex: number,
): readonly [Uint8Array, Uint8Array] {
  const ikm = concatBytes(dh, ephemeralPublicKey.toBytes(), recipientPublicKey.toBytes());
  const info = concatBytes(
    encoder.encode(HPKE_PREFIX),
    encoder.encode(ENC_INFO_TRANSFER),
    salt,
    u32be(slotIndex),
  );
  try {
    const output = hkdf(sha256, ikm, undefined, info, 44);
    return [output.subarray(0, 32), output.subarray(32)];
  } catch (error) {
    throw wrapKeypairError("KEYPAIR_HKDF", error);
  } finally {
    ikm.fill(0);
  }
}

export function applyTransferCipher(
  secret: Uint8Array,
  counterparty: P256PublicKey,
  ephemeralPublicKey: P256PublicKey,
  recipientPublicKey: P256PublicKey,
  input: Uint8Array,
  salt: Uint8Array,
  slotIndex: number,
): Uint8Array {
  // Every derived secret is wiped on the way out, including when HKDF or the
  // cipher throws: a rejected ciphertext must not leave the shared secret or
  // the AES key sitting in a live buffer.
  const shared = ecdhX(secret, counterparty);
  let key: Uint8Array | undefined;
  try {
    let nonce: Uint8Array;
    [key, nonce] = deriveKeyNonce(shared, ephemeralPublicKey, recipientPublicKey, salt, slotIndex);
    const counter = new Uint8Array(16);
    counter.set(nonce);
    counter[15] = 2;
    return ctr(key, counter).encrypt(copyBytes(input));
  } finally {
    shared.fill(0);
    key?.fill(0);
  }
}
