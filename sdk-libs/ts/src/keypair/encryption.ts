import { ctr } from "@noble/ciphers/aes.js";

import { copyBytes, u32be } from "./bytes.js";
import { ENC_INFO_TRANSFER, HPKE_PREFIX, hkdfExpand, x25519Ecdh } from "./derivation.js";
import type { X25519PublicKey } from "./x25519.js";
import { concatBytes } from "../interface/bytes.js";

const encoder = new TextEncoder();

function deriveKeyNonce(
  dh: Uint8Array,
  ephemeralPublicKey: X25519PublicKey,
  recipientPublicKey: X25519PublicKey,
  salt: Uint8Array,
  slotIndex: number,
  infoLabel: string,
): readonly [Uint8Array, Uint8Array] {
  const ikm = concatBytes(dh, ephemeralPublicKey.toBytes(), recipientPublicKey.toBytes());
  const info = concatBytes(
    encoder.encode(HPKE_PREFIX),
    encoder.encode(infoLabel),
    salt,
    u32be(slotIndex),
  );
  try {
    const output = hkdfExpand(undefined, ikm, info, 44);
    return [output.subarray(0, 32), output.subarray(32)];
  } finally {
    ikm.fill(0);
  }
}

export function applyTransferCipher(
  secret: Uint8Array,
  counterparty: X25519PublicKey,
  ephemeralPublicKey: X25519PublicKey,
  recipientPublicKey: X25519PublicKey,
  input: Uint8Array,
  salt: Uint8Array,
  slotIndex: number,
  infoLabel: string = ENC_INFO_TRANSFER,
): Uint8Array {
  // Every derived secret is wiped on the way out, including when HKDF or the
  // cipher throws: a rejected ciphertext must not leave the shared secret or
  // the AES key sitting in a live buffer.
  const shared = x25519Ecdh(secret, counterparty);
  let key: Uint8Array | undefined;
  try {
    let nonce: Uint8Array;
    [key, nonce] = deriveKeyNonce(
      shared,
      ephemeralPublicKey,
      recipientPublicKey,
      salt,
      slotIndex,
      infoLabel,
    );
    const counter = new Uint8Array(16);
    counter.set(nonce);
    counter[15] = 2;
    return ctr(key, counter).encrypt(copyBytes(input));
  } finally {
    shared.fill(0);
    key?.fill(0);
  }
}
