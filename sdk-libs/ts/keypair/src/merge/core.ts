import { ctr } from "@noble/ciphers/aes.js";

import {
  type Bytes32,
  type Bytes33,
  bigIntToBytes,
  checkedBytes,
  concatBytes,
  copyBytes,
} from "../bytes.js";
import { ecdhX } from "../encryption.js";
import { pack33 } from "../hash.js";
import { poseidon } from "../poseidon.js";
import { P256PublicKey } from "../public-key.js";

export const MERGE_INFO = new TextEncoder().encode("TSPP/merge");

const DOM_SEP_SHARED_SECRET = 0x544d_5353n;
const DOM_SEP_SILO = 0x544d_5349n;
const DOM_SEP_KEY = 0x544d_534bn;
const DOM_SEP_NONCE = 0x544d_534en;

function pack32(bytes: Uint8Array): readonly [Uint8Array, Uint8Array] {
  const low = new Uint8Array(32);
  low.set(bytes.subarray(0, 31), 1);
  const high = new Uint8Array(32);
  high[31] = bytes.at(31) ?? 0;
  return [low, high];
}

function packInfo(info: Uint8Array): readonly [Uint8Array, Uint8Array] {
  const split = Math.min(info.length, 31);
  const low = new Uint8Array(32);
  low[0] = info.length;
  low.set(info.subarray(0, split), 32 - split);
  const high = new Uint8Array(32);
  high.set(info.subarray(split), 32 - (info.length - split));
  return [low, high];
}

function deriveSharedSecret(
  dh: Uint8Array,
  ephemeralPublicKey: P256PublicKey,
  recipientPublicKey: P256PublicKey,
): Uint8Array {
  const [dhLow, dhHigh] = pack32(dh);
  const [ephemeralLow, ephemeralHigh] = pack33(ephemeralPublicKey.toBytes());
  const [recipientLow, recipientHigh] = pack33(recipientPublicKey.toBytes());
  return poseidon([
    bigIntToBytes(DOM_SEP_SHARED_SECRET),
    dhLow,
    dhHigh,
    ephemeralLow,
    ephemeralHigh,
    recipientLow,
    recipientHigh,
  ]);
}

function keySchedule(sharedSecret: Uint8Array): readonly [Uint8Array, Uint8Array] {
  const [infoLow, infoHigh] = packInfo(MERGE_INFO);
  const siloed = poseidon([bigIntToBytes(DOM_SEP_SILO), sharedSecret, infoLow, infoHigh]);
  const keyLow = poseidon([bigIntToBytes(DOM_SEP_KEY), siloed]);
  const keyHigh = poseidon([bigIntToBytes(DOM_SEP_KEY + 1n), siloed]);
  const key = concatBytes(keyHigh.subarray(16), keyLow.subarray(16));
  const nonce = poseidon([bigIntToBytes(DOM_SEP_NONCE), siloed]).subarray(20);
  siloed.fill(0);
  return [key, nonce];
}

function applyMergeCipher(
  secret: Uint8Array,
  counterparty: P256PublicKey,
  ephemeralPublicKey: P256PublicKey,
  recipientPublicKey: P256PublicKey,
  input: Uint8Array,
): Uint8Array {
  const dh = ecdhX(secret, counterparty);
  const sharedSecret = deriveSharedSecret(dh, ephemeralPublicKey, recipientPublicKey);
  dh.fill(0);
  const [key, nonce] = keySchedule(sharedSecret);
  sharedSecret.fill(0);
  const counter = new Uint8Array(16);
  counter.set(nonce);
  counter[15] = 2;
  try {
    return ctr(key, counter).encrypt(copyBytes(input));
  } finally {
    key.fill(0);
  }
}

export function encryptVerifiableSecret(
  txViewingSecret: Uint8Array,
  userViewingPublicKey: P256PublicKey,
  plaintext: Uint8Array,
): Readonly<{ ciphertext: Uint8Array; txViewingPublicKey: P256PublicKey }> {
  const secret = checkedBytes<Bytes32>(txViewingSecret, 32, "transaction viewing secret");
  const txViewingPublicKey = P256PublicKey.fromSecret(secret);
  return {
    ciphertext: applyMergeCipher(
      secret,
      userViewingPublicKey,
      txViewingPublicKey,
      userViewingPublicKey,
      plaintext,
    ),
    txViewingPublicKey,
  };
}

export function decryptVerifiableSecret(
  userViewingSecret: Uint8Array,
  txViewingPublicKey: P256PublicKey,
  ciphertext: Uint8Array,
): Uint8Array {
  const secret = checkedBytes<Bytes32>(userViewingSecret, 32, "user viewing secret");
  return applyMergeCipher(
    secret,
    txViewingPublicKey,
    txViewingPublicKey,
    P256PublicKey.fromSecret(secret),
    ciphertext,
  );
}

export function packMergePublicKey(publicKey: P256PublicKey): readonly [Bytes32, Bytes32] {
  const bytes = checkedBytes<Bytes33>(publicKey.toBytes(), 33, "transaction viewing public key");
  const [low, high] = pack33(bytes);
  return [low as Bytes32, high as Bytes32];
}
