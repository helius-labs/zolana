import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { type Bytes31, type Bytes32, type Bytes33, checkedBytes, concatBytes } from "./bytes.js";
import {
  DERIVATION_PAYLOAD_PREFIX,
  ED25519_DERIVATION_MSG,
  INFO_NF_KEY_ECDH,
  INFO_NF_KEY_ED25519,
  INFO_PDA_NF_KEY,
  INFO_PDA_VIEW_KEY,
  INFO_VIEW_KEY_ECDH,
  INFO_VIEW_KEY_ED25519,
  P_DERIVE_SEC1,
  P_PDA_SEC1,
} from "./constants.js";
import { KeypairError } from "./error.js";
import { NullifierKey } from "./nullifier-key.js";
import { P256PublicKey, type SigningCurve } from "./public-key.js";
import { ViewingKey, viewingKeyFromOkm48 } from "./viewing-key.js";

const encoder = new TextEncoder();
const DERIVATION_PREFIX_BYTES = encoder.encode(DERIVATION_PAYLOAD_PREFIX);

export const OFFCHAIN_MESSAGE_MAGIC = Uint8Array.from([0xff, ...encoder.encode("solana offchain")]);

/** `sha256(ED25519_DERIVATION_MSG)`. */
export const TSPP_APPLICATION_DOMAIN = Uint8Array.from([
  0x1d, 0x32, 0xa8, 0x85, 0x33, 0xaf, 0x12, 0xd3, 0x5e, 0x5a, 0xc6, 0xfc, 0xe8, 0x17, 0xa4, 0xcb,
  0x81, 0x0b, 0xcc, 0x41, 0x15, 0x38, 0x6b, 0x14, 0xa7, 0x8e, 0x8b, 0x2e, 0xf0, 0x9d, 0x86, 0x4c,
]);

export const P_DERIVE = P256PublicKey.fromBytes(P_DERIVE_SEC1 as Bytes33);
export const P_PDA = P256PublicKey.fromBytes(P_PDA_SEC1 as Bytes33);

/** The Solana off-chain message v0 signed by an Ed25519 owner. */
export function ed25519DerivationMessage(signerPublicKey: Bytes32): Uint8Array {
  const signer = checkedBytes<Bytes32>(signerPublicKey, 32, "Ed25519 public key");
  const payload = encoder.encode(ED25519_DERIVATION_MSG);
  return concatBytes(
    OFFCHAIN_MESSAGE_MAGIC,
    Uint8Array.of(0),
    TSPP_APPLICATION_DOMAIN,
    Uint8Array.of(0, 1),
    signer,
    Uint8Array.of(payload.length & 0xff, payload.length >> 8),
    payload,
  );
}

function startsWith(bytes: Uint8Array, prefix: Uint8Array): boolean {
  if (bytes.length < prefix.length) return false;
  for (let index = 0; index < prefix.length; index++) {
    if (bytes[index] !== prefix[index]) return false;
  }
  return true;
}

function offchainV0Payload(message: Uint8Array): Uint8Array | undefined {
  if (!startsWith(message, OFFCHAIN_MESSAGE_MAGIC)) return undefined;

  let offset = OFFCHAIN_MESSAGE_MAGIC.length;
  if (message[offset] !== 0) return undefined;
  offset += 1;

  if (message.length < offset + 32 + 2) return undefined;
  offset += 32;
  offset += 1;

  const signerCount = message[offset];
  if (signerCount === undefined) return undefined;
  offset += 1;

  const signerBytes = 32 * signerCount;
  if (message.length < offset + signerBytes + 2) return undefined;
  offset += signerBytes;

  const declaredLength = (message[offset] as number) | ((message[offset + 1] as number) << 8);
  const payload = message.subarray(offset + 2);
  return payload.length === declaredLength ? payload : undefined;
}

/** True when signing `message` would produce a derivation seed. */
export function isDerivationInput(message: Uint8Array): boolean {
  if (startsWith(message, DERIVATION_PREFIX_BYTES)) return true;
  const payload = offchainV0Payload(message);
  return payload !== undefined && startsWith(payload, DERIVATION_PREFIX_BYTES);
}

/** Generic ECDH refuses points whose shared secret is a derivation root. */
export function isDerivationPoint(publicKey: P256PublicKey): boolean {
  return publicKey.equals(P_DERIVE) || publicKey.equals(P_PDA);
}

function extractOrThrow(input: Uint8Array): Uint8Array {
  try {
    return extract(sha256, input);
  } catch (error) {
    throw new KeypairError("KEYPAIR_HKDF", undefined, error);
  }
}

function expandOrThrow(prk: Uint8Array, info: string, length: number): Uint8Array {
  try {
    return expand(sha256, prk, encoder.encode(info), length);
  } catch (error) {
    throw new KeypairError("KEYPAIR_HKDF", { name: info, actual: length }, error);
  }
}

function expandBytesOrThrow(
  prk: Uint8Array,
  info: Uint8Array,
  name: string,
  length: number,
): Uint8Array {
  try {
    return expand(sha256, prk, info, length);
  } catch (error) {
    throw new KeypairError("KEYPAIR_HKDF", { name, actual: length }, error);
  }
}

export class RoleExpansion {
  readonly #prk: Uint8Array;
  readonly #curve: SigningCurve;

  constructor(seed: Uint8Array, curve: SigningCurve) {
    this.#prk = extractOrThrow(seed);
    this.#curve = curve;
  }

  nullifierKey(): NullifierKey {
    const info = this.#curve === "ed25519" ? INFO_NF_KEY_ED25519 : INFO_NF_KEY_ECDH;
    return NullifierKey.fromSecret(expandOrThrow(this.#prk, info, 31) as Bytes31);
  }

  viewingKey(): ViewingKey {
    const info = this.#curve === "ed25519" ? INFO_VIEW_KEY_ED25519 : INFO_VIEW_KEY_ECDH;
    return viewingKeyFromOkm48(expandOrThrow(this.#prk, info, 48));
  }

  destroy(): void {
    this.#prk.fill(0);
  }
}

export class PdaRoleExpansion {
  readonly #prk: Uint8Array;
  readonly #pda: Bytes32;

  constructor(shared: Bytes32, pda: Bytes32) {
    this.#prk = extractOrThrow(shared);
    this.#pda = checkedBytes<Bytes32>(pda, 32, "PDA");
  }

  nullifierKey(): NullifierKey {
    const info = concatBytes(encoder.encode(INFO_PDA_NF_KEY), this.#pda);
    return NullifierKey.fromSecret(
      expandBytesOrThrow(this.#prk, info, INFO_PDA_NF_KEY, 31) as Bytes31,
    );
  }

  viewingKey(): ViewingKey {
    const info = concatBytes(encoder.encode(INFO_PDA_VIEW_KEY), this.#pda);
    return viewingKeyFromOkm48(expandBytesOrThrow(this.#prk, info, INFO_PDA_VIEW_KEY, 48));
  }

  destroy(): void {
    this.#prk.fill(0);
  }
}
