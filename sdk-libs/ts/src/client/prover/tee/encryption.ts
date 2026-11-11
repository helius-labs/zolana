import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { gcm } from "@noble/ciphers/aes.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

import { ClientError } from "../../error.js";

export const HEADER_VERSION = "Spr-Tee";
export const HEADER_ENC = "Spr-Tee-Enc";
/** Carries the encrypted bytes of a GET, fetch refuses a GET body. */
export const HEADER_CIPHERTEXT = "Spr-Tee-Ciphertext";
/** The wire version this client sends; it binds the method and the route. */
export const VERSION = "v1.1";
export const RESPONSE_NONCE_SIZE = 12;

// Domain separation for the HPKE context and its response exporter.
const HPKE_INFO = utf8ToBytes("zolana/prover-tee/v1.1");
const RESPONSE_EXPORT = utf8ToBytes("zolana/prover-tee/v1.1/response");

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

export type DecryptedResponse = Readonly<{ status: number; body: Uint8Array }>;

/** One request encrypted to the attested key, and the only key that decrypts its answer. */
export type EncryptedRequest = Readonly<{
  enc: string;
  body: Uint8Array;
  decrypt(encrypted: Uint8Array): DecryptedResponse;
}>;

/**
 * Binds `method` and `route` as AAD, so the encrypted body decrypts only on the
 * route it was sent to. `route` is the path below the prover URL, such as
 * `/prove/transfer_2_2`; the query is not bound and the prover never reads it.
 */
export async function encryptRequest(
  hpkePublicKey: Uint8Array,
  method: string,
  route: string,
  plaintext: Uint8Array,
): Promise<EncryptedRequest> {
  const recipientPublicKey = await suite.kem.deserializePublicKey(hpkePublicKey);
  const sender = await suite.createSenderContext({ recipientPublicKey, info: HPKE_INFO });
  const body = new Uint8Array(await sender.seal(plaintext, utf8ToBytes(requestAad(method, route))));
  const responseKey = new Uint8Array(await sender.export(RESPONSE_EXPORT, 32));
  return Object.freeze({
    enc: bytesToHex(new Uint8Array(sender.enc)),
    body,
    decrypt: (encrypted: Uint8Array) => decryptResponse(responseKey, encrypted),
  });
}

/**
 * A client binds the route below its prover URL, so a proxy can serve the
 * prover under any path.
 */
export function requestAad(method: string, route: string): string {
  return `${method} ${route}`;
}

export function decryptResponse(key: Uint8Array, encrypted: Uint8Array): DecryptedResponse {
  let plaintext: Uint8Array;
  try {
    plaintext = gcm(key, encrypted.subarray(0, RESPONSE_NONCE_SIZE)).decrypt(
      encrypted.subarray(RESPONSE_NONCE_SIZE),
    );
  } catch {
    throw new ClientError("CLIENT_PROVER_TEE_ENCRYPTION", { details: { check: "response" } });
  }
  if (plaintext.length < 2) {
    throw new ClientError("CLIENT_PROVER_TEE_ENCRYPTION", { details: { check: "response" } });
  }
  return Object.freeze({
    status: new DataView(plaintext.buffer, plaintext.byteOffset).getUint16(0, false),
    body: plaintext.subarray(2),
  });
}
