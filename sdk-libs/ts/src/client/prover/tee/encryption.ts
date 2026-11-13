import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { gcm } from "@noble/ciphers/aes.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

import { SPR_GATEWAY_PATH } from "../../../endpoint.js";
import { ClientError } from "../../error.js";
import { unsupportedCrypto } from "./crypto-support.js";

export const HEADER_VERSION = "Spr-Tee";
export const HEADER_ENC = "Spr-Tee-Enc";
/** Carries the encrypted bytes of a GET, fetch refuses a GET body. */
export const HEADER_CIPHERTEXT = "Spr-Tee-Ciphertext";
export const VERSION = "v1";

/**
 * The header names of the encrypted prover channel. A proxy in front of a
 * prover forwards every `request` header unchanged, passes the
 * `application/octet-stream` body through, and returns every `response`
 * header; for browsers it allows the `request` headers in CORS preflight and
 * exposes the `response` headers. A prover that does not receive them refuses
 * the call with `CLIENT_PROVER_TEE_REJECTED`.
 */
export const PROVER_TEE_HEADERS: Readonly<{
  request: readonly ["Spr-Tee", "Spr-Tee-Enc", "Spr-Tee-Ciphertext"];
  response: readonly ["Spr-Tee"];
}> = Object.freeze({
  request: Object.freeze([HEADER_VERSION, HEADER_ENC, HEADER_CIPHERTEXT] as const),
  response: Object.freeze([HEADER_VERSION] as const),
});
export const RESPONSE_NONCE_SIZE = 12;

// Domain separation for the HPKE context and its response exporter.
const HPKE_INFO = utf8ToBytes("zolana/prover-tee/v1");
const RESPONSE_EXPORT = utf8ToBytes("zolana/prover-tee/v1/response");

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
 * Binds `method` and `requestUri` without its `api-key` pairs as AAD, so the
 * encrypted body decrypts only on the route it was sent to. `requestUri` is
 * the path below the prover URL and its query.
 */
export async function encryptRequest(
  hpkePublicKey: Uint8Array,
  method: string,
  requestUri: string,
  plaintext: Uint8Array,
): Promise<EncryptedRequest> {
  // Each step names the WebCrypto algorithm a runtime may lack.
  let algorithm = "X25519";
  try {
    const recipientPublicKey = await suite.kem.deserializePublicKey(hpkePublicKey);
    const sender = await suite.createSenderContext({ recipientPublicKey, info: HPKE_INFO });
    algorithm = "AES-256-GCM";
    const body = new Uint8Array(
      await sender.seal(plaintext, utf8ToBytes(requestAad(method, requestUri))),
    );
    algorithm = "HKDF-SHA256";
    const responseKey = new Uint8Array(await sender.export(RESPONSE_EXPORT, 32));
    return Object.freeze({
      enc: bytesToHex(new Uint8Array(sender.enc)),
      body,
      decrypt: (encrypted: Uint8Array) => decryptResponse(responseKey, encrypted),
    });
  } catch (error) {
    throw unsupportedCrypto(error, algorithm) ?? error;
  }
}

/**
 * The method, route and query minus every `api-key` parameter, so a proxy can
 * move the credential while the route and job stay bound. The route drops
 * trailing slashes and then the gateway prefix, in the order a gateway trims
 * and forwards; a client passes the path below its prover URL, so a proxy can
 * serve the prover under any path.
 */
export function requestAad(method: string, requestUri: string): string {
  const separator = requestUri.indexOf("?");
  const received = separator === -1 ? requestUri : requestUri.slice(0, separator);
  const trimmed = received.replace(/\/+$/, "");
  const path =
    (trimmed.startsWith(`${SPR_GATEWAY_PATH}/`)
      ? trimmed.slice(SPR_GATEWAY_PATH.length)
      : trimmed) || "/";
  const query = separator === -1 ? "" : requestUri.slice(separator + 1);
  const kept = query
    .split("&")
    .filter((pair) => pair !== "" && !new URLSearchParams(`?${pair}`).has("api-key"));
  return kept.length === 0 ? `${method} ${path}` : `${method} ${path}?${kept.join("&")}`;
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
