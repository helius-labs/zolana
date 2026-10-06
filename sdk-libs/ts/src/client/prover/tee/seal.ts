import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { gcm } from "@noble/ciphers/aes.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

import { ClientError } from "../../error.js";

export const HEADER_VERSION = "Zolana-Tee";
export const HEADER_ENC = "Zolana-Tee-Enc";
/** Carries the sealed bytes of a GET, fetch refuses a GET body. */
export const HEADER_SEAL = "Zolana-Tee-Seal";
export const VERSION = "v1";
export const RESPONSE_NONCE_SIZE = 12;

// Domain separation for the HPKE context and its response exporter.
const HPKE_INFO = utf8ToBytes("zolana/prover-tee/v1");
const RESPONSE_EXPORT = utf8ToBytes("zolana/prover-tee/v1/response");

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

export type OpenedResponse = Readonly<{ status: number; body: Uint8Array }>;

/** One request sealed to the attested key, and the only key its answer opens with. */
export type SealedRequest = Readonly<{
  enc: string;
  body: Uint8Array;
  open(sealed: Uint8Array): OpenedResponse;
}>;

/**
 * Binds `method` and the raw request target as AAD, so the sealed body opens
 * only on the route and job it was sent to.
 */
export async function sealRequest(
  hpkePublicKey: Uint8Array,
  method: string,
  requestUri: string,
  plaintext: Uint8Array,
): Promise<SealedRequest> {
  const recipientPublicKey = await suite.kem.deserializePublicKey(hpkePublicKey);
  const sender = await suite.createSenderContext({ recipientPublicKey, info: HPKE_INFO });
  const body = new Uint8Array(
    await sender.seal(plaintext, utf8ToBytes(requestAad(method, requestUri))),
  );
  const responseKey = new Uint8Array(await sender.export(RESPONSE_EXPORT, 32));
  return Object.freeze({
    enc: bytesToHex(new Uint8Array(sender.enc)),
    body,
    open: (sealed: Uint8Array) => openResponse(responseKey, sealed),
  });
}

/**
 * The method, path and query minus every `api-key` parameter, so a proxy can
 * move the credential while the route and job stay bound.
 */
export function requestAad(method: string, requestUri: string): string {
  const separator = requestUri.indexOf("?");
  const path = separator === -1 ? requestUri : requestUri.slice(0, separator);
  const query = separator === -1 ? "" : requestUri.slice(separator + 1);
  const kept = query.split("&").filter((pair) => pair !== "" && pair.split("=")[0] !== "api-key");
  return kept.length === 0 ? `${method} ${path}` : `${method} ${path}?${kept.join("&")}`;
}

export function openResponse(key: Uint8Array, sealed: Uint8Array): OpenedResponse {
  let plaintext: Uint8Array;
  try {
    plaintext = gcm(key, sealed.subarray(0, RESPONSE_NONCE_SIZE)).decrypt(
      sealed.subarray(RESPONSE_NONCE_SIZE),
    );
  } catch {
    throw new ClientError("CLIENT_PROVER_TEE_SEAL", { details: { check: "response" } });
  }
  if (plaintext.length < 2) {
    throw new ClientError("CLIENT_PROVER_TEE_SEAL", { details: { check: "response" } });
  }
  return Object.freeze({
    status: new DataView(plaintext.buffer, plaintext.byteOffset).getUint16(0, false),
    body: plaintext.subarray(2),
  });
}
