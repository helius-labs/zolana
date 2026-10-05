import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { gcm } from "@noble/ciphers/aes.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

import { ClientError } from "../../error.js";

export const HEADER_VERSION = "Zolana-Tee";
export const HEADER_ENC = "Zolana-Tee-Enc";
export const VERSION = "v1";

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
  const body = new Uint8Array(await sender.seal(plaintext, utf8ToBytes(`${method} ${requestUri}`)));
  const responseKey = new Uint8Array(await sender.export(RESPONSE_EXPORT, 32));
  return Object.freeze({
    enc: bytesToHex(new Uint8Array(sender.enc)),
    body,
    open: (sealed: Uint8Array) => openResponse(responseKey, sealed),
  });
}

/** The response key is single use, so the zero nonce never repeats under it. */
export function openResponse(key: Uint8Array, sealed: Uint8Array): OpenedResponse {
  let plaintext: Uint8Array;
  try {
    plaintext = gcm(key, new Uint8Array(12)).decrypt(sealed);
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
