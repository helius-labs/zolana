import { sha256 } from "../interface/internal.js";
import { P256PublicKey } from "../keypair/public-key.js";

import { RingError } from "./error.js";
import { checkedReaderKey, readerKeyBytes } from "./reader.js";
import type { RingReadSigner, WebAuthnSignature } from "./rpc.js";

export interface Passkey {
  readonly credentialId: Uint8Array;
  readonly publicKey: P256PublicKey;
}

const ES256 = -7;
/** SPKI DER of a P-256 key ends with the 65-byte uncompressed point. */
const UNCOMPRESSED_POINT_LENGTH = 65;

/** Only ES256 is offered, the authenticator always answers with a P-256 key. */
export async function createPasskey(
  input: Readonly<{ rpName: string; userName: string }>,
): Promise<Passkey> {
  const credentials = webAuthn();
  const userId = new Uint8Array(16);
  crypto.getRandomValues(userId);
  const credential = (await credentials.create({
    publicKey: {
      rp: { name: input.rpName },
      user: { id: userId, name: input.userName, displayName: input.userName },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: "public-key", alg: ES256 }],
      authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
    },
  })) as PublicKeyCredential | null;
  const response = credential?.response as AuthenticatorAttestationResponse | undefined;
  const spki = response?.getPublicKey?.();
  if (!credential || !spki || response?.getPublicKeyAlgorithm?.() !== ES256) {
    throw new RingError("RING_PASSKEY", { details: { reason: "no ES256 credential" } });
  }
  const point = new Uint8Array(spki).slice(-UNCOMPRESSED_POINT_LENGTH);
  return Object.freeze({
    credentialId: new Uint8Array(credential.rawId),
    publicKey: P256PublicKey.fromUncompressed(point),
  });
}

/** The challenge is the attestation's SHA-256, the RPC recomputes it. */
export function passkeyReader(passkey: Passkey): RingReadSigner {
  return Object.freeze({
    reader: readerKeyBytes(checkedReaderKey(passkey.publicKey)),
    async sign(message: Uint8Array): Promise<WebAuthnSignature> {
      const credential = (await webAuthn().get({
        publicKey: {
          challenge: bufferSource(sha256(message)),
          allowCredentials: [{ type: "public-key", id: bufferSource(passkey.credentialId) }],
          userVerification: "required",
        },
      })) as PublicKeyCredential | null;
      const response = credential?.response as AuthenticatorAssertionResponse | undefined;
      if (!response) {
        throw new RingError("RING_PASSKEY", { details: { reason: "no assertion" } });
      }
      return Object.freeze({
        signature: new Uint8Array(response.signature),
        authenticatorData: new Uint8Array(response.authenticatorData),
        clientDataJSON: new Uint8Array(response.clientDataJSON),
      });
    },
  });
}

/** WebAuthn wants an `ArrayBuffer`-backed view. */
function bufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

function webAuthn(): CredentialsContainer {
  const credentials = globalThis.navigator?.credentials;
  if (!credentials) {
    throw new RingError("RING_PASSKEY", { details: { reason: "WebAuthn is unavailable" } });
  }
  return credentials;
}
