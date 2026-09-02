import { getBase64Decoder, getBase64Encoder } from "@solana/kit";

import type { ShieldedKeypair } from "../keypair/shielded.js";
import { deserializeWallet } from "../transaction/wallet/persistence.js";

import { WalletError } from "./error.js";
import { equalBytes } from "./internal.js";
import type { WalletStateCipher } from "./persisted.js";

const SNAPSHOT_DOMAIN = "zolana/wallet-snapshot/v1";
const ENVELOPE_VERSION = 1;

const base64Decoder = getBase64Decoder();
const base64Encoder = getBase64Encoder();
const encoder = new TextEncoder();
const decoder = new TextDecoder();

interface SealedEnvelope {
  readonly v: number;
  readonly snapshotVersion: number;
  readonly nonce: string;
  readonly data: string;
}

/**
 * AES-256-GCM over the snapshot, keyed from the keypair's viewing secret under
 * the snapshot domain. The tag binds the wallet identity and the snapshot
 * version, a modified snapshot or one sealed for another wallet fails to open.
 */
export function walletSnapshotCipher(keypair: ShieldedKeypair): WalletStateCipher {
  const identity = keypair.shieldedAddress().toBytes();
  return Object.freeze({
    async seal(snapshot: string): Promise<string> {
      const snapshotVersion = checkedSnapshot(snapshot, identity);
      const key = await snapshotKey(keypair);
      const nonce = new Uint8Array(12);
      globalThis.crypto.getRandomValues(nonce);
      const data = new Uint8Array(
        await globalThis.crypto.subtle.encrypt(
          { name: "AES-GCM", iv: nonce, additionalData: sealedContext(identity, snapshotVersion) },
          key,
          encoder.encode(snapshot),
        ),
      );
      const envelope: SealedEnvelope = {
        v: ENVELOPE_VERSION,
        snapshotVersion,
        nonce: base64Decoder.decode(nonce),
        data: base64Decoder.decode(data),
      };
      return JSON.stringify(envelope);
    },
    async open(sealed: string): Promise<string> {
      const envelope = parseEnvelope(sealed);
      const key = await snapshotKey(keypair);
      let plaintext: ArrayBuffer;
      try {
        plaintext = await globalThis.crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: new Uint8Array(base64Encoder.encode(envelope.nonce)),
            additionalData: sealedContext(identity, envelope.snapshotVersion),
          },
          key,
          new Uint8Array(base64Encoder.encode(envelope.data)),
        );
      } catch (cause) {
        throw new WalletError("WALLET_SNAPSHOT", { cause });
      }
      const snapshot = decoder.decode(plaintext);
      if (checkedSnapshot(snapshot, identity) !== envelope.snapshotVersion) {
        throw new WalletError("WALLET_SNAPSHOT");
      }
      return snapshot;
    },
  });
}

function checkedSnapshot(snapshot: string, identity: Uint8Array): number {
  let version: unknown;
  try {
    version = (JSON.parse(snapshot) as Readonly<{ version?: unknown }>).version;
  } catch (cause) {
    throw new WalletError("WALLET_SNAPSHOT", { cause });
  }
  if (typeof version !== "number" || !Number.isInteger(version) || version < 0 || version > 255) {
    throw new WalletError("WALLET_SNAPSHOT");
  }
  let snapshotIdentity: Uint8Array;
  try {
    snapshotIdentity = deserializeWallet(snapshot).identity.toBytes();
  } catch (cause) {
    throw new WalletError("WALLET_SNAPSHOT", { cause });
  }
  if (!equalBytes(snapshotIdentity, identity)) throw new WalletError("WALLET_SNAPSHOT");
  return version;
}

function parseEnvelope(sealed: string): SealedEnvelope {
  let value: unknown;
  try {
    value = JSON.parse(sealed);
  } catch (cause) {
    throw new WalletError("WALLET_SNAPSHOT", { cause });
  }
  if (typeof value !== "object" || value === null) throw new WalletError("WALLET_SNAPSHOT");
  const envelope = value as Readonly<Record<string, unknown>>;
  const snapshotVersion = envelope["snapshotVersion"];
  if (
    envelope["v"] !== ENVELOPE_VERSION ||
    typeof snapshotVersion !== "number" ||
    !Number.isInteger(snapshotVersion) ||
    snapshotVersion < 0 ||
    snapshotVersion > 255 ||
    typeof envelope["nonce"] !== "string" ||
    typeof envelope["data"] !== "string"
  ) {
    throw new WalletError("WALLET_SNAPSHOT");
  }
  return {
    v: ENVELOPE_VERSION,
    snapshotVersion,
    nonce: envelope["nonce"],
    data: envelope["data"],
  };
}

function sealedContext(identity: Uint8Array, snapshotVersion: number): Uint8Array<ArrayBuffer> {
  const domain = encoder.encode(SNAPSHOT_DOMAIN);
  const context = new Uint8Array(domain.length + identity.length + 1);
  context.set(domain, 0);
  context.set(identity, domain.length);
  context[context.length - 1] = snapshotVersion;
  return context;
}

async function snapshotKey(keypair: ShieldedKeypair): Promise<CryptoKey> {
  const viewing = keypair.viewingKey();
  const secret = viewing.secretBytes();
  const ikmBytes = new Uint8Array(secret);
  try {
    const ikm = await globalThis.crypto.subtle.importKey("raw", ikmBytes, "HKDF", false, [
      "deriveKey",
    ]);
    return await globalThis.crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: encoder.encode(SNAPSHOT_DOMAIN),
      },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    ikmBytes.fill(0);
    secret.fill(0);
    viewing.destroy();
  }
}
