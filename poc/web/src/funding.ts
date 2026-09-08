/** Funding wallet of the page, secret kept in localStorage, test funds only. */

import { createKeyPairSignerFromBytes, type KeyPairSigner } from "@solana/kit";
import { ed25519 } from "@noble/curves/ed25519.js";

const STORAGE_KEY = "zolana-poc-funding-seed";

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function unhex(text: string): Uint8Array | undefined {
  if (!/^[0-9a-f]{64}$/u.test(text)) return undefined;
  return Uint8Array.from(text.match(/../gu) ?? [], (pair) => Number.parseInt(pair, 16));
}

function seed(): Uint8Array {
  let stored: string | null = null;
  try {
    stored = globalThis.localStorage?.getItem(STORAGE_KEY) ?? null;
  } catch {
    stored = null;
  }
  const existing = stored === null ? undefined : unhex(stored);
  if (existing !== undefined) return existing;
  const fresh = crypto.getRandomValues(new Uint8Array(32));
  try {
    globalThis.localStorage?.setItem(STORAGE_KEY, hex(fresh));
  } catch {
    // Storage blocked, wallet lasts one page load.
  }
  return fresh;
}

export async function fundingSigner(): Promise<KeyPairSigner> {
  const secret = seed();
  return await createKeyPairSignerFromBytes(
    Uint8Array.of(...secret, ...ed25519.getPublicKey(secret)),
  );
}

export function forgetFundingWallet(): void {
  try {
    globalThis.localStorage?.removeItem(STORAGE_KEY);
  } catch {
    // Storage blocked.
  }
}
