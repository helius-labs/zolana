import { readFileSync, writeFileSync } from "node:fs";

import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";

import type { Bytes31, Bytes32, Bytes64 } from "../../src/bytes.js";
import { NullifierKey, SigningKey, ViewingKey, sha256Be } from "../../src/index.js";
import { fromHex, toHex } from "./certification.js";

/**
 * The other suites replay Rust into TypeScript. This one runs the direction a
 * replay cannot cover: TypeScript produces the material and commits it, and
 * `sdk-libs/keypair/tests/key_certification_reverse.rs` verifies every entry
 * with the Rust implementation. Neither side can drift without one of the two
 * tests failing.
 *
 * Regenerate with `UPDATE_KEY_CERTIFICATION_VECTORS=1`, then re-run the Rust
 * test; a regeneration that Rust does not accept is a divergence, not a
 * refresh.
 */
const target = new URL("../../../vectors/key-certification-typescript-v1.json", import.meta.url);

const P256_ORDER =
  115_792_089_210_356_248_762_697_446_949_407_573_529_996_955_224_135_760_342_422_259_061_068_512_044_369n;

function seed(byte: number): Bytes32 {
  return Uint8Array.from({ length: 32 }, (_, index) => (byte + index * 2) & 0xff) as Bytes32;
}

function digest(label: string): Bytes32 {
  return sha256(new TextEncoder().encode(label)) as Bytes32;
}

/** The nullifier and transaction-key rails take BN254 field elements. */
function fieldDigest(label: string): Bytes32 {
  return sha256Be(new TextEncoder().encode(label));
}

function belowOrder(bytes: Uint8Array): boolean {
  return BigInt(`0x${toHex(bytes)}`) < P256_ORDER;
}

function produce(): unknown {
  const p256Secret = seed(3);
  const p256 = SigningKey.fromBytes(p256Secret);
  const ed25519Secret = seed(17);
  const ed25519 = SigningKey.fromEd25519Bytes(ed25519Secret);
  const nullifier = NullifierKey.fromSigningKey(SigningKey.fromBytes(p256Secret));
  const viewing = ViewingKey.fromBytes(seed(29));

  const prehashes = ["reverse/0", "reverse/1", "reverse/2", "reverse/3"].map(digest);
  expect(prehashes.every(belowOrder), "prehashes stay below the group order").toBe(true);

  const messages = [new Uint8Array(), Uint8Array.from([0x2a]), digest("reverse/message")];

  return {
    version: 1,
    note: "Produced by @zolana/keypair; verified by sdk-libs/keypair/tests/key_certification_reverse.rs.",
    p256: {
      secretBytes: toHex(p256Secret),
      taggedPublicKeyBytes: toHex(p256.publicKey().toBytes()),
      signatures: prehashes.map((prehash) => ({
        digestBytes: toHex(prehash),
        signatureBytes: toHex(p256.sign(prehash)),
      })),
    },
    ed25519: {
      secretBytes: toHex(ed25519Secret),
      taggedPublicKeyBytes: toHex(ed25519.publicKey().toBytes()),
      signatures: messages.map((message) => ({
        messageBytes: toHex(message),
        signatureBytes: toHex(ed25519.sign(message)),
      })),
    },
    nullifiers: {
      signingSecretBytes: toHex(p256Secret),
      secretBytes: toHex(nullifier.secretBytes()),
      publicKeyBytes: toHex(nullifier.publicKey()),
      derivations: [0x03, 0x00, 0xff].map((byte) => {
        const blinding = new Uint8Array(31).fill(byte) as Bytes31;
        const utxoHash = fieldDigest(`reverse/utxo/${byte}`);
        return {
          utxoHashBytes: toHex(utxoHash),
          blindingBytes: toHex(blinding),
          nullifierBytes: toHex(nullifier.nullifier(utxoHash, blinding)),
        };
      }),
    },
    viewing: {
      secretBytes: toHex(viewing.secretBytes()),
      publicKeyBytes: toHex(viewing.publicKey().toBytes()),
      senderTagBytes: [0n, 1n, 2n ** 64n - 1n].map((counter) => ({
        counter: counter.toString(),
        tagBytes: toHex(viewing.senderViewTag(counter)),
      })),
      transactionKeys: ["reverse/nullifier/0", "reverse/nullifier/1"].map((label) => {
        const firstNullifier = fieldDigest(label);
        const derived = viewing.transactionViewingKey(firstNullifier);
        return {
          firstNullifierBytes: toHex(firstNullifier),
          secretBytes: toHex(derived.secretBytes()),
          publicKeyBytes: toHex(derived.publicKey().toBytes()),
        };
      }),
    },
  };
}

describe("TypeScript-produced corpus for Rust to verify", () => {
  it("matches the committed corpus", () => {
    const produced = `${JSON.stringify(produce(), null, 2)}\n`;
    if (process.env.UPDATE_KEY_CERTIFICATION_VECTORS === "1") {
      writeFileSync(target, produced);
    }
    expect(readFileSync(target, "utf8")).toBe(produced);
  });

  it("verifies its own corpus, so a Rust failure isolates to the boundary", () => {
    const parsed = JSON.parse(readFileSync(target, "utf8")) as {
      p256: { secretBytes: string; signatures: { digestBytes: string; signatureBytes: string }[] };
      ed25519: {
        secretBytes: string;
        signatures: { messageBytes: string; signatureBytes: string }[];
      };
    };

    const p256 = SigningKey.fromBytes(fromHex(parsed.p256.secretBytes) as Bytes32);
    for (const entry of parsed.p256.signatures) {
      expect(
        p256.verify(fromHex(entry.digestBytes), fromHex(entry.signatureBytes) as Bytes64),
      ).toBe(true);
    }

    const ed25519 = SigningKey.fromEd25519Bytes(fromHex(parsed.ed25519.secretBytes) as Bytes32);
    for (const entry of parsed.ed25519.signatures) {
      expect(
        ed25519.verify(fromHex(entry.messageBytes), fromHex(entry.signatureBytes) as Bytes64),
      ).toBe(true);
    }
  });
});
