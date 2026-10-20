import { getAddressDecoder } from "@solana/kit";
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";

import vector from "../../../test-vectors/ring_spend_message.json" with { type: "json" };
import {
  RING_SPEND_MESSAGE_PREFIX,
  ringSpendMessage,
  transactMessageHash,
} from "../src/transaction/instructions/transact.js";
import type { Bytes32 } from "../src/keypair/index.js";

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function bytes(value: string): Bytes32 {
  return Uint8Array.from(Buffer.from(value, "hex")) as Bytes32;
}

describe("ringSpendMessage known-answer vector", () => {
  const ring = getAddressDecoder().decode(bytes(vector.ring_program_id));
  const digest = transactMessageHash(
    bytes(vector.private_tx_hash),
    bytes(vector.external_data_hash),
  );
  const message = ringSpendMessage(ring, digest);

  it("hashes the committed digest", () => {
    expect(hex(digest)).toBe(vector.digest);
  });

  it("builds prefix || ring || digest", () => {
    expect(new TextDecoder().decode(RING_SPEND_MESSAGE_PREFIX)).toBe(vector.prefix);
    expect(message.length).toBe(84);
    expect(hex(message)).toBe(vector.message);
  });

  it("carries the committed deterministic signature", () => {
    const publicKey = ed25519.getPublicKey(bytes(vector.seed));
    expect(hex(publicKey)).toBe(vector.public_key);
    expect(hex(ed25519.sign(message, bytes(vector.seed)))).toBe(vector.signature);
    expect(ed25519.verify(bytes(vector.signature), message, publicKey)).toBe(true);
    expect(ed25519.verify(bytes(vector.signature), digest, publicKey)).toBe(false);
  });
});
