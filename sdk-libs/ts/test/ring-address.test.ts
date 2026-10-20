import { readFileSync } from "node:fs";

import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  InboxSecret,
  KeypairError,
  RingAddress,
  RingPaymentRequest,
  ShieldedAddress,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  type Bytes32,
} from "../src/keypair/index.js";

type ValidCase = Readonly<{
  name: string;
  uri: string;
  recipient: string;
  ring_program_id: string;
  inbox_secret: string;
  amount: string | null;
  mint: string | null;
  label: string | null;
}>;

type RejectedCase = Readonly<{ name: string; uri: string; error: string }>;

const vectors = JSON.parse(
  readFileSync(new URL("../../../test-vectors/ring_address.json", import.meta.url), "utf8"),
) as Readonly<{ valid: readonly ValidCase[]; rejected: readonly RejectedCase[] }>;

function bytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function rustVariant(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof KeypairError) return error.rustVariant ?? error.code;
    throw error;
  }
  throw new Error("expected a KeypairError");
}

describe("shared ring address vectors (test-vectors/ring_address.json)", () => {
  it("parses and prints every valid request", () => {
    expect(vectors.valid.length).toBeGreaterThanOrEqual(3);
    for (const vector of vectors.valid) {
      const request = RingPaymentRequest.parse(vector.uri);
      expect(request.toString(), vector.name).toBe(vector.uri);
      expect(hex(request.address.recipient.toBytes())).toBe(vector.recipient);
      expect(request.address.ringProgramId).toBe(vector.ring_program_id);
      expect(hex(request.address.inboxSecret.toBytes())).toBe(vector.inbox_secret);
      expect(request.amount).toBe(vector.amount === null ? undefined : BigInt(vector.amount));
      expect(request.mint).toBe(vector.mint ?? undefined);
      expect(request.label).toBe(vector.label ?? undefined);
      expect(RingAddress.fromBase58(request.address.toBase58()).toBytes()).toEqual(
        request.address.toBytes(),
      );
    }
  });

  it("rejects every malformed request with the Rust variant", () => {
    expect(vectors.rejected.length).toBeGreaterThanOrEqual(13);
    for (const vector of vectors.rejected) {
      expect(
        rustVariant(() => RingPaymentRequest.parse(vector.uri)),
        vector.name,
      ).toBe(vector.error);
    }
  });

  it("builds the fixture address from the wallet keys", () => {
    const vector = vectors.valid[0];
    if (vector === undefined) throw new Error("no valid vector");
    const recipient = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(7) as Bytes32),
    ).shieldedAddress();
    const inboxSecret = ViewingKey.fromBytes(new Uint8Array(32).fill(0x21) as Bytes32).inboxSecret(
      0,
    );
    const ringAddress = new RingAddress({
      recipient,
      ringProgramId: address(vector.ring_program_id),
      inboxSecret,
    });
    expect(new RingPaymentRequest({ address: ringAddress }).toString()).toBe(vector.uri);
    expect(hex(ShieldedAddress.fromBytes(bytes(vector.recipient)).toBytes())).toBe(
      vector.recipient,
    );
    expect(InboxSecret.fromBytes(bytes(vector.inbox_secret)).toBytes()).toEqual(
      inboxSecret.toBytes(),
    );
  });

  it("round-trips every field", () => {
    const base = RingPaymentRequest.parse(vectors.valid[0]?.uri ?? "");
    const request = new RingPaymentRequest({
      address: base.address,
      amount: (1n << 64n) - 1n,
      mint: address("5i1Ty3d3n2c3hYwdeaxkhtgMMSJUCiKYdpZK9TmPc5un"),
      label: "a=b&c?d/\u00e9 !*'()",
    });
    const parsed = RingPaymentRequest.parse(request.toString());
    expect(parsed.toString()).toBe(request.toString());
    expect(parsed.amount).toBe(request.amount);
    expect(parsed.mint).toBe(request.mint);
    expect(parsed.label).toBe(request.label);
  });
});
