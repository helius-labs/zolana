import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import type { Bytes32 } from "../src/interface/types.js";
import { ViewingKey } from "../src/keypair/index.js";

const vector = JSON.parse(
  readFileSync(new URL("../../../test-vectors/merge_ring.json", import.meta.url), "utf8"),
) as Readonly<{
  viewing_secret: string;
  ring_program_id: string;
  first_nullifier: string;
  merge_seed: string;
}>;

function bytes(value: string): Bytes32 {
  return Uint8Array.from(
    value.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? [],
  ) as Bytes32;
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("ViewingKey.mergeSeed", () => {
  it("matches the Rust derivation on the shared vector", () => {
    const viewingKey = ViewingKey.fromBytes(bytes(vector.viewing_secret));
    const seed = viewingKey.mergeSeed(bytes(vector.ring_program_id), bytes(vector.first_nullifier));
    expect(hex(seed)).toBe(vector.merge_seed);
  });
});
