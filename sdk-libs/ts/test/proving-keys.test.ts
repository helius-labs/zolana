import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { InterfaceError } from "../src/interface/errors.js";
import { RING_AUTHORITY_SHAPES, SPP_SUPPORTED_SHAPES } from "../src/interface/shape.js";
import {
  PROVING_KEY_SHA256S,
  RING_KEYS,
  expectedProvingKey,
  ringProvingKey,
} from "../src/interface/proving-keys.js";

type Lockfile = { keys: Record<string, { sha256: string }> };

// The file the prover verifies every key it loads against; the Rust
// `vk_proving_key_lock` tests pin the verifying keys' digests to it too.
const lock = JSON.parse(
  readFileSync(
    new URL("../../../prover/server/prover/provingkeys/proving-keys.lock", import.meta.url),
    "utf8",
  ),
) as Lockfile;

/** Go `RingKeyFile`. */
function ringKeyFile(name: string): string {
  return `${name.replaceAll("-", "_")}.key`;
}

const RING_KEY_FILES = new Set(RING_KEYS.map((key) => ringKeyFile(key.name)));

describe("PROVING_KEY_SHA256S", () => {
  it("equals proving-keys.lock over every key a client can request", () => {
    const entries = Object.entries(lock.keys);
    const retired = entries.filter(
      ([name]) => name.startsWith("custom_ring_") && !RING_KEY_FILES.has(name),
    );
    const requestable = entries.filter((entry) => !retired.includes(entry));
    expect({ ...PROVING_KEY_SHA256S }).toEqual(
      Object.fromEntries(requestable.map(([name, entry]) => [name, entry.sha256])),
    );
    for (const [name] of retired) expect(Object.hasOwn(PROVING_KEY_SHA256S, name)).toBe(false);
  });
});

describe("expectedProvingKey", () => {
  it("names the key file the prover proves each circuit with", () => {
    const names = [
      expectedProvingKey({ circuit: "transfer-confidential", nInputs: 1, nOutputs: 2 }),
      expectedProvingKey({ circuit: "transfer-ring", nInputs: 49, nOutputs: 2 }),
      expectedProvingKey({ circuit: "transfer-ring-authority", nInputs: 2, nOutputs: 2 }),
      expectedProvingKey({ circuit: "transfer-eddsa-ring", nInputs: 2, nOutputs: 2 }),
      expectedProvingKey({ circuit: "merge", nInputs: 24 }),
      expectedProvingKey({ circuit: "merge-ring", nInputs: 52 }),
    ];
    expect(names).toEqual(
      [
        "transfer_confidential_1_2.key",
        "transfer_ring_49_2.key",
        "transfer_ring_authority_2_2.key",
        "transfer_eddsa_ring_2_2.key",
        "merge_24_1.key",
        "merge_ring_52_1.key",
      ].map((name) => ({ name, sha256: lock.keys[name]?.sha256 })),
    );
  });

  it("pins a ring authority key for exactly the ring authority shapes", () => {
    for (const shape of SPP_SUPPORTED_SHAPES) {
      const request = {
        circuit: "transfer-ring-authority",
        nInputs: shape.inputs,
        nOutputs: shape.outputs,
      } as const;
      if (RING_AUTHORITY_SHAPES.includes(shape))
        expect(expectedProvingKey(request).name).toBe(
          `transfer_ring_authority_${String(shape.inputs)}_${String(shape.outputs)}.key`,
        );
      else
        expect(() => expectedProvingKey(request)).toThrow(
          expect.objectContaining({ code: "INTERFACE_INVALID_SHAPE" }),
        );
    }
  });

  it("throws for a shape without a committed verifying key", () => {
    for (const request of [
      { circuit: "transfer-ring", nInputs: 2, nOutputs: 7 },
      { circuit: "transfer-confidential", nInputs: 0, nOutputs: 1 },
      { circuit: "merge", nInputs: 9 },
      { circuit: "transfer-confidential", nInputs: 1, nOutputs: 1 },
      { circuit: "transfer-ring", nInputs: 36, nOutputs: 2 },
      { circuit: "transfer-ring-authority", nInputs: 3, nOutputs: 3 },
      { circuit: "merge", nInputs: 23 },
      { circuit: "merge-ring", nInputs: 36 },
    ] as const) {
      let thrown: unknown;
      try {
        expectedProvingKey(request);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(InterfaceError);
      expect((thrown as InterfaceError).code).toBe("INTERFACE_INVALID_SHAPE");
    }
  });
});

describe("RING_KEYS", () => {
  it("lists every key of ring_keys.rs in its order", () => {
    const rust = readFileSync(
      new URL("../../../custom-rings/interface/src/ring_keys.rs", import.meta.url),
      "utf8",
    );
    const names = [...rust.matchAll(/name: "([a-z0-9-]+)"/gu)].map((match) => match[1]);
    expect(RING_KEYS.map((key) => key.name)).toEqual(names);
  });

  it("answers every ring key from the lock pin, and a key the lock does not pin refuses", () => {
    for (const key of RING_KEYS) {
      const name = ringKeyFile(key.name);
      const sha256 = lock.keys[name]?.sha256;
      if (sha256 === undefined)
        expect(() => ringProvingKey(key.circuit)).toThrow(
          expect.objectContaining({ code: "INTERFACE_INVALID_SHAPE" }),
        );
      else expect(ringProvingKey(key.circuit)).toEqual({ name, sha256 });
    }
  });
});
