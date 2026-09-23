import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { InterfaceError } from "../src/interface/errors.js";
import { expectedProvingKey, PROVING_KEY_SHA256S } from "../src/interface/proving-keys.js";

type Lockfile = { keys: Record<string, { sha256: string }> };

// The file the prover verifies every key it loads against; the Rust
// `vk_proving_key_lock` tests pin the verifying keys' digests to it too.
const lock = JSON.parse(
  readFileSync(
    new URL("../../../prover/server/prover/provingkeys/proving-keys.lock", import.meta.url),
    "utf8",
  ),
) as Lockfile;

describe("PROVING_KEY_SHA256S", () => {
  it("equals proving-keys.lock, no key missing or extra", () => {
    const locked = Object.fromEntries(
      Object.entries(lock.keys).map(([name, entry]) => [name, entry.sha256]),
    );
    expect({ ...PROVING_KEY_SHA256S }).toEqual(locked);
  });
});

describe("expectedProvingKey", () => {
  it("names the key file the prover proves each circuit with", () => {
    const names = [
      expectedProvingKey({ circuit: "transfer-confidential", nInputs: 1, nOutputs: 1 }),
      expectedProvingKey({ circuit: "transfer-ring", nInputs: 36, nOutputs: 2 }),
      expectedProvingKey({ circuit: "merge", nInputs: 8 }),
      expectedProvingKey({ circuit: "custom-ring-base" }),
      expectedProvingKey({ circuit: "custom-ring-policy" }),
    ];
    expect(names).toEqual(
      [
        "transfer_confidential_1_1.key",
        "transfer_ring_36_2.key",
        "merge_8_1.key",
        "custom_ring_base.key",
        "custom_ring_policy.key",
      ].map((name) => ({ name, sha256: lock.keys[name]?.sha256 })),
    );
  });

  it("throws for a shape without a committed verifying key", () => {
    for (const request of [
      { circuit: "transfer-ring", nInputs: 2, nOutputs: 7 },
      { circuit: "transfer-confidential", nInputs: 0, nOutputs: 1 },
      { circuit: "merge", nInputs: 9 },
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
