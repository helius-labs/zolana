import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { RING_POLICY_SUPPORTED_SHAPES } from "../src/interface/shape.js";
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
      expectedProvingKey({ circuit: "transfer-confidential", nInputs: 1, nOutputs: 2 }),
      expectedProvingKey({ circuit: "transfer-ring", nInputs: 49, nOutputs: 2 }),
      expectedProvingKey({ circuit: "transfer-ring-authority", nInputs: 2, nOutputs: 2 }),
      expectedProvingKey({ circuit: "merge", nInputs: 24 }),
      expectedProvingKey({ circuit: "merge-ring", nInputs: 52 }),
      expectedProvingKey({ circuit: "custom-ring-base" }),
      expectedProvingKey({ circuit: "custom-ring-policy" }),
    ];
    expect(names).toEqual(
      [
        "transfer_confidential_1_2.key",
        "transfer_ring_49_2.key",
        "transfer_ring_authority_2_2.key",
        "merge_24_1.key",
        "merge_ring_52_1.key",
        "custom_ring_base.key",
        "custom_ring_policy.key",
      ].map((name) => ({ name, sha256: lock.keys[name]?.sha256 })),
    );
  });

  it("refuses malformed shaped request flags", () => {
    const request = {
      circuit: "custom-ring-policy-shaped",
      shape: { inputs: 1, outputs: 2 },
      registrySubtree: false,
    } as const;
    Reflect.set(request, "registrySubtree", "false");
    expect(() => expectedProvingKey(request)).toThrow(InterfaceError);
  });

  it("pins both registry path variants for every supported ordinary shape", () => {
    for (const shape of RING_POLICY_SUPPORTED_SHAPES) {
      for (const registrySubtree of [false, true]) {
        const key = expectedProvingKey({
          circuit: "custom-ring-policy-shaped",
          shape,
          registrySubtree,
        });
        expect(key.name).toBe(
          `custom_ring_policy_${shape.inputs}_${shape.outputs}${registrySubtree ? "_subtree" : ""}.key`,
        );
        expect(key.sha256).toBe(lock.keys[key.name]?.sha256);
      }
    }
    expect(() =>
      expectedProvingKey({
        circuit: "custom-ring-policy-shaped",
        shape: { inputs: 1, outputs: 8 },
      }),
    ).toThrow(InterfaceError);
    expect(() =>
      expectedProvingKey({
        circuit: "custom-ring-policy-shaped",
        shape: { inputs: 32, outputs: 2 },
      }),
    ).toThrow(InterfaceError);
    expect(() =>
      expectedProvingKey({
        circuit: "custom-ring-delegate-policy-shaped",
        shape: { inputs: 2, outputs: 4 },
      }),
    ).toThrow(InterfaceError);
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
