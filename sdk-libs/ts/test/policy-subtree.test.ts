import { readFileSync } from "node:fs";
import { RING_POLICY_SUPPORTED_SHAPES } from "../src/interface/shape.js";
import { shapedPolicyCircuit } from "../src/interface/proving-keys.js";
import { describe, expect, it } from "vitest";
import { shareMemberSubtree, MEMBER_REGISTRY_CAPACITY } from "../src/interface/member-registry.js";

describe("policy subtree eligibility", () => {
  it("admits shared records and any aligned block in the full registry", () => {
    for (const indices of [
      [],
      [0n, 7n],
      [8n, 15n, 8n],
      [1024n, 1026n],
      [MEMBER_REGISTRY_CAPACITY - 1n],
    ]) {
      expect(shareMemberSubtree(indices)).toBe(true);
    }
  });
  it("keeps scattered records and invalid indices off the smaller path", () => {
    for (const indices of [[7n, 8n], [0n, 1024n], [-1n], [MEMBER_REGISTRY_CAPACITY]]) {
      expect(shareMemberSubtree(indices)).toBe(false);
    }
  });
});

describe("policy shape protocol catalog", () => {
  it("matches every circuit name and rail in the shared Go and Rust catalog", () => {
    const catalog: unknown = JSON.parse(
      readFileSync(new URL("../../../custom-rings/policy-shapes.json", import.meta.url), "utf8"),
    );
    const expected = [
      ...RING_POLICY_SUPPORTED_SHAPES.map((shape) => ({
        ...shape,
        anonymous: false,
        delegate: false,
      })),
      ...[
        { inputs: 2, outputs: 2 },
        { inputs: 2, outputs: 4 },
        { inputs: 3, outputs: 4 },
        { inputs: 4, outputs: 2 },
      ].map((shape) => ({ ...shape, anonymous: true, delegate: false })),
      ...[
        { inputs: 2, outputs: 2 },
        { inputs: 4, outputs: 4 },
      ].map((shape) => ({ ...shape, anonymous: false, delegate: true })),
    ].flatMap((entry) =>
      [false, true].map((subtree) => ({
        ...entry,
        subtree,
        circuit: shapedPolicyCircuit(entry, subtree, entry.delegate, entry.anonymous),
      })),
    );
    expect(catalog).toHaveLength(48);
    expect(catalog).toEqual(expect.arrayContaining(expected));
  });
});
