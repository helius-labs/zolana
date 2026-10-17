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
