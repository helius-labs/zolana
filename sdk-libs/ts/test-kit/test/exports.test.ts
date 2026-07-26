import { describe, expect, it } from "vitest";

import * as root from "../src/index.js";

/**
 * The root entry is the annex contract documented in
 * `planning/typescript-sdk-port/public-exports.md`. Broader helpers live on
 * `@zolana/test-kit/node` and are outside SDK semver.
 */
describe("public exports", () => {
  it("pins the root entry point", () => {
    expect(Object.keys(root).sort()).toEqual([
      "TestKitError",
      "createTestWallet",
      "fixtureBytes",
      "startLocalStack",
    ]);
  });

  it("keeps the root free of the Node annex helpers", () => {
    expect("TestRpc" in root).toBe(false);
    expect("TestIndexer" in root).toBe(false);
    expect("createE2eHarness" in root).toBe(false);
    expect("FIXTURES_ROOT" in root).toBe(false);
  });
});
