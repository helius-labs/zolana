import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import report from "../../api-reports/test-kit.json" with { type: "json" };
import * as fixtures from "../src/fixtures/index.js";
import * as root from "../src/index.js";
import * as node from "../src/node/index.js";

/**
 * Closed `TestKitErrorCode` union from `src/error.ts`. Kept here rather than
 * published so the private annex does not grow a new root export solely for
 * the exhaustiveness pin.
 */
const TEST_KIT_ERROR_CODES = [
  "TEST_KIT_ABORTED",
  "TEST_KIT_FIXTURE",
  "TEST_KIT_INVALID_CONFIG",
  "TEST_KIT_PROCESS",
  "TEST_KIT_READINESS",
  "TEST_KIT_RPC",
  "TEST_KIT_TIMEOUT",
] as const;

function reportValues(entryPoint: keyof typeof report.entryPoints): string[] {
  return report.entryPoints[entryPoint]
    .filter((entry) => entry.kind === "value")
    .map((entry) => entry.name)
    .sort();
}

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
    expect(reportValues(".")).toEqual([
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

  it("pins the node annex value exports to the api report", () => {
    expect(Object.keys(node).sort()).toEqual(reportValues("./node"));
  });

  it("pins the fixtures entry value exports to the api report", () => {
    expect(Object.keys(fixtures).sort()).toEqual(reportValues("./fixtures"));
  });

  it("keeps TEST_KIT_ERROR_CODES closed over every code the package raises", async () => {
    const directory = fileURLToPath(new URL("../src", import.meta.url));
    const files = (await readdir(directory, { recursive: true })).filter((entry) =>
      entry.endsWith(".ts"),
    );
    const raised = new Set<string>();
    for (const file of files) {
      if (file === "error.ts" || file.endsWith(`${path.sep}error.ts`)) continue;
      const source = await readFile(path.join(directory, file), "utf8");
      for (const match of source.matchAll(/"(TEST_KIT_[A-Z0-9_]+)"/g)) {
        raised.add(match[1]!);
      }
    }
    expect([...raised].sort()).toStrictEqual([...TEST_KIT_ERROR_CODES].sort());
  });
});
