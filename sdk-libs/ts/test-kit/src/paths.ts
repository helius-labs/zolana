/// <reference types="node" />

import path from "node:path";
import { fileURLToPath } from "node:url";

import { TestKitError } from "./error.js";

/**
 * The kit runs from `src/` under a source checkout and from `dist/es/` once
 * built, which sits one directory deeper. Counting `..` segments is therefore
 * right in one layout and wrong in the other, so walk up to the package
 * directory that both layouts sit under.
 */
function packageRoot(): string {
  let directory = path.dirname(fileURLToPath(import.meta.url));
  while (path.basename(directory) !== "test-kit") {
    const parent = path.dirname(directory);
    if (parent === directory) {
      throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
        details: { field: "packageRoot", reason: "missing" },
      });
    }
    directory = parent;
  }
  return directory;
}

/** `sdk-libs/ts/fixtures`, the committed fixture tree with its manifest. */
export const FIXTURES_ROOT = path.resolve(packageRoot(), "../fixtures");

/** The repository root, which the local stack reads built binaries from. */
export const WORKSPACE_ROOT = path.resolve(packageRoot(), "../../..");
