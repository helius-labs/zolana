import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import * as root from "../src/index.js";

const readText = readFileSync as unknown as (path: URL, encoding: "utf8") => string;
const rustSource = (): string =>
  readText(new URL("../../../smart-account-client/src/lib.rs", import.meta.url), "utf8");

/**
 * Rust name to TypeScript name for every `pub` item in the crate. Written out
 * rather than derived, because the port renames deliberately: `_pda` becomes
 * `Address`, and `_ix` becomes `Instruction`. A mechanical rule would let a
 * rename pass unnoticed.
 */
const RUST_TO_TS: Record<string, string> = {
  SMART_ACCOUNT_PROGRAM_ID: "SMART_ACCOUNT_PROGRAM_ID",
  program_config_pda: "programConfigAddress",
  treasury_pda: "treasuryAddress",
  settings_pda: "settingsAddress",
  smart_account_pda: "smartAccountAddress",
  create_smart_account_ix: "createSmartAccountInstruction",
  execute_sync_ix: "executeSyncInstruction",
};

describe("public exports", () => {
  it("pins the runtime export surface", () => {
    expect(Object.keys(root).sort()).toEqual([
      "SMART_ACCOUNT_PROGRAM_ID",
      "SmartAccountClientError",
      "allPermissions",
      "createSmartAccountInstruction",
      "executeSyncInstruction",
      "programConfigAddress",
      "settingsAddress",
      "smartAccountAddress",
      "treasuryAddress",
    ]);
  });

  it("carries every public Rust value across", () => {
    const source = rustSource();
    const declared = [...source.matchAll(/^pub (?:const|fn) (\w+)/gm)].map((match) => match[1]);
    expect(declared.sort()).toEqual(Object.keys(RUST_TO_TS).sort());
    for (const name of declared) {
      expect(root).toHaveProperty(RUST_TO_TS[name] as string);
    }
  });

  /**
   * `Permissions` and `SmartAccountSigner` are Rust structs and TypeScript
   * interfaces, so they erase at runtime and cannot appear above. The port adds
   * `allPermissions` for the mask the Rust callers write inline, and an error
   * type for the boundaries Rust reports by panicking.
   */
  it("accounts for the two names that are types and the two the port adds", () => {
    const source = rustSource();
    expect(source).toContain("pub struct Permissions");
    expect(source).toContain("pub struct SmartAccountSigner");
    expect(root.allPermissions()).toEqual({ mask: 0b111 });
    expect(new root.SmartAccountClientError("SMART_ACCOUNT_INVALID_INDEX", "x").name).toBe(
      "SmartAccountClientError",
    );
  });

  it("publishes one entry point", () => {
    const manifest = JSON.parse(
      readText(new URL("../package.json", import.meta.url), "utf8"),
    ) as Record<string, unknown>;
    expect(Object.keys(manifest.exports as Record<string, unknown>)).toEqual(["."]);
    expect(manifest.files).toEqual(["dist"]);
    expect(manifest.sideEffects).toBe(false);
  });
});
