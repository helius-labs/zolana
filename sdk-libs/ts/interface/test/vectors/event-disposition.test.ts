import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import * as interfaceRoot from "../../src/index.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../../");

function collectTs(relativeDir: string): string[] {
  const root = path.join(repoRoot, relativeDir);
  return readdirSync(root, { recursive: true, encoding: "utf8" })
    .filter((entry) => entry.endsWith(".ts"))
    .map((entry) => readFileSync(path.join(root, entry), "utf8"));
}

/**
 * E05 / E06 confirmation artifact: the event-emission layer stays with Photon
 * and `@zolana/indexer-api` JSON, not `@zolana/interface`. These assertions fail
 * if a later change publishes `GeneralEvent` decoding or turns the
 * `program-test` feature on by default.
 */
describe("event crate disposition", () => {
  it("does not export GeneralEvent emission surface from @zolana/interface", () => {
    const names = new Set(Object.keys(interfaceRoot));
    for (const name of [
      "GeneralEvent",
      "EventKind",
      "DepositWithdraw",
      "encodeEventInstruction",
      "encodeEventInstructionWith",
      "encodeEventPayload",
      "OutputUtxo",
    ]) {
      expect(names.has(name)).toBe(false);
      expect((interfaceRoot as Record<string, unknown>)[name]).toBeUndefined();
    }
  });

  it("keeps zolana-event program-test feature off by default", () => {
    const cargo = readFileSync(path.join(repoRoot, "program-libs/event/Cargo.toml"), "utf8");
    const features = cargo.split("[features]")[1] ?? "";
    expect(features).toMatch(/program-test\s*=\s*\[\]/);
    const defaultLine = [...features.matchAll(/^\s*default\s*=\s*(\[[^\]]*\])/gm)].map(
      (match) => match[1],
    );
    for (const value of defaultLine) {
      expect(value).not.toContain("program-test");
    }
  });

  it("ships no decoder for program_test event helpers in the SDK trees that could", () => {
    const forbidden =
      /\b(GeneralEvent|EventKind|encode_event_instruction|encodeEventInstruction|decodeGeneralEvent)\b/;
    for (const relative of [
      "sdk-libs/ts/interface/src",
      "sdk-libs/ts/indexer-api/src",
      "sdk-libs/ts/api/src",
    ]) {
      for (const source of collectTs(relative)) {
        expect(source).not.toMatch(forbidden);
      }
    }
    // test-kit may hold plain shapes for harness use; it must not decode the
    // emit_event borsh body that program_test.rs parses.
    for (const source of collectTs("sdk-libs/ts/test-kit/src")) {
      expect(source).not.toMatch(/\b(EventKind|encode_event_instruction|BorshDeserialize)\b/);
    }
  });
});
