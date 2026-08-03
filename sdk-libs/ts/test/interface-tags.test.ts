/**
 * Pins the TypeScript instruction-tag table to the program's canonical tags.
 *
 * The tag byte is the first byte of every instruction, so a stale table means
 * every instruction the SDK builds is dispatched to the wrong handler (or none),
 * and the program answers `InvalidInstructionData` (7000) after ~310 compute
 * units. That failure carries no hint about which side is wrong, so it has to be
 * caught here instead.
 *
 * The expectations are parsed out of `program-libs/event/src/tag.rs` at test time
 * rather than copied into this file. A copied table is just a second thing to
 * forget to update: this way a renumbering on the Rust side fails the suite
 * immediately, which is exactly what did not happen when the tags were last
 * renumbered.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { InstructionTag } from "../src/interface/program.js";

const TAG_SOURCE = fileURLToPath(
  new URL("../../../program-libs/event/src/tag.rs", import.meta.url),
);

/** `CREATE_PROTOCOL_CONFIG` -> `createProtocolConfig`. */
function camelCase(screamingSnake: string): string {
  return screamingSnake
    .toLowerCase()
    .split("_")
    .map((part, index) => (index === 0 ? part : part.charAt(0).toUpperCase() + part.slice(1)))
    .join("");
}

/**
 * Every `pub const NAME: u8 = N;` in the canonical tag module. The event crate is
 * the single source of truth: `zolana_interface` re-exports it (`pub use
 * zolana_event::{tag, tag::InstructionTag}`) and the program dispatches on it.
 */
function canonicalTags(): ReadonlyMap<string, number> {
  const source = readFileSync(TAG_SOURCE, "utf8");
  const tags = new Map<string, number>();
  for (const match of source.matchAll(/^pub const (\w+): u8 = (\d+);/gmu)) {
    const [, name, value] = match;
    if (name === undefined || value === undefined) continue;
    tags.set(camelCase(name), Number(value));
  }
  return tags;
}

describe("instruction tags match the program", () => {
  const canonical = canonicalTags();

  it("parses the canonical tag module", () => {
    // Guards the regex itself: if the Rust file is restructured so nothing
    // matches, every other assertion here would pass vacuously.
    expect(canonical.size).toBeGreaterThan(10);
    expect(canonical.get("deposit")).toBeTypeOf("number");
  });

  it("assigns every instruction the program's tag byte", () => {
    const actual = InstructionTag as Readonly<Record<string, number>>;
    const mismatched = [...canonical]
      .filter(([name, value]) => actual[name] !== value)
      .map(([name, value]) => `${name}: sdk=${String(actual[name])} program=${String(value)}`);
    expect(mismatched).toEqual([]);
  });

  it("defines no tag the program does not have", () => {
    // A leftover name (e.g. a renamed instruction) is as dangerous as a wrong
    // number: it still produces a byte the program will reject or misroute.
    const stale = Object.keys(InstructionTag).filter((name) => !canonical.has(name));
    expect(stale).toEqual([]);
  });

  it("keeps tag bytes unique", () => {
    const values = Object.values(InstructionTag);
    expect(new Set(values).size).toBe(values.length);
  });
});
