import { describe, expect, it } from "vitest";
import rust from "../fixtures/idl/rust.json" with { type: "json" };
import shieldedPool from "../idl/shieldedPool.json" with { type: "json" };
import userRegistry from "../idl/userRegistry.json" with { type: "json" };
import { decodeAccount, decodeInstruction, type DecodedValue } from "./idl-decoder.js";

function normalized(value: DecodedValue): unknown {
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Uint8Array) return Buffer.from(value).toString("hex");
  if (Array.isArray(value)) return value.map(normalized);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, normalized(entry)]),
    );
  return value;
}
function programName(value: string) {
  if (value === "shieldedPool" || value === "userRegistry") return value;
  throw new Error(`Unknown fixture program: ${value}`);
}
const fromHex = (value: string) => Uint8Array.from(Buffer.from(value, "hex"));

describe("IDL byte parity with Rust", () => {
  it.each(rust.instructions.map((entry, index) => ({ ...entry, index })))(
    "decodes $program $name [$index]",
    (entry) => {
      const result = decodeInstruction(programName(entry.program), fromHex(entry.hex));
      expect(result.name).toBe(entry.name);
      expect(result.tag).toBe(entry.tag);
      if (entry.expected === null) expect(result.data).toBeNull();
      else expect(normalized(result.data)).toMatchObject(entry.expected);
    },
  );
  it.each(rust.accounts.map((entry, index) => ({ ...entry, index })))(
    "decodes $name account [$index]",
    (entry) => {
      expect(
        normalized(decodeAccount(programName(entry.program), entry.name, fromHex(entry.hex))),
      ).toMatchObject(entry.expected);
    },
  );
  it("covers every instruction tag and event kind", () => {
    for (const [program, idl] of [
      ["shieldedPool", shieldedPool],
      ["userRegistry", userRegistry],
    ] as const) {
      const tags = [
        ...new Set(rust.instructions.filter((x) => x.program === program).map((x) => x.tag)),
      ].sort((a, b) => a - b);
      expect(tags).toEqual(
        idl.program.instructions.map((ix) => ix.arguments[0]?.defaultValue?.number),
      );
    }
    expect(
      rust.instructions.filter((x) => x.name === "emitEvent").map((x) => fromHex(x.hex)[1]),
    ).toEqual([1, 2, 3, 4]);
  });
  it("rejects truncated or trailing instruction bytes", () => {
    for (const entry of rust.instructions) {
      const bytes = fromHex(entry.hex);
      expect(() => decodeInstruction(programName(entry.program), bytes.slice(0, -1))).toThrow();
      expect(() =>
        decodeInstruction(programName(entry.program), Uint8Array.from([...bytes, 255])),
      ).toThrow();
    }
    expect(() => decodeInstruction("shieldedPool", Uint8Array.of(1, 255))).toThrow();
    expect(() => decodeInstruction("shieldedPool", Uint8Array.of(255))).toThrow();
  });
  it("rejects the wrong account discriminator and allocation size", () => {
    for (const entry of rust.accounts) {
      const bytes = fromHex(entry.hex);
      expect(() =>
        decodeAccount(programName(entry.program), entry.name, bytes.slice(0, -1)),
      ).toThrow();
      bytes[0] = 255;
      expect(() => decodeAccount(programName(entry.program), entry.name, bytes)).toThrow();
    }
  });
});
