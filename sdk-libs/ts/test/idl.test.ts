import { describe, expect, it } from "vitest";
import rust from "../fixtures/idl/rust.json" with { type: "json" };
import shieldedPool from "../idl/shieldedPool.json" with { type: "json" };
import userRegistry from "../idl/userRegistry.json" with { type: "json" };
import { decodeAccount, decodeInstruction, fields, type DecodedValue } from "./idl-decoder.js";

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
  it.each(rust.accountMetas)("matches Rust account roles for $name", (entry) => {
    const idl = entry.program === "userRegistry" ? userRegistry : shieldedPool;
    const instruction = idl.program.instructions.find((ix) => ix.name === entry.name);
    expect(
      instruction?.accounts?.map(({ isWritable, isSigner }) => ({ isWritable, isSigner })),
    ).toEqual(entry.accounts);
  });
  it("covers every circuit selector including cached and committed proofs", () => {
    const selectors = new Set<string>();
    for (const entry of rust.instructions.filter(
      (ix) => [16, 19, 21].includes(ix.tag) && ix.program === "shieldedPool",
    )) {
      const circuit = fields(
        fields(decodeInstruction("shieldedPool", fromHex(entry.hex)).data).circuit,
      );
      if (typeof circuit.variant !== "string") throw new Error("Missing circuit variant");
      selectors.add(circuit.variant);
    }
    const circuit = shieldedPool.program.definedTypes.find((type) => type.name === "circuit");
    if (!circuit || !("variants" in circuit.type)) throw new Error("Missing circuit schema");
    expect([...selectors].sort()).toEqual(
      circuit.type.variants.map((variant) => variant.name).sort(),
    );
  });
  it("describes the optional cache writer and authority burn signer", () => {
    expect(shieldedPool.program.instructions.find((ix) => ix.name === "closeCache")).toMatchObject({
      optionalAccountStrategy: "omitted",
      accounts: [
        { name: "cache", isWritable: true, isSigner: false },
        { name: "rentRecipient", isWritable: true, isSigner: false },
        { name: "writer", isWritable: false, isSigner: true, isOptional: true },
      ],
    });
    expect(
      shieldedPool.program.instructions
        .find((ix) => ix.name === "updateRingConfigOwner")
        ?.accounts?.at(-1),
    ).toMatchObject({ name: "newAuthority", isSigner: "either" });
  });
  it("rejects unrecognized merge encryption and legacy key updates", () => {
    expect(() => decodeInstruction("userRegistry", Uint8Array.of(1, 2))).toThrow();
    const update = rust.instructions.find(
      (ix) => ix.program === "userRegistry" && ix.name === "updateKeys",
    );
    if (!update) throw new Error("Missing key-update fixture");
    expect(() =>
      decodeInstruction(
        "userRegistry",
        Uint8Array.from([...fromHex(update.hex), ...new Uint8Array(32)]),
      ),
    ).toThrow();
    const record = rust.accounts.find((account) => account.program === "userRegistry");
    if (!record) throw new Error("Missing user-record fixture");
    const bytes = fromHex(record.hex);
    bytes[bytes.length - 1] = 2;
    expect(() => decodeAccount("userRegistry", "userRecord", bytes)).toThrow();
  });
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
