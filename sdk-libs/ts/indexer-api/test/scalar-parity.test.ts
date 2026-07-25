import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { IndexerSchemaError, base64Bytes, base64String, hash, hashBytes } from "../src/index.js";

const readText = readFileSync as unknown as (path: URL, encoding: "utf8") => string;
const rustSource = (): string =>
  readText(new URL("../../../indexer-api/src/lib.rs", import.meta.url), "utf8");

function codeOf(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(IndexerSchemaError);
    return (error as IndexerSchemaError).code;
  }
  throw new Error("expected the scalar to be rejected");
}

describe("scalar parity with the Rust crate", () => {
  /**
   * Rust reaches `WrongSize` two ways, an over-long string and a decode that is
   * not 32 bytes, and `Invalid` only when bs58 itself rejects the input. The
   * port collapsed all three into one code, which left a caller unable to tell
   * a truncated hash from a corrupted one.
   */
  it("separates the two hash failures Rust names", () => {
    const source = rustSource();
    expect(source).toContain("pub enum ParseHashError");
    expect(source).toContain("WrongSize");
    expect(source).toContain("Invalid,");

    // Longer than MAX_BASE58_32_LEN, which Rust checks before it decodes.
    expect(codeOf(() => hash("1".repeat(45)))).toBe("INDEXER_SCHEMA_HASH_WRONG_SIZE");
    // Decodes cleanly, but not to 32 bytes.
    expect(codeOf(() => hash("short"))).toBe("INDEXER_SCHEMA_HASH_WRONG_SIZE");
    expect(codeOf(() => hash(new Uint8Array(31) as never))).toBe("INDEXER_SCHEMA_HASH_WRONG_SIZE");
    // `0`, `O`, `I`, and `l` are outside the base58 alphabet.
    expect(codeOf(() => hash("0OIl"))).toBe("INDEXER_SCHEMA_INVALID_HASH");
    expect(codeOf(() => hashBytes("0OIl" as never))).toBe("INDEXER_SCHEMA_INVALID_HASH");
  });

  /**
   * Rust's `Base64String` holds the bytes and encodes at the serde boundary, so
   * `From<Base64String> for Vec<u8>` is a field read. The port brands the wire
   * string, so the same capability has to be a function or it is absent.
   */
  it("converts a payload back to bytes, as the Rust type does", () => {
    const source = rustSource();
    expect(source).toContain("pub struct Base64String(pub Vec<u8>);");
    expect(source).toContain("impl From<Base64String> for Vec<u8>");

    const bytes = new Uint8Array([0, 1, 2, 250, 255]);
    expect(base64Bytes(base64String(bytes))).toEqual(bytes);
    expect(base64Bytes(base64String(new Uint8Array()))).toEqual(new Uint8Array());
  });

  it("holds the payload decoder to the canonical form the encoder produces", () => {
    expect(codeOf(() => base64Bytes("A===" as never))).toBe("INDEXER_SCHEMA_INVALID_BASE64");
    expect(codeOf(() => base64Bytes("AQI" as never))).toBe("INDEXER_SCHEMA_INVALID_BASE64");
  });
});
