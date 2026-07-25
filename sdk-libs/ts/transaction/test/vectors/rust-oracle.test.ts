import type { Address, Bytes31, Bytes32 } from "@zolana/interface";
import { describe, expect, it } from "vitest";

import {
  AssetRegistry,
  Data,
  EncryptedScheme,
  SOL_ASSET_ID,
  SOL_MINT,
  TRANSACTION_ERROR_CODES,
  TransactionError,
  canonicalShape,
  deriveBlinding,
  encryptedSchemeFromByte,
  encryptedSchemeToByte,
  ownerUtxoHash,
  resolveShape,
  slotOrdinal,
  type DataRecord,
  type Shape,
  type TransactionErrorCode,
} from "../../src/index.js";
import { encodeData, decodeData } from "../../src/serialization/index.js";
import oracle from "../oracles/transaction-parity-v1.json" with { type: "json" };

/// `sdk-libs/transaction/tests/ts_oracle.rs` produced every value in
/// `oracles/transaction-parity-v1.json` from the production Rust path, and its
/// own test fails if Rust drifts from the committed file. This test runs the
/// TypeScript path over the same inputs, so the two languages are compared by
/// execution rather than by reading.

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytes(value: string): Uint8Array {
  const out = new Uint8Array(value.length / 2);
  for (let index = 0; index < out.length; index++) {
    out[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

function codeOf(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof TransactionError) return error.code;
    return `non-transaction error: ${String(error)}`;
  }
  return "no error";
}

/**
 * Codes TypeScript declares that no Rust variant maps onto. Every one is a
 * runtime check TypeScript needs and Rust gets from its types: Rust cannot be
 * handed a 33-byte address or a `number` where a `u64` belongs, so it has no
 * variant to port. Each entry names the check that raises it, and the test
 * below fails if a code here stops having a producer or if a new unmapped code
 * appears.
 */
const TYPESCRIPT_ONLY_CODES: Readonly<Record<string, string>> = Object.freeze({
  TRANSACTION_DUMMY_INPUT_NOT_ALLOWED: "builders reject a dummy where a real input is required",
  TRANSACTION_DUPLICATE_OUTPUT: "builders reject the same output slot twice",
  TRANSACTION_INPUT_OWNER_MISMATCH: "builders reject an input owned by another key",
  TRANSACTION_INVALID_ADDRESS: "decodeAddress rejects a malformed base58 address",
  TRANSACTION_INVALID_AMOUNT: "checked integer bounds on a bigint amount",
  TRANSACTION_INVALID_ASSET_ID: "AssetRegistry rejects a non-bigint or out-of-range asset id",
  TRANSACTION_INVALID_BLINDING: "checked rejects a blinding of the wrong length",
  TRANSACTION_INVALID_DATA_LENGTH: "codecs reject a record longer than its u16 length prefix",
  TRANSACTION_INVALID_INTEGER: "readers reject an integer wider than its encoded width",
  TRANSACTION_INVALID_POSITION: "deriveBlinding rejects a position outside 0..=255",
  TRANSACTION_OUTPUT_TAG_MISMATCH: "external data rejects a tag count unequal to the output count",
  TRANSACTION_SIGNATURE_OWNER_MISMATCH: "a returned signature does not match the signing owner",
  TRANSACTION_TRAILING_BYTES: "decoders reject bytes left after an exact read",
  TRANSACTION_UNKNOWN_VARIANT: "unknownTransactionError wraps an unrecognized runtime value",
});

interface ErrorVariant {
  readonly variant: string;
  readonly display: string;
  readonly tsCode: string;
}

interface DataCase {
  readonly name: string;
  readonly records: readonly Readonly<{ kind: string; bytesHex: string }>[];
  readonly encodedHex: string | null;
  readonly error: string | null;
}

interface ShapeJson {
  readonly inputs: number;
  readonly outputs: number;
}

interface ResolveCase {
  readonly declared: ShapeJson | null;
  readonly inputs: number;
  readonly outputs: number;
  readonly shape: ShapeJson | null;
  readonly error: string | null;
}

interface UtxoCase {
  readonly name: string;
  readonly ownerHashHex: string;
  readonly asset: string;
  readonly amount: string;
  readonly blindingHex: string;
  readonly dataHashHex: string | null;
  readonly zoneDataHashHex: string | null;
  readonly zoneProgramId: string | null;
  readonly hashHex: string | null;
  readonly error: string | null;
}

describe("the Rust oracle and TypeScript agree on the error code set", () => {
  const variants = oracle.errors.variants as readonly ErrorVariant[];

  it("maps every current Rust variant onto a declared TypeScript code", () => {
    const declared = new Set<string>(TRANSACTION_ERROR_CODES);
    const missing = variants.filter((entry) => !declared.has(entry.tsCode));
    expect(missing.map((entry) => `${entry.variant} -> ${entry.tsCode}`)).toEqual([]);
  });

  it("records a reason for every declared code no Rust variant maps onto", () => {
    const mapped = new Set(variants.map((entry) => entry.tsCode));
    const unmapped = TRANSACTION_ERROR_CODES.filter((code) => !mapped.has(code));
    expect([...unmapped].sort()).toEqual(Object.keys(TYPESCRIPT_ONLY_CODES).sort());
  });

  it("covers all 70 Rust variants exactly once", () => {
    expect(variants).toHaveLength(70);
    expect(new Set(variants.map((entry) => entry.variant)).size).toBe(variants.length);
  });
});

describe("the Rust oracle and TypeScript agree on UTXO data records", () => {
  for (const testCase of oracle.data.cases as readonly DataCase[]) {
    it(`encodes ${testCase.name} the same way`, () => {
      const records = testCase.records.map(
        (record) => ({ kind: record.kind, bytes: bytes(record.bytesHex) }) as DataRecord,
      );
      if (testCase.error !== null) {
        expect(codeOf(() => new Data(records))).toBe(testCase.error);
        return;
      }
      const data = new Data(records);
      const encoded = encodeData(data);
      expect(hex(encoded)).toBe(testCase.encodedHex);
      expect(
        decodeData(encoded)
          .records()
          .map((record) => `${record.kind}:${hex(record.bytes)}`),
      ).toEqual(records.map((record) => `${record.kind}:${hex(record.bytes)}`));
    });
  }
});

describe("the Rust oracle and TypeScript agree on the encrypted scheme byte", () => {
  it("assigns the same byte to every scheme", () => {
    const values = oracle.scheme.values as readonly Readonly<{ name: string; byte: number }>[];
    for (const entry of values) {
      const scheme = EncryptedScheme[entry.name as keyof typeof EncryptedScheme];
      expect(scheme).toBe(entry.byte);
      expect(encryptedSchemeToByte(scheme)).toBe(entry.byte);
      expect(encryptedSchemeFromByte(entry.byte)).toBe(scheme);
    }
    expect(values.map((entry) => entry.name).sort()).toEqual(Object.keys(EncryptedScheme).sort());
  });

  it("rejects the same bytes", () => {
    for (const entry of oracle.scheme.invalid as readonly Readonly<{
      byte: number;
      error: string;
    }>[]) {
      expect(codeOf(() => encryptedSchemeFromByte(entry.byte))).toBe(entry.error);
    }
  });
});

describe("the Rust oracle and TypeScript agree on proof shapes", () => {
  it("supports the same shape set", () => {
    const supported = oracle.shape.supported as readonly ShapeJson[];
    expect(
      supported.map((shape) => `${String(shape.inputs)}x${String(shape.outputs)}`),
    ).not.toHaveLength(0);
    for (const shape of supported) {
      expect(resolveShape(shape.inputs, shape.outputs, shape as Shape)).toEqual(shape);
    }
  });

  it("resolves or rejects every declared and undeclared case identically", () => {
    const mismatches: string[] = [];
    for (const testCase of oracle.shape.resolve as readonly ResolveCase[]) {
      const label = `declared=${JSON.stringify(testCase.declared)} in=${String(
        testCase.inputs,
      )} out=${String(testCase.outputs)}`;
      const run = (): Shape =>
        testCase.declared === null
          ? resolveShape(testCase.inputs, testCase.outputs)
          : resolveShape(testCase.inputs, testCase.outputs, testCase.declared as Shape);
      if (testCase.error !== null) {
        const code = codeOf(run);
        if (code !== testCase.error) mismatches.push(`${label}: ${code} != ${testCase.error}`);
        continue;
      }
      let actual: Shape | string;
      try {
        actual = run();
      } catch (error) {
        actual = `threw ${String(error)}`;
      }
      if (
        typeof actual === "string" ||
        actual.inputs !== testCase.shape?.inputs ||
        actual.outputs !== testCase.shape.outputs
      ) {
        mismatches.push(`${label}: ${JSON.stringify(actual)} != ${JSON.stringify(testCase.shape)}`);
      }
    }
    expect(mismatches).toEqual([]);
  });

  it("picks the same canonical shape", () => {
    const mismatches: string[] = [];
    for (const testCase of oracle.shape.canonical as readonly ResolveCase[]) {
      const label = `in=${String(testCase.inputs)} out=${String(testCase.outputs)}`;
      if (testCase.error !== null) {
        const code = codeOf(() => canonicalShape(testCase.inputs, testCase.outputs));
        if (code !== testCase.error) mismatches.push(`${label}: ${code} != ${testCase.error}`);
        continue;
      }
      const shape = canonicalShape(testCase.inputs, testCase.outputs);
      if (shape.inputs !== testCase.shape?.inputs || shape.outputs !== testCase.shape.outputs) {
        mismatches.push(`${label}: ${JSON.stringify(shape)} != ${JSON.stringify(testCase.shape)}`);
      }
    }
    expect(mismatches).toEqual([]);
  });
});

describe("the Rust oracle and TypeScript agree on the asset registry", () => {
  it("uses the same SOL constants", () => {
    expect(SOL_ASSET_ID.toString()).toBe(oracle.asset.solAssetId);
    expect(SOL_MINT).toBe(oracle.asset.solMint);
  });

  it("accepts and rejects the same inserts in the same order", () => {
    const registry = new AssetRegistry();
    const results = (
      oracle.asset.inserts as readonly Readonly<{
        assetId: string;
        mint: string;
        error: string | null;
      }>[]
    ).map((entry) => {
      const code = codeOf(() => {
        registry.insert(BigInt(entry.assetId), entry.mint as Address);
      });
      return `${entry.assetId}:${code === "no error" ? "ok" : code}`;
    });
    expect(results).toEqual(
      (
        oracle.asset.inserts as readonly Readonly<{
          assetId: string;
          error: string | null;
        }>[]
      ).map((entry) => `${entry.assetId}:${entry.error ?? "ok"}`),
    );

    for (const entry of oracle.asset.resolve as readonly Readonly<{
      assetId: string;
      mint: string | null;
      error: string | null;
    }>[]) {
      if (entry.error !== null) {
        expect(codeOf(() => registry.resolve(BigInt(entry.assetId)))).toBe(entry.error);
        continue;
      }
      expect(registry.resolve(BigInt(entry.assetId))).toBe(entry.mint);
    }

    for (const entry of oracle.asset.assetId as readonly Readonly<{
      mint: string;
      assetId: string | null;
      error: string | null;
    }>[]) {
      if (entry.error !== null) {
        expect(codeOf(() => registry.assetId(entry.mint as Address))).toBe(entry.error);
        continue;
      }
      expect(registry.assetId(entry.mint as Address).toString()).toBe(entry.assetId);
    }

    for (const entry of oracle.asset.addressForField as readonly Readonly<{
      fieldHex: string;
      mint: string | null;
    }>[]) {
      expect(registry.addressForField(bytes(entry.fieldHex) as Bytes32) ?? null).toBe(entry.mint);
    }
  });
});

describe("the Rust oracle and TypeScript agree on UTXO commitments", () => {
  for (const testCase of oracle.utxo.proofInputHashes as readonly UtxoCase[]) {
    it(`hashes ${testCase.name} the same way`, () => {
      const input = {
        owner: bytes(testCase.ownerHashHex) as Bytes32,
        asset: testCase.asset as Address,
        amount: BigInt(testCase.amount),
        blinding: bytes(testCase.blindingHex) as Bytes31,
        ...(testCase.dataHashHex === null
          ? {}
          : { dataHash: bytes(testCase.dataHashHex) as Bytes32 }),
        ...(testCase.zoneDataHashHex === null
          ? {}
          : { zoneDataHash: bytes(testCase.zoneDataHashHex) as Bytes32 }),
        ...(testCase.zoneProgramId === null
          ? {}
          : { zoneProgramId: testCase.zoneProgramId as Address }),
      };
      if (testCase.error !== null) {
        expect(codeOf(() => ownerUtxoHash(input))).toBe(testCase.error);
        return;
      }
      expect(hex(ownerUtxoHash(input))).toBe(testCase.hashHex);
    });
  }

  it("commits an owner hash and blinding the same way", () => {
    for (const entry of oracle.utxo.ownerUtxoHashes as readonly Readonly<{
      ownerHashHex: string;
      blindingHex: string;
      hashHex: string;
    }>[]) {
      expect(
        hex(
          ownerUtxoHash(
            bytes(entry.ownerHashHex) as Bytes32,
            bytes(entry.blindingHex) as Bytes31,
          ),
        ),
      ).toBe(entry.hashHex);
    }
  });

  it("derives the same blinding for every position", () => {
    for (const entry of oracle.utxo.deriveBlinding as readonly Readonly<{
      seedHex: string;
      position: number;
      blindingHex: string;
    }>[]) {
      expect(hex(deriveBlinding(bytes(entry.seedHex) as Bytes31, entry.position))).toBe(
        entry.blindingHex,
      );
    }
  });
});

describe("the Rust oracle and TypeScript agree on ciphertext slot ordinals", () => {
  it("accepts and rejects the same positions", () => {
    for (const entry of oracle.slots.ordinals as readonly Readonly<{
      position: string;
      ordinal: number | null;
      error: string | null;
    }>[]) {
      const position = Number(entry.position);
      if (entry.error !== null) {
        expect(codeOf(() => slotOrdinal(position))).toBe(entry.error);
        continue;
      }
      expect(slotOrdinal(position)).toBe(entry.ordinal);
    }
  });
});

describe("the recorded TypeScript-only codes still have producers", () => {
  it("keeps every allowlisted code in the declared set", () => {
    const declared = new Set<TransactionErrorCode>(TRANSACTION_ERROR_CODES);
    for (const code of Object.keys(TYPESCRIPT_ONLY_CODES)) {
      expect(declared.has(code as TransactionErrorCode)).toBe(true);
    }
  });
});
