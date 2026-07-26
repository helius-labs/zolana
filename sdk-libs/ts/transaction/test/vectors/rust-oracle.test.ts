import type { Address, Bytes16, Bytes31, Bytes32, Bytes33 } from "@zolana/interface";
import {
  NullifierKey,
  P256PublicKey,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
} from "@zolana/keypair";
import { describe, expect, it } from "vitest";

import {
  AssetRegistry,
  BN254_MODULUS_DEC,
  ConfidentialSplit,
  ConfidentialTransfer,
  Data,
  EncryptedScheme,
  MERGE_INPUTS,
  Merge,
  MergeZone,
  PreparedMerge,
  PreparedMergeZone,
  PreparedSplit,
  ProofInputUtxo,
  SENDER_SLOT_COUNT,
  SOL_ASSET_ID,
  SOL_MINT,
  TRANSACTION_ERROR_CODES,
  TransactionError,
  Utxo,
  Wallet,
  anonymousRecipientFromUtxos,
  anonymousSenderFromUtxos,
  assetField,
  canonicalShape,
  createEncryptedTransaction,
  createExternalData,
  createInputUtxo,
  createProofOutput,
  deriveBlinding,
  encryptedSchemeFromByte,
  privateTxHash,
  encryptedSchemeToByte,
  ownerUtxoHash,
  plaintextTransferFromUtxos,
  prepareZoneAuthority,
  prooflessFromUtxos,
  resolveShape,
  signedToField,
  splitBundleFromUtxos,
  slotOrdinal,
  type AssetBalance,
  type DataRecord,
  type ExternalData,
  type Filter,
  type PreparedTransfer,
  type PreparedZoneAuthority,
  type Shape,
  type TransactionErrorCode,
  type WithdrawalTarget,
} from "../../src/index.js";
import {
  decodeAnonymousRecipient,
  decodeConfidential,
  decodeData,
  decodeMerge,
  decodeProofless,
  decodeSplitEncrypted,
  decryptAnonymous,
  decryptConfidential,
  decryptMerge,
  encodeAnonymousRecipient,
  encodeAnonymousSender,
  encodeConfidential,
  encodeData,
  encodeMerge,
  encodePlaintextTransfer,
  encodeProofless,
  encodeSplitBundle,
  encodeSplitEncrypted,
  mergeUtxo,
  type ProoflessOutput,
  type SplitEncryptedUtxos,
} from "../../src/serialization/index.js";
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

function rejection(run: () => unknown): Readonly<{ code: string; field: unknown }> {
  try {
    run();
  } catch (error) {
    if (error instanceof TransactionError) {
      return { code: error.code, field: error.details?.field ?? null };
    }
    return { code: `non-transaction error: ${String(error)}`, field: null };
  }
  return { code: "no error", field: null };
}

function details(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    if (error instanceof TransactionError) return error.details;
  }
  return undefined;
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
  TRANSACTION_INVALID_INTEGER: "readers reject an integer wider than its encoded width",
  TRANSACTION_INVALID_POSITION: "deriveBlinding rejects a position outside 0..=255",
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

interface CanonicalDummyCase {
  readonly name: string;
  readonly fields: readonly string[];
  readonly error: string | null;
  readonly field: string | null;
}

/** `Address::default()`: both the dummy's asset and Rust's zero zone address. */
const ZERO_ADDRESS = "11111111111111111111111111111111" as Address;

/** A dummy input with the named fields set to the same values Rust uses. */
function noncanonicalDummy(fields: readonly string[]): ProofInputUtxo {
  const set = new Set(fields);
  const zeroHash = (): Bytes32 => new Uint8Array(32) as Bytes32;
  const nullifierKey = set.has("nullifier_key")
    ? shieldedKeypair(7, oracle.transfer.ownerViewingSeedHex).nullifierKey()
    : NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);
  try {
    return new ProofInputUtxo({
      utxo: new Utxo({
        owner: ShieldedPublicKey.zeroed(),
        asset: set.has("asset") ? (oracle.fromUtxos.splMint as Address) : ZERO_ADDRESS,
        amount: set.has("amount") ? 7n : 0n,
        blinding: new Uint8Array(31) as Bytes31,
        ...(set.has("data")
          ? {
              data: new Data([{ kind: "memo", bytes: Uint8Array.from(BUILDER_RECORD_BYTES.memo) }]),
            }
          : {}),
        ...(set.has("zone_program_id") ? { zoneProgramId: oracle.merge.zone as Address } : {}),
        ...(set.has("zero_zone_program_id") ? { zoneProgramId: ZERO_ADDRESS } : {}),
      }),
      nullifierKey,
      ...(set.has("data_hash") ? { dataHash: bytes(oracle.merge.dataHashHex) as Bytes32 } : {}),
      ...(set.has("zero_data_hash") ? { dataHash: zeroHash() } : {}),
      ...(set.has("zone_data_hash")
        ? { zoneDataHash: bytes(oracle.merge.zoneDataHashHex) as Bytes32 }
        : {}),
      ...(set.has("zero_zone_data_hash") ? { zoneDataHash: zeroHash() } : {}),
    });
  } finally {
    nullifierKey.destroy();
  }
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

  it("covers all 72 Rust variants exactly once", () => {
    expect(variants).toHaveLength(72);
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
          : resolveShape(testCase.inputs, testCase.outputs, testCase.declared);
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
          ownerUtxoHash(bytes(entry.ownerHashHex) as Bytes32, bytes(entry.blindingHex) as Bytes31),
        ),
      ).toBe(entry.hashHex);
    }
  });

  // A dummy carrying a nonzero field is rejected by naming that field, and the
  // checks run in a fixed order, so the multi-field cases pin which name wins.
  for (const testCase of oracle.utxo.canonicalDummy as readonly CanonicalDummyCase[]) {
    it(`rules on the ${testCase.name} dummy the same way`, () => {
      if (testCase.error === null) {
        expect(noncanonicalDummy(testCase.fields).isDummy()).toBe(true);
        return;
      }
      expect(rejection(() => noncanonicalDummy(testCase.fields))).toEqual({
        code: testCase.error,
        field: testCase.field,
      });
    });
  }

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

interface ProoflessLayoutCase {
  readonly name: string;
  readonly ownerHex: string;
  readonly blindingHex: string;
  readonly asset: string;
  readonly amount: string;
  readonly dataHashHex: string | null;
  readonly utxoDataHex: string | null;
  readonly zoneProgramId: string | null;
  readonly zoneDataHashHex: string | null;
  readonly zoneDataHex: string | null;
  readonly memoHex: string | null;
  readonly encodedHex: string;
}

describe("the Rust oracle and TypeScript agree on the key-free plaintext layouts", () => {
  it("encodes a confidential output the same way", () => {
    for (const entry of oracle.serialization.confidential as readonly Readonly<{
      name: string;
      assetId: string;
      amount: string;
      blindingHex: string;
      zoneProgramId: string | null;
      records: readonly Readonly<{ kind: string; bytesHex: string }>[];
      encodedHex: string;
    }>[]) {
      const value = {
        assetId: BigInt(entry.assetId),
        amount: BigInt(entry.amount),
        blinding: bytes(entry.blindingHex) as Bytes31,
        ...(entry.zoneProgramId === null ? {} : { zoneProgramId: entry.zoneProgramId as Address }),
        data: new Data(
          entry.records.map(
            (record) => ({ kind: record.kind, bytes: bytes(record.bytesHex) }) as DataRecord,
          ),
        ),
      };
      const encoded = encodeConfidential(value);
      expect(`${entry.name}:${hex(encoded)}`).toBe(`${entry.name}:${entry.encodedHex}`);
      const parsed = decodeConfidential(encoded);
      expect(parsed.assetId).toBe(value.assetId);
      expect(parsed.amount).toBe(value.amount);
      expect(hex(parsed.blinding)).toBe(entry.blindingHex);
      expect(parsed.zoneProgramId ?? null).toBe(entry.zoneProgramId);
    }
  });

  // The proofless note has six optional fields, so the reader and the writer
  // both have to agree with Borsh on which are present and in what order.
  for (const entry of oracle.serialization.proofless as readonly ProoflessLayoutCase[]) {
    it(`round-trips the ${entry.name} proofless note the same way`, () => {
      const value: ProoflessOutput = {
        owner: bytes(entry.ownerHex) as Bytes32,
        blinding: bytes(entry.blindingHex) as Bytes31,
        asset: entry.asset as Address,
        amount: BigInt(entry.amount),
        ...(entry.dataHashHex === null ? {} : { dataHash: bytes(entry.dataHashHex) as Bytes32 }),
        ...(entry.utxoDataHex === null ? {} : { utxoData: bytes(entry.utxoDataHex) }),
        ...(entry.zoneProgramId === null ? {} : { zoneProgramId: entry.zoneProgramId as Address }),
        ...(entry.zoneDataHashHex === null
          ? {}
          : { zoneDataHash: bytes(entry.zoneDataHashHex) as Bytes32 }),
        ...(entry.zoneDataHex === null ? {} : { zoneData: bytes(entry.zoneDataHex) }),
        ...(entry.memoHex === null ? {} : { memo: bytes(entry.memoHex) }),
      };
      expect(hex(encodeProofless(value))).toBe(entry.encodedHex);

      const parsed = decodeProofless(bytes(entry.encodedHex));
      expect(hex(parsed.owner)).toBe(entry.ownerHex);
      expect(hex(parsed.blinding)).toBe(entry.blindingHex);
      expect(parsed.asset).toBe(entry.asset);
      expect(parsed.amount.toString()).toBe(entry.amount);
      expect(parsed.dataHash === undefined ? null : hex(parsed.dataHash)).toBe(entry.dataHashHex);
      expect(parsed.utxoData === undefined ? null : hex(parsed.utxoData)).toBe(entry.utxoDataHex);
      expect(parsed.zoneProgramId ?? null).toBe(entry.zoneProgramId);
      expect(parsed.zoneDataHash === undefined ? null : hex(parsed.zoneDataHash)).toBe(
        entry.zoneDataHashHex,
      );
      expect(parsed.zoneData === undefined ? null : hex(parsed.zoneData)).toBe(entry.zoneDataHex);
      expect(parsed.memo === undefined ? null : hex(parsed.memo)).toBe(entry.memoHex);
    });
  }

  // The split envelope's ciphertext carries a u16 length prefix, so a payload
  // past 255 bytes is the case a byte prefix would silently truncate.
  const splitEncrypted = oracle.serialization.splitEncrypted;
  for (const entry of splitEncrypted.cases as readonly Readonly<{
    name: string;
    typePrefix: number;
    txViewingPublicKeyHex: string;
    saltHex: string;
    ciphertextHex: string;
    encodedHex: string;
  }>[]) {
    it(`round-trips the ${entry.name} split envelope the same way`, () => {
      const value: SplitEncryptedUtxos = {
        typePrefix: entry.typePrefix,
        txViewingPublicKey: P256PublicKey.fromBytes(bytes(entry.txViewingPublicKeyHex) as Bytes33),
        salt: bytes(entry.saltHex) as Bytes16,
        ciphertext: bytes(entry.ciphertextHex),
      };
      expect(hex(encodeSplitEncrypted(value))).toBe(entry.encodedHex);

      const parsed = decodeSplitEncrypted(bytes(entry.encodedHex));
      expect(parsed.typePrefix).toBe(entry.typePrefix);
      expect(hex(parsed.txViewingPublicKey.toBytes())).toBe(entry.txViewingPublicKeyHex);
      expect(hex(parsed.salt)).toBe(entry.saltHex);
      expect(hex(parsed.ciphertext)).toBe(entry.ciphertextHex);
    });
  }

  it("rejects a split envelope carrying another scheme's prefix", () => {
    expect(codeOf(() => decodeSplitEncrypted(bytes(splitEncrypted.foreignSchemeHex)))).toBe(
      splitEncrypted.foreignSchemeError,
    );
  });

  it("encodes a merge plaintext the same way", () => {
    for (const entry of oracle.serialization.merge as readonly Readonly<{
      name: string;
      amount: string;
      assetFieldHex: string;
      blindingHex: string;
      encodedHex: string;
    }>[]) {
      const encoded = encodeMerge({
        amount: BigInt(entry.amount),
        assetField: bytes(entry.assetFieldHex) as Bytes32,
        blinding: bytes(entry.blindingHex) as Bytes31,
      });
      expect(`${entry.name}:${hex(encoded)}`).toBe(`${entry.name}:${entry.encodedHex}`);
      const parsed = decodeMerge(encoded);
      expect(parsed.amount).toBe(BigInt(entry.amount));
      expect(hex(parsed.assetField)).toBe(entry.assetFieldHex);
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

/**
 * Every `error` the oracle records is replayed against TypeScript somewhere in
 * this file, so a code appearing here is a code both languages raise on the same
 * input. Codes absent from this set are declared but unexercised.
 */
function oracleProducedCodes(): ReadonlySet<string> {
  const codes = new Set<string>();
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const child of node) walk(child);
      return;
    }
    if (typeof node !== "object" || node === null) return;
    for (const [key, value] of Object.entries(node)) {
      if (key === "error" && typeof value === "string") codes.add(value);
      else walk(value);
    }
  };
  walk(oracle);
  return codes;
}

describe("the declared error codes have producers", () => {
  const produced = oracleProducedCodes();

  it("keeps every allowlisted code in the declared set", () => {
    const declared = new Set<TransactionErrorCode>(TRANSACTION_ERROR_CODES);
    for (const code of Object.keys(TYPESCRIPT_ONLY_CODES)) {
      expect(declared.has(code as TransactionErrorCode)).toBe(true);
    }
  });

  // These six were declared with no caller until the UTXO conversions were
  // ported. Each is now raised by a named oracle case, so deleting the producer
  // fails here rather than leaving a dead code behind.
  it.each([
    "TRANSACTION_INVALID_OUTPUT_POSITION",
    "TRANSACTION_OUTPUT_AMOUNT_MISMATCH",
    "TRANSACTION_OUTPUT_ASSET_MISMATCH",
    "TRANSACTION_OUTPUT_BLINDING_MISMATCH",
    "TRANSACTION_OUTPUT_OWNER_MISMATCH",
    "TRANSACTION_UNKNOWN_ASSET_FIELD",
  ])("raises %s from a replayed case", (code) => {
    expect(produced.has(code)).toBe(true);
  });

  it("only expects codes TypeScript declares", () => {
    const declared = new Set<string>(TRANSACTION_ERROR_CODES);
    expect([...produced].filter((code) => !declared.has(code))).toEqual([]);
  });
});

interface UtxoSpec {
  readonly owner: string;
  readonly asset: string;
  readonly amount: string;
  readonly position: number | null;
  readonly zoneProgramId: string | null;
  readonly records: readonly Readonly<{ kind: string; bytesHex: string }>[];
}

interface FromUtxosCase {
  readonly name: string;
  readonly utxos: readonly UtxoSpec[];
  readonly zoneProgramId: string | null;
  readonly encodedHex: string | null;
  readonly error: string | null;
}

interface MergeIntoUtxosCase {
  readonly name: string;
  readonly assetFieldHex: string;
  readonly zoneBound: boolean;
  readonly error: string | null;
  readonly asset: string | null;
  readonly amount: string | null;
  readonly zoneProgramId: string | null;
}

describe("the Rust oracle and TypeScript agree on the from-UTXO conversions", () => {
  const fromUtxos = oracle.fromUtxos;
  const ownerKey = SigningKey.fromBytes(bytes(`${"00".repeat(31)}07`) as Bytes32).publicKey();
  const otherKey = SigningKey.fromBytes(bytes(`${"00".repeat(31)}0c`) as Bytes32).publicKey();
  const senderViewing = ViewingKey.fromBytes(bytes("08".repeat(32)) as Bytes32).publicKey();
  const blindingSeed = bytes(fromUtxos.blindingSeedHex) as Bytes31;
  const splMint = fromUtxos.splMint as Address;

  it("derives the same keys the Rust oracle recorded", () => {
    expect(hex(ownerKey.toBytes())).toBe(fromUtxos.ownerPublicKeyHex);
    expect(hex(otherKey.toBytes())).toBe(fromUtxos.otherPublicKeyHex);
    expect(hex(senderViewing.toBytes())).toBe(fromUtxos.senderViewingPublicKeyHex);
  });

  function buildUtxo(spec: UtxoSpec): Utxo {
    return new Utxo({
      owner: spec.owner === "owner" ? ownerKey : otherKey,
      asset: spec.asset as Address,
      amount: BigInt(spec.amount),
      blinding:
        spec.position === null
          ? (new Uint8Array(31).fill(99) as Bytes31)
          : deriveBlinding(blindingSeed, spec.position),
      data: new Data(
        spec.records.map(
          (record) => ({ kind: record.kind, bytes: bytes(record.bytesHex) }) as DataRecord,
        ),
      ),
      ...(spec.zoneProgramId === null ? {} : { zoneProgramId: spec.zoneProgramId as Address }),
    });
  }

  function run(family: string, testCase: FromUtxosCase): void {
    const utxos = testCase.utxos.map(buildUtxo);
    const owner = {
      owner: ownerKey,
      assets: new AssetRegistry([[2n, splMint]]),
      ...(testCase.zoneProgramId === null
        ? {}
        : { zoneProgramId: testCase.zoneProgramId as Address }),
    };
    const convert = (): Uint8Array => {
      switch (family) {
        case "plaintextTransfer":
          return encodePlaintextTransfer(
            plaintextTransferFromUtxos(utxos, owner, { blindingSeed }),
          );
        case "anonymousRecipient":
          return encodeAnonymousRecipient(
            anonymousRecipientFromUtxos(utxos, owner, { senderPublicKey: senderViewing }),
          );
        case "anonymousSender":
          return encodeAnonymousSender(
            anonymousSenderFromUtxos(utxos, owner, {
              blindingSeed,
              recipientViewingPublicKeys: [senderViewing],
            }),
          );
        case "split":
          return encodeSplitBundle(splitBundleFromUtxos(utxos, owner, { blindingSeed }));
        default:
          return encodeProofless(
            prooflessFromUtxos(utxos, owner, {
              ownerHash: bytes(fromUtxos.prooflessOwnerHashHex) as Bytes32,
              dataHash: bytes(fromUtxos.prooflessDataHashHex) as Bytes32,
            }),
          );
      }
    };
    if (testCase.error !== null) {
      expect(codeOf(convert)).toBe(testCase.error);
      return;
    }
    expect(hex(convert())).toBe(testCase.encodedHex);
  }

  for (const family of [
    "plaintextTransfer",
    "anonymousRecipient",
    "anonymousSender",
    "split",
    "proofless",
  ] as const) {
    for (const testCase of fromUtxos[family] as readonly FromUtxosCase[]) {
      it(`converts ${family} ${testCase.name} the same way`, () => {
        run(family, testCase);
      });
    }
  }

  // The reverse direction for the merge rail: only the asset field has to be
  // resolved back, and an unregistered one must be named rather than defaulted.
  for (const testCase of fromUtxos.mergeIntoUtxos as readonly MergeIntoUtxosCase[]) {
    it(`rebuilds the merge ${testCase.name} UTXO the same way`, () => {
      const rebuild = (): Utxo =>
        mergeUtxo(
          {
            amount: 500n,
            assetField: bytes(testCase.assetFieldHex) as Bytes32,
            blinding: bytes(oracle.transactTypes.blindingHex) as Bytes31,
          },
          ownerKey,
          new AssetRegistry([[2n, splMint]]),
          ...(testCase.zoneBound ? [fromUtxos.zoneProgramId as Address] : []),
        );
      if (testCase.error !== null) {
        expect(codeOf(rebuild)).toBe(testCase.error);
        return;
      }
      const utxo = rebuild();
      expect(utxo.asset).toBe(testCase.asset);
      expect(utxo.amount.toString()).toBe(testCase.amount);
      expect(utxo.zoneProgramId ?? null).toBe(testCase.zoneProgramId);
    });
  }
});

type TransferOp =
  | Readonly<{ kind: "send"; asset: string; amount: string }>
  | Readonly<{ kind: "withdraw"; asset: string; amount: string; target: "sol" | "spl" }>
  | Readonly<{ kind: "withShape"; shape: ShapeJson }>;

interface TransferCase {
  readonly name: string;
  readonly inputs: readonly Readonly<{ asset: string; amount: string; position: number }>[];
  readonly ops: readonly TransferOp[];
  readonly error: string | null;
  readonly shape: ShapeJson | null;
  readonly preparedInputs: number | null;
  readonly preparedOutputs: number | null;
  readonly changeAmounts: readonly string[] | null;
  readonly publicSol: string | null;
  readonly publicSpl: string | null;
  readonly userSolAccount: string | null;
  readonly userSplToken: string | null;
}

describe("the Rust oracle and TypeScript agree on the transfer builder", () => {
  const transfer = oracle.transfer;
  const splTarget = transfer.splTarget;

  function keypair(
    secretByte: number,
    viewingSeed: string,
  ): Readonly<{ shielded: ShieldedKeypair; nullifier: NullifierKey }> {
    const secret = new Uint8Array(32);
    secret[31] = secretByte;
    const signing = SigningKey.fromBytes(secret as Bytes32);
    const nullifier = NullifierKey.fromSigningKey(signing);
    return {
      shielded: ShieldedKeypair.fromKeys(
        signing,
        nullifier,
        ViewingKey.fromBytes(bytes(viewingSeed) as Bytes32),
      ),
      nullifier,
    };
  }

  const sender = keypair(7, transfer.ownerViewingSeedHex);
  const receiver = keypair(12, transfer.recipientViewingSeedHex);
  const blindingSeed = new Uint8Array(31).fill(11) as Bytes31;

  function withdrawalTarget(target: "sol" | "spl"): WithdrawalTarget {
    return target === "sol"
      ? { kind: "sol", recipient: transfer.solTarget as Address }
      : {
          kind: "spl",
          userTokenAccount: splTarget.userSplToken as Address,
          splTokenInterface: splTarget.splTokenInterface as Address,
        };
  }

  function build(testCase: TransferCase): PreparedTransfer {
    const builder = new ConfidentialTransfer(
      sender.shielded.shieldedAddress(),
      testCase.inputs.map(
        (input) =>
          new ProofInputUtxo({
            utxo: new Utxo({
              owner: sender.shielded.signingPublicKey(),
              asset: input.asset as Address,
              amount: BigInt(input.amount),
              blinding: deriveBlinding(blindingSeed, input.position),
            }),
            nullifierKey: sender.nullifier,
          }),
      ),
      transfer.payer as Address,
    );
    for (const op of testCase.ops) {
      switch (op.kind) {
        case "send":
          builder.send(receiver.shielded.shieldedAddress(), op.asset as Address, BigInt(op.amount));
          break;
        case "withdraw":
          builder.withdraw(op.asset as Address, BigInt(op.amount), withdrawalTarget(op.target));
          break;
        default:
          builder.withShape(op.shape);
      }
    }
    return builder.prepare();
  }

  it("counts the same sender slots", () => {
    expect(SENDER_SLOT_COUNT).toBe(transfer.senderSlotCount);
  });

  for (const testCase of transfer.cases as readonly TransferCase[]) {
    it(`decides ${testCase.name} the same way`, () => {
      if (testCase.error !== null) {
        expect(codeOf(() => build(testCase))).toBe(testCase.error);
        return;
      }
      const prepared = build(testCase);
      // Rust pads inputs and outputs in `finalize`, so these counts stay at the
      // real slot count; a language that padded in `prepare` would report the
      // shape's width instead.
      expect(prepared.inputs.length).toBe(testCase.preparedInputs);
      expect(prepared.outputs.length).toBe(testCase.preparedOutputs);
      expect(prepared.shape).toEqual(testCase.shape);
      expect(
        prepared.outputs.slice(0, SENDER_SLOT_COUNT).map((output) => output.amount.toString()),
      ).toEqual(testCase.changeAmounts);
      expect(prepared.publicSolAmount?.toString() ?? null).toBe(testCase.publicSol);
      expect(prepared.publicSplAmount?.toString() ?? null).toBe(testCase.publicSpl);
      expect(prepared.userSolAccount).toBe(testCase.userSolAccount);
      expect(prepared.userSplToken).toBe(testCase.userSplToken);
    });
  }
});

interface MergeInputSpec {
  readonly owner: "owner" | "other";
  readonly nullifier: "owner" | "other";
  readonly asset: string;
  readonly amount: string;
  readonly position: number;
  readonly zone: string | null;
  readonly records: readonly DataRecord["kind"][];
  readonly dataHash: boolean;
  readonly zoneDataHash: boolean;
}

interface ContextJson {
  readonly index: number;
  readonly utxoHashHex: string;
  readonly nullifierHex: string;
}

interface MergeCase {
  readonly name: string;
  readonly rail: "plain" | "zone";
  readonly inputs: readonly MergeInputSpec[];
  readonly error: string | null;
  readonly asset: string | null;
  readonly outputAmount: string | null;
  readonly paddedInputs: number | null;
  readonly expiryUnixTs: string | null;
  readonly inputContexts: readonly ContextJson[] | null;
}

interface PreparedContextCase {
  readonly name: string;
  readonly rail: "plain" | "zone";
  readonly perturbation: "dataHash" | "zoneDataHash" | "utxoData" | "foreignZone";
  readonly error: string | null;
  readonly inputContexts: readonly ContextJson[] | null;
}

/** The blinding seed every builder section's inputs derive from, `[11u8; 31]` in Rust. */
const BUILDER_BLINDING_SEED = new Uint8Array(31).fill(11) as Bytes31;

const BUILDER_RECORD_BYTES: Readonly<Record<DataRecord["kind"], number[]>> = {
  zoneData: [1, 2, 3],
  utxoData: [4, 5],
  memo: [6],
};

function shieldedKeypair(secretByte: number, viewingSeed: string): ShieldedKeypair {
  const secret = new Uint8Array(32);
  secret[31] = secretByte;
  const signing = SigningKey.fromBytes(secret as Bytes32);
  return ShieldedKeypair.fromKeys(
    signing,
    NullifierKey.fromSigningKey(signing),
    ViewingKey.fromBytes(bytes(viewingSeed) as Bytes32),
  );
}

function mergeInput(spec: MergeInputSpec): ProofInputUtxo {
  const owner = shieldedKeypair(7, oracle.transfer.ownerViewingSeedHex);
  const other = shieldedKeypair(12, oracle.transfer.recipientViewingSeedHex);
  return new ProofInputUtxo({
    utxo: new Utxo({
      owner: (spec.owner === "owner" ? owner : other).signingPublicKey(),
      asset: spec.asset as Address,
      amount: BigInt(spec.amount),
      blinding: deriveBlinding(BUILDER_BLINDING_SEED, spec.position),
      data: new Data(
        spec.records.map((kind) => ({ kind, bytes: Uint8Array.from(BUILDER_RECORD_BYTES[kind]) })),
      ),
      ...(spec.zone === null ? {} : { zoneProgramId: spec.zone as Address }),
    }),
    nullifierKey: (spec.nullifier === "owner" ? owner : other).nullifierKey(),
    ...(spec.dataHash ? { dataHash: bytes(oracle.merge.dataHashHex) as Bytes32 } : {}),
    ...(spec.zoneDataHash ? { zoneDataHash: bytes(oracle.merge.zoneDataHashHex) as Bytes32 } : {}),
  });
}

describe("the Rust oracle and TypeScript agree on the merge builders", () => {
  const merge = oracle.merge;
  const zone = merge.zone as Address;
  const dataHash = bytes(merge.dataHashHex) as Bytes32;
  const zoneDataHash = bytes(merge.zoneDataHashHex) as Bytes32;
  const sender = shieldedKeypair(7, oracle.transfer.ownerViewingSeedHex);
  const buildInput = mergeInput;

  function prepare(rail: "plain" | "zone", inputs: readonly ProofInputUtxo[]): PreparedMerge {
    return rail === "zone"
      ? new MergeZone(sender, inputs, zone).prepare()
      : new Merge(sender, inputs).prepare();
  }

  function contexts(prepared: PreparedMerge): readonly ContextJson[] {
    return prepared.inputUtxoHashes().map((context) => ({
      index: context.index,
      utxoHashHex: hex(context.utxoHash),
      nullifierHex: hex(context.nullifier),
    }));
  }

  it("pads to the same input count", () => {
    expect(MERGE_INPUTS).toBe(merge.mergeInputs);
  });

  for (const testCase of merge.cases as readonly MergeCase[]) {
    it(`decides ${testCase.rail} ${testCase.name} the same way`, () => {
      const inputs = testCase.inputs.map(buildInput);
      if (testCase.error !== null) {
        expect(codeOf(() => prepare(testCase.rail, inputs))).toBe(testCase.error);
        return;
      }
      const prepared = prepare(testCase.rail, inputs);
      expect(prepared.output.asset).toBe(testCase.asset);
      expect(prepared.output.amount.toString()).toBe(testCase.outputAmount);
      expect(prepared.inputs).toHaveLength(testCase.paddedInputs ?? -1);
      expect(prepared.expiryUnixTs.toString()).toBe(testCase.expiryUnixTs);
      expect(contexts(prepared)).toEqual(testCase.inputContexts);
    });
  }

  // The prepared values are publicly constructible, so their context accessor
  // re-checks the rail's data policy instead of trusting the builder.
  for (const testCase of merge.preparedContexts as readonly PreparedContextCase[]) {
    it(`re-checks ${testCase.name} the same way`, () => {
      const zoneRail = testCase.rail === "zone";
      const base = prepare(zoneRail ? "zone" : "plain", [
        buildInput({
          owner: "owner",
          nullifier: "owner",
          asset: SOL_MINT,
          amount: "100",
          position: 0,
          zone: zoneRail ? zone : null,
          records: [],
          dataHash: false,
          zoneDataHash: false,
        }),
      ]);
      const first = base.inputs[0];
      if (!first) throw new Error("prepared input missing");
      const perturbed = new ProofInputUtxo({
        utxo:
          testCase.perturbation === "utxoData"
            ? new Utxo({
                owner: first.utxo.owner,
                asset: first.utxo.asset,
                amount: first.utxo.amount,
                blinding: first.utxo.blinding,
                data: new Data([{ kind: "utxoData", bytes: Uint8Array.from([4, 5]) }]),
                ...(first.utxo.zoneProgramId === undefined
                  ? {}
                  : { zoneProgramId: first.utxo.zoneProgramId }),
              })
            : testCase.perturbation === "foreignZone"
              ? new Utxo({
                  owner: first.utxo.owner,
                  asset: first.utxo.asset,
                  amount: first.utxo.amount,
                  blinding: first.utxo.blinding,
                  zoneProgramId: oracle.merge.foreignZone as Address,
                })
              : first.utxo,
        nullifierKey: first.nullifierKey,
        ...(testCase.perturbation === "dataHash" ? { dataHash } : {}),
        ...(testCase.perturbation === "zoneDataHash" ? { zoneDataHash } : {}),
      });
      const inputs = [perturbed, ...base.inputs.slice(1)];
      const prepared = zoneRail
        ? new PreparedMergeZone({
            inputs,
            output: base.output,
            expiryUnixTs: base.expiryUnixTs,
            signingPublicKey: base.signingPublicKey,
            userViewingPublicKey: base.userViewingPublicKey,
            txViewingSecret: base.txViewingSecret,
            zoneProgramId: zone,
          })
        : new PreparedMerge({
            inputs,
            output: base.output,
            expiryUnixTs: base.expiryUnixTs,
            signingPublicKey: base.signingPublicKey,
            userViewingPublicKey: base.userViewingPublicKey,
            txViewingSecret: base.txViewingSecret,
          });
      if (testCase.error !== null) {
        expect(codeOf(() => prepared.inputUtxoHashes())).toBe(testCase.error);
        return;
      }
      expect(contexts(prepared)).toEqual(testCase.inputContexts);
    });
  }
});

interface SplitCase {
  readonly name: string;
  readonly input: MergeInputSpec;
  readonly asset: string;
  readonly numOutputs: number;
  readonly perOutputAmount: string;
  readonly dummyInput: boolean;
  readonly error: string | null;
  readonly outputAmounts: readonly string[] | null;
  readonly firstNullifierHex: string | null;
  readonly ownerViewTagHex: string | null;
  readonly payerPublicKeyHashHex: string | null;
}

describe("the Rust oracle and TypeScript agree on the split builder", () => {
  const split = oracle.split;
  const owner = shieldedKeypair(7, oracle.transfer.ownerViewingSeedHex);

  for (const testCase of split.cases as readonly SplitCase[]) {
    it(`decides ${testCase.name} the same way`, () => {
      const build = (): PreparedSplit =>
        new ConfidentialSplit({
          owner: owner.shieldedAddress(),
          input: testCase.dummyInput ? ProofInputUtxo.dummy() : mergeInput(testCase.input),
          asset: testCase.asset as Address,
          numOutputs: testCase.numOutputs,
          perOutputAmount: BigInt(testCase.perOutputAmount),
          payer: split.payer as Address,
        }).prepare();
      if (testCase.error !== null) {
        expect(codeOf(build)).toBe(testCase.error);
        return;
      }
      const prepared = build();
      expect(prepared.outputs.map((output) => output.amount.toString())).toEqual(
        testCase.outputAmounts,
      );
      expect(hex(prepared.firstNullifier)).toBe(testCase.firstNullifierHex);
      expect(hex(prepared.ownerViewTag())).toBe(testCase.ownerViewTagHex);
      expect(hex(prepared.payerPublicKeyHash)).toBe(testCase.payerPublicKeyHashHex);
    });
  }
});

interface PrivateTxHashCase {
  readonly name: string;
  readonly inputHashesHex: readonly string[];
  readonly outputHashesHex: readonly string[];
  readonly addressHashesHex: readonly string[] | null;
  readonly hashHex: string | null;
  readonly error: string | null;
  readonly expected: number | null;
  readonly actual: number | null;
}

interface InputUtxoCase {
  readonly name: string;
  readonly zone: string | null;
  readonly dataHash: boolean;
  readonly zoneDataHash: boolean;
  readonly isDummy: boolean;
  readonly hashHex: string;
}

interface OutputBuilderCase {
  readonly name: string;
  readonly ops: readonly string[];
  readonly records: readonly Readonly<{ kind: string; bytesHex: string }>[];
  readonly dataHashHex: string | null;
  readonly zoneDataHashHex: string | null;
  readonly zoneProgramId: string | null;
  readonly isDummy: boolean;
  readonly ownerHashHex: string;
  readonly hashHex: string;
}

interface EncryptedTransactionCase {
  readonly name: string;
  readonly realInput: boolean;
  readonly realOutput: boolean;
  readonly hashHex: string;
}

describe("the Rust oracle and TypeScript agree on the transaction types", () => {
  const types = oracle.transactTypes;
  const owner = shieldedKeypair(7, oracle.transfer.ownerViewingSeedHex);
  const blinding = bytes(types.blindingHex) as Bytes31;
  const nullifierPublicKey = bytes(types.nullifierPublicKeyHex) as Bytes32;
  const dataHash = bytes(oracle.merge.dataHashHex) as Bytes32;
  const zoneDataHash = bytes(oracle.merge.zoneDataHashHex) as Bytes32;
  const zone = oracle.merge.zone as Address;
  const zeroAddress = "11111111111111111111111111111111" as Address;

  function inputUtxo(spec: Readonly<{ zone: boolean; dataHash: boolean; zoneDataHash: boolean }>) {
    return createInputUtxo({
      utxo: new Utxo({
        owner: owner.signingPublicKey(),
        asset: SOL_MINT,
        amount: 100n,
        blinding,
        ...(spec.zone ? { zoneProgramId: zone } : {}),
      }),
      nullifierPublicKey,
      ...(spec.dataHash ? { dataHash } : {}),
      ...(spec.zoneDataHash ? { zoneDataHash } : {}),
    });
  }

  function emptyExternalData() {
    return createExternalData({
      instructionDiscriminator: types.emptyExternalData.instructionDiscriminator,
      expiryUnixTs: BigInt(types.emptyExternalData.expiryUnixTs),
      relayerFee: types.emptyExternalData.relayerFee,
      userSolAccount: zeroAddress,
      userSplToken: zeroAddress,
      splTokenInterface: zeroAddress,
      // Not covered by `externalDataHash` on either side; only the type needs it.
      txViewingPublicKey: owner.viewingPublicKey(),
      salt: new Uint8Array(16) as Bytes16,
      outputs: [],
      resolvedOwnerTags: [],
      messages: [],
    });
  }

  it("hashes the same empty external data", () => {
    expect(hex(emptyExternalData().hash())).toBe(types.emptyExternalData.hashHex);
  });

  for (const testCase of types.privateTxHashes as readonly PrivateTxHashCase[]) {
    it(`chains ${testCase.name} the same way`, () => {
      const input = {
        inputHashes: testCase.inputHashesHex.map((value) => bytes(value) as Bytes32),
        outputHashes: testCase.outputHashesHex.map((value) => bytes(value) as Bytes32),
        ...(testCase.addressHashesHex === null
          ? {}
          : { addressHashes: testCase.addressHashesHex.map((value) => bytes(value) as Bytes32) }),
        externalDataHash: bytes(types.externalDataHashHex) as Bytes32,
      };
      if (testCase.error !== null) {
        expect(codeOf(() => privateTxHash(input))).toBe(testCase.error);
        if (testCase.expected !== null) {
          expect(details(() => privateTxHash(input))).toEqual({
            expected: testCase.expected,
            actual: testCase.actual,
          });
        }
        return;
      }
      expect(hex(privateTxHash(input))).toBe(testCase.hashHex);
    });
  }

  for (const testCase of types.inputUtxos as readonly InputUtxoCase[]) {
    it(`hashes the ${testCase.name} input the same way`, () => {
      const input = inputUtxo({
        zone: testCase.zone !== null,
        dataHash: testCase.dataHash,
        zoneDataHash: testCase.zoneDataHash,
      });
      expect(input.isDummy()).toBe(testCase.isDummy);
      expect(hex(input.hash())).toBe(testCase.hashHex);
    });
  }

  for (const testCase of types.outputBuilders as readonly OutputBuilderCase[]) {
    it(`builds the ${testCase.name} output the same way`, () => {
      const payloads: Readonly<Record<string, number[]>> = {
        memoA: [6],
        memoB: [9, 9],
        utxoDataA: [4, 5],
        utxoDataB: [7],
        zoneDataA: [1, 2, 3],
      };
      let output = createProofOutput({
        ownerAddress: owner.shieldedAddress(),
        asset: SOL_MINT,
        amount: 100n,
        blinding,
      });
      for (const op of testCase.ops) {
        switch (op) {
          case "memoA":
          case "memoB":
            output = output.withMemo(Uint8Array.from(payloads[op] ?? []));
            break;
          case "utxoDataA":
          case "utxoDataB":
            output = output.withUtxoData(Uint8Array.from(payloads[op] ?? []), dataHash);
            break;
          case "zoneDataA":
            output = output.withZoneData(zone, Uint8Array.from(payloads[op] ?? []), zoneDataHash);
            break;
          case "zoneProgramId":
            output = output.withZoneProgramId(zone);
            break;
          case "zoneDataHash":
            output = output.withZoneDataHash(zone, zoneDataHash);
            break;
          default:
            throw new Error(`unknown output builder op ${op}`);
        }
      }
      expect(
        output.data.records().map((record) => ({ kind: record.kind, bytesHex: hex(record.bytes) })),
      ).toEqual(testCase.records);
      expect(output.dataHash === undefined ? null : hex(output.dataHash)).toBe(
        testCase.dataHashHex,
      );
      expect(output.zoneDataHash === undefined ? null : hex(output.zoneDataHash)).toBe(
        testCase.zoneDataHashHex,
      );
      expect(output.zoneProgramId ?? null).toBe(testCase.zoneProgramId);
      expect(output.isDummy()).toBe(testCase.isDummy);
      expect(hex(output.ownerHash())).toBe(testCase.ownerHashHex);
      expect(hex(output.hash())).toBe(testCase.hashHex);
    });
  }

  for (const testCase of types.encryptedTransaction as readonly EncryptedTransactionCase[]) {
    it(`hashes the ${testCase.name} transaction the same way`, () => {
      const input = testCase.realInput
        ? inputUtxo({ zone: false, dataHash: false, zoneDataHash: false })
        : createInputUtxo({
            utxo: new Utxo({
              owner: ShieldedPublicKey.zeroed(),
              asset: zeroAddress,
              amount: 0n,
              blinding,
            }),
            nullifierPublicKey: new Uint8Array(32) as Bytes32,
          });
      const output = testCase.realOutput
        ? createProofOutput({
            ownerAddress: owner.shieldedAddress(),
            asset: SOL_MINT,
            amount: 100n,
            blinding,
          })
        : createProofOutput({
            asset: zeroAddress,
            amount: 0n,
            blinding: new Uint8Array(31) as Bytes31,
          });
      const transaction = createEncryptedTransaction({
        inputs: [input],
        outputs: [output],
        externalData: emptyExternalData(),
      });
      expect(hex(transaction.hash())).toBe(testCase.hashHex);
    });
  }
});

interface ZoneAuthorityCase {
  readonly name: string;
  readonly inputZone: string | null;
  readonly outputZone: string | null;
  readonly pinnedZone: string;
  readonly publicSol: string | null;
  readonly extraOutputs: number;
  readonly error: string | null;
  readonly index: number | null;
  readonly shape: ShapeJson | null;
  readonly payerPublicKeyHashHex: string | null;
  readonly inputContexts: readonly ContextJson[] | null;
}

describe("the Rust oracle and TypeScript agree on the zone-authority rail", () => {
  const owner = shieldedKeypair(7, oracle.transfer.ownerViewingSeedHex);
  const blinding = bytes(oracle.transactTypes.blindingHex) as Bytes31;
  const payerPublicKeyHash = bytes(
    (oracle.zoneAuthority as readonly ZoneAuthorityCase[])[0]?.payerPublicKeyHashHex ?? "",
  ) as Bytes32;

  for (const testCase of oracle.zoneAuthority as readonly ZoneAuthorityCase[]) {
    it(`decides ${testCase.name} the same way`, () => {
      const outputs = [
        createProofOutput({
          ownerAddress: owner.shieldedAddress(),
          asset: SOL_MINT,
          amount: 500n,
          blinding,
          ...(testCase.outputZone === null
            ? {}
            : { zoneProgramId: testCase.outputZone as Address }),
        }),
        ...Array.from({ length: testCase.extraOutputs + 1 }, () =>
          createProofOutput({
            asset: "11111111111111111111111111111111" as Address,
            amount: 0n,
            blinding: new Uint8Array(31) as Bytes31,
          }),
        ),
      ];
      const prepare = (): PreparedZoneAuthority =>
        prepareZoneAuthority({
          inputs: [
            new ProofInputUtxo({
              utxo: new Utxo({
                owner: owner.signingPublicKey(),
                asset: SOL_MINT,
                amount: 500n,
                blinding,
                ...(testCase.inputZone === null
                  ? {}
                  : { zoneProgramId: testCase.inputZone as Address }),
              }),
              nullifierKey: owner.nullifierKey(),
            }),
            ProofInputUtxo.dummy(blinding),
          ],
          outputs,
          zoneProgramId: testCase.pinnedZone as Address,
          payerPublicKeyHash,
          ...(testCase.publicSol === null
            ? {}
            : { publicAmounts: { sol: BigInt(testCase.publicSol) } }),
        });
      if (testCase.error !== null) {
        expect(rejection(prepare)).toEqual({ code: testCase.error, field: null });
        if (testCase.index !== null) {
          expect(details(prepare)).toEqual({ index: testCase.index });
        }
        return;
      }
      const prepared = prepare();
      expect({ inputs: prepared.shape.inputs, outputs: prepared.shape.outputs }).toEqual(
        testCase.shape,
      );
      expect(hex(prepared.payerPublicKeyHash)).toBe(testCase.payerPublicKeyHashHex);
      expect(
        prepared.inputUtxoHashes().map((context) => ({
          index: context.index,
          utxoHashHex: hex(context.utxoHash),
          nullifierHex: hex(context.nullifier),
        })),
      ).toEqual(testCase.inputContexts);
    });
  }
});

interface DecryptCase {
  readonly name: string;
  readonly bodyHex: string;
  readonly slotIndex?: number;
  readonly error: Readonly<{
    code: string;
    expected: number | null;
    actual: number | null;
  }> | null;
  readonly plaintext: Readonly<{
    assetId?: string;
    amount: string;
    assetFieldHex?: string;
    blindingHex: string;
  }> | null;
}

describe("the Rust oracle and TypeScript agree on the encrypted rails' reader", () => {
  const decrypt = oracle.decrypt;
  const user = ViewingKey.fromBytes(bytes(decrypt.userViewingSeedHex) as Bytes32);
  const tx = ViewingKey.fromBytes(bytes(decrypt.txViewingSeedHex) as Bytes32);
  const salt = bytes(decrypt.saltHex) as Bytes16;

  /// `Reader.exact` names leftover bytes; Rust folds that rejection into the
  /// wincode `Deserialize` category. TYPESCRIPT_ONLY_CODES already records the
  /// finer code as deliberate, so the comparison widens it rather than
  /// treating the same rejection as a divergence.
  const RUST_CATEGORY: Readonly<Record<string, string>> = Object.freeze({
    TRANSACTION_TRAILING_BYTES: "TRANSACTION_DESERIALIZE",
  });

  /// A published slot is attacker-chosen bytes, so the reader's rejection
  /// category is part of the protocol: both languages must sort the same body
  /// into the same category rather than merely both failing.
  function expectSame(testCase: DecryptCase, run: () => unknown): void {
    if (testCase.error !== null) {
      const code = codeOf(run);
      expect(RUST_CATEGORY[code] ?? code).toBe(testCase.error.code);
      if (testCase.error.expected !== null) {
        expect(details(run)).toMatchObject({
          expected: testCase.error.expected,
          actual: testCase.error.actual,
        });
      }
      return;
    }
    expect(run()).toBeDefined();
  }

  for (const testCase of decrypt.merge as readonly DecryptCase[]) {
    it(`reads the ${testCase.name} merge body the same way`, () => {
      const read = (): unknown => decryptMerge(user, bytes(testCase.bodyHex));
      expectSame(testCase, read);
      if (testCase.plaintext === null) return;
      const plaintext = decryptMerge(user, bytes(testCase.bodyHex));
      expect({
        amount: plaintext.amount.toString(),
        assetFieldHex: hex(plaintext.assetField),
        blindingHex: hex(plaintext.blinding),
      }).toEqual(testCase.plaintext);
    });
  }

  for (const testCase of decrypt.confidential as readonly DecryptCase[]) {
    it(`reads the ${testCase.name} confidential body the same way`, () => {
      const slotIndex = testCase.slotIndex ?? decrypt.slotIndex;
      const read = (): unknown =>
        decryptConfidential(user, tx.publicKey(), bytes(testCase.bodyHex), salt, slotIndex);
      expectSame(testCase, read);
      if (testCase.plaintext === null) return;
      const plaintext = decryptConfidential(
        user,
        tx.publicKey(),
        bytes(testCase.bodyHex),
        salt,
        slotIndex,
      );
      expect({
        assetId: plaintext.assetId.toString(),
        amount: plaintext.amount.toString(),
        blindingHex: hex(plaintext.blinding),
      }).toEqual(testCase.plaintext);
    });
  }
});

interface ProgressionStep {
  readonly index: number;
  readonly tagHex: string;
  readonly saltHex: string;
  readonly slotIndex: number;
  readonly amount: string;
  readonly blindingHex: string;
  readonly plaintextHex: string;
  readonly bodyHex: string;
}

/**
 * A sender and a recipient exchanging four anonymous transfers in sequence.
 * The shared view tag advances by an index the two sides derive independently,
 * which is how the recipient finds its slot without a per-transfer channel, and
 * each step carries the transfer that tag addresses, so the tag stream and the
 * payload are checked in step rather than only in isolation.
 */
describe("the Rust oracle and TypeScript agree on the anonymous tag progression", () => {
  const progression = oracle.anonymousProgression;
  const sender = ViewingKey.fromBytes(bytes(progression.senderViewingSeedHex) as Bytes32);
  const recipient = ViewingKey.fromBytes(bytes(progression.recipientViewingSeedHex) as Bytes32);
  const tx = ViewingKey.fromBytes(bytes(progression.txViewingSeedHex) as Bytes32);
  const steps = progression.steps as readonly ProgressionStep[];

  for (const step of steps) {
    it(`derives the tag and the transfer at index ${String(step.index)} the same way`, () => {
      const index = BigInt(step.index);
      expect(hex(sender.sendSharedViewTag(recipient.publicKey(), index))).toBe(step.tagHex);
      expect(hex(recipient.recipientSharedViewTag(sender.publicKey(), index))).toBe(step.tagHex);

      const plaintext = decryptAnonymous(
        recipient,
        tx.publicKey(),
        bytes(step.bodyHex),
        bytes(step.saltHex) as Bytes16,
        step.slotIndex,
      );
      expect(hex(plaintext)).toBe(step.plaintextHex);

      const decoded = decodeAnonymousRecipient(plaintext);
      expect(decoded.amount).toBe(BigInt(step.amount));
      expect(hex(decoded.blinding)).toBe(step.blindingHex);
      expect(hex(decoded.senderPublicKey.toBytes())).toBe(hex(sender.publicKey().toBytes()));
      expect(hex(decoded.ownerPublicKey.toBytes())).toBe(progression.ownerPublicKeyHex);
    });
  }

  it("advances the tag at every step", () => {
    expect(new Set(steps.map((step) => step.tagHex)).size).toBe(steps.length);
  });
});

interface BuilderSequenceCase {
  readonly name: string;
  readonly ops: readonly string[];
  readonly hashHex: string | null;
  readonly error: string | null;
}

interface ExternalDataCase {
  readonly name: string;
  readonly outputs: number;
  readonly messages: number;
  readonly outputDataLength: number | null;
  readonly messageDataLength: number;
  readonly tags: number | null;
  readonly hashHex: string | null;
  readonly error: string | null;
}

/**
 * The preimage writes the output count, each output's ciphertext length, the
 * message count, and each message's length behind `u16` prefixes, and
 * `program-libs/interface` casts rather than checking. Under the T21 ruling
 * both SDKs refuse the oversized input rather than hash a shortened preimage,
 * so this is a deliberate and documented case of the SDKs being stricter than
 * the deployed program, at a size no Solana transaction can carry.
 */
describe("the Rust oracle and TypeScript agree at the external-data prefix bounds", () => {
  const external = oracle.externalData;
  const txViewingPublicKey = P256PublicKey.fromBytes(
    bytes(external.txViewingPublicKeyHex) as Bytes33,
  );
  const salt = bytes(external.saltHex) as Bytes16;
  const zeroAddress = "11111111111111111111111111111111" as Address;
  const defaults = oracle.transactTypes.emptyExternalData;

  /// Index `i` big-endian at the front of the commitment and at the back of the
  /// owner tag, matching the Rust shape, so pairing them the wrong way round
  /// changes the hash rather than passing.
  function indexed(index: number, atFront: boolean): Bytes32 {
    const value = new Uint8Array(32);
    const offset = atFront ? 0 : 30;
    value[offset] = (index >> 8) & 0xff;
    value[offset + 1] = index & 0xff;
    return value as Bytes32;
  }

  for (const testCase of external.cases as readonly ExternalDataCase[]) {
    it(`hashes or refuses the ${testCase.name} shape the same way`, () => {
      const build = (): Bytes32 =>
        createExternalData({
          instructionDiscriminator: defaults.instructionDiscriminator,
          expiryUnixTs: BigInt(defaults.expiryUnixTs),
          relayerFee: defaults.relayerFee,
          userSolAccount: zeroAddress,
          userSplToken: zeroAddress,
          splTokenInterface: zeroAddress,
          txViewingPublicKey,
          salt,
          outputs: Array.from({ length: testCase.outputs }, (_unused, index) => ({
            utxoHash: indexed(index, true),
            ownerTag: { kind: "p256SigningKey" as const },
            ...(testCase.outputDataLength === null
              ? {}
              : {
                  data: new Uint8Array(testCase.outputDataLength).fill(external.outputDataByte),
                }),
          })),
          resolvedOwnerTags: Array.from(
            { length: testCase.tags ?? testCase.outputs },
            (_unused, index) => indexed(index, false),
          ),
          messages: Array.from({ length: testCase.messages }, (_unused, index) => ({
            viewTag: indexed(index, true),
            data: new Uint8Array(testCase.messageDataLength).fill(external.messageDataByte),
          })),
        }).hash();

      if (testCase.error !== null) {
        expect(codeOf(build)).toBe(testCase.error);
        return;
      }
      expect(hex(build())).toBe(testCase.hashHex);
    });
  }

  describe("and on the constructor defaults and the three builders", () => {
    const builders = external.builders;

    const shaped = (): ExternalData =>
      createExternalData({
        txViewingPublicKey,
        salt,
        outputs: Array.from({ length: builders.outputs }, (_unused, index) => ({
          utxoHash: indexed(index, true),
          ownerTag: { kind: "p256SigningKey" as const },
          data: new Uint8Array(builders.outputDataLength).fill(external.outputDataByte),
        })),
        resolvedOwnerTags: Array.from({ length: builders.outputs }, (_unused, index) =>
          indexed(index, false),
        ),
        messages: Array.from({ length: builders.messages }, (_unused, index) => ({
          viewTag: indexed(index, true),
          data: new Uint8Array(builders.messageDataLength).fill(external.messageDataByte),
        })),
      });

    const apply = (data: ExternalData, op: string): ExternalData => {
      switch (op) {
        case "publicSol":
          return data.withPublicSol(BigInt(builders.solAmount), builders.solAccount as Address);
        case "publicSpl":
          return data.withPublicSpl(
            BigInt(builders.splAmount),
            builders.splToken as Address,
            builders.splTokenInterface as Address,
          );
        case "zoneHashes":
          return data.withZoneHashes(
            bytes(builders.dataHashHex) as Bytes32,
            bytes(builders.zoneDataHashHex) as Bytes32,
          );
        default:
          throw new Error(`unknown builder op ${op}`);
      }
    };

    for (const testCase of builders.cases as readonly BuilderSequenceCase[]) {
      it(`applies ${testCase.name} the same way`, () => {
        const build = (): Bytes32 =>
          testCase.ops.reduce((data, op) => apply(data, op), shaped()).hash();
        if (testCase.error !== null) {
          expect(codeOf(build)).toBe(testCase.error);
          return;
        }
        expect(hex(build())).toBe(testCase.hashHex);
      });
    }

    it("leaves the value a builder derived from untouched", () => {
      const defaults = (builders.cases as readonly BuilderSequenceCase[]).find(
        (entry) => entry.name === "defaults",
      );
      const base = shaped();
      base.withPublicSol(BigInt(builders.solAmount), builders.solAccount as Address);
      expect(base.publicSolAmount).toBeUndefined();
      expect(hex(base.hash())).toBe(defaults?.hashHex);
    });
  });
});

describe("the Rust oracle and TypeScript agree on public-input field encodings", () => {
  const fields = oracle.fields;

  it("pins the same BN254 modulus", () => {
    expect(BN254_MODULUS_DEC).toBe(fields.bn254Modulus);
  });

  it("wraps every signed amount into the same field element", () => {
    for (const entry of fields.signedToField as readonly Readonly<{
      value: string;
      fieldHex: string;
    }>[]) {
      expect(hex(signedToField(BigInt(entry.value)))).toBe(entry.fieldHex);
    }
  });

  it("hashes every asset into the same field element", () => {
    for (const entry of fields.assetField as readonly Readonly<{
      asset: string;
      fieldHex: string;
    }>[]) {
      expect(hex(assetField(entry.asset as Address))).toBe(entry.fieldHex);
    }
  });
});

describe("the Rust oracle and TypeScript agree on wallet balances", () => {
  const section = oracle.walletBalances;
  const mints = section.mints as Readonly<Record<string, Address>>;

  interface Balance {
    readonly assetId: string;
    readonly mint: string;
    readonly amount: string;
    readonly utxoAmounts: readonly string[];
  }
  type Arm =
    | { readonly arm: "ok"; readonly value: Balance | readonly Balance[] }
    | { readonly arm: "err"; readonly error: string };

  const filled = (value: number): Bytes32 => new Uint8Array(32).fill(value) as Bytes32;
  const minAmount = (value: bigint): Filter => ({ kind: "minAmount", minAmount: value });
  const describeBalance = (balance: AssetBalance): Balance => ({
    assetId: balance.assetId.toString(),
    mint: balance.mint,
    amount: balance.amount.toString(),
    utxoAmounts: balance.utxos.map((utxo) => utxo.amount.toString()),
  });

  function observe(outcome: Arm, act: () => Balance | readonly Balance[]): unknown {
    if (outcome.arm === "ok") return { arm: "ok", value: act() };
    try {
      act();
    } catch (cause) {
      return { arm: "err", error: (cause as { code?: unknown }).code };
    }
    throw new Error(`expected ${outcome.error} but the call returned`);
  }

  function walletOf(): Wallet {
    const keypair = ShieldedKeypair.fromEd25519(filled(71), 0);
    const wallet = new Wallet({
      identity: keypair.shieldedAddress(),
      registry: new AssetRegistry(
        (section.registry as readonly (readonly [string, string])[]).map(
          ([id, mint]) => [BigInt(id), mint as Address] as const,
        ),
      ),
    });
    wallet._replace({
      utxos: (
        section.notes as readonly Readonly<{ mint: string; amount: string; spent: boolean }>[]
      ).map((note, index) => ({
        utxo: new Utxo({
          owner: keypair.signingPublicKey(),
          asset: mints[note.mint] as Address,
          amount: BigInt(note.amount),
          blinding: new Uint8Array(31).fill(index + 1) as Bytes31,
          data: new Data(),
        }),
        outputContext: {
          hash: filled(index + 1),
          tree: mints.sol as Address,
          leafIndex: BigInt(index),
        },
        nullifier: filled(index + 20),
        spent: note.spent,
      })),
      transactions: [],
      nullifiers: new Set(),
    });
    return wallet;
  }

  // A registered mint the wallet holds no note of still has a balance, the
  // min-amount filter narrows which notes count, and an unregistered mint is a
  // rejection rather than an absent entry.
  const filters: Readonly<Record<string, readonly [string, Filter | undefined]>> = {
    sol: ["sol", undefined],
    solMinAmount5: ["sol", minAmount(5n)],
    solMinAmountAboveEvery: ["sol", minAmount(1000n)],
    second: ["second", undefined],
    emptyRegistered: ["emptyRegistered", undefined],
    unregistered: ["unregistered", undefined],
  };

  for (const [name, [mint, filter]] of Object.entries(filters)) {
    const outcome = (section.balance as Readonly<Record<string, Arm>>)[name];
    if (outcome === undefined) throw new Error(`the oracle has no balance case ${name}`);
    it(`balance: ${name}`, () => {
      const wallet = walletOf();
      expect(
        observe(outcome, () =>
          describeBalance(
            filter === undefined
              ? wallet.balance(mints[mint] as Address)
              : wallet.balance(mints[mint] as Address, filter),
          ),
        ),
      ).toEqual(outcome);
    });
  }

  for (const [name, skipUtxos] of [
    ["withUtxos", false],
    ["skipUtxos", true],
  ] as const) {
    const outcome = (section.balances as Readonly<Record<string, Arm>>)[name];
    if (outcome === undefined) throw new Error(`the oracle has no balances case ${name}`);
    it(`balances: ${name}`, () => {
      const wallet = walletOf();
      expect(observe(outcome, () => wallet.balances(skipUtxos).map(describeBalance))).toEqual(
        outcome,
      );
    });
  }
});
