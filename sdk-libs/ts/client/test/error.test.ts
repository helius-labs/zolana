import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { KeypairError } from "@zolana/keypair";
import { SppProofInputs, TransactionError } from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import fixtureJson from "../../fixtures/client/errors-v1.json" with { type: "json" };
import manifestJson from "../../fixtures/manifest.json" with { type: "json" };
import {
  CANONICAL_CLIENT_ERROR_CODES,
  ClientError,
  type CanonicalClientErrorCode,
  type ClientErrorCode,
} from "../src/index.js";
import { TYPESCRIPT_CLIENT_ERROR_CODES, fromClientCause, hasherError } from "../src/error.js";
import { poseidon } from "../src/internal.js";
import { assemble } from "../src/prover/index.js";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const PRODUCER = /new ClientError\(\s*"(CLIENT_[A-Z0-9_]+)"/gu;

/** Canonical variants TypeScript surfaces as the wrapped keypair, transaction, or hasher error. */
const WRAPPED_IN_LOWER_LEVEL_ERROR: readonly CanonicalClientErrorCode[] = [
  "CLIENT_UNSUPPORTED_SHAPE",
  "CLIENT_TOO_MANY_INPUTS",
  "CLIENT_TOO_MANY_OUTPUTS",
  "CLIENT_INSUFFICIENT_BALANCE",
  "CLIENT_SELECTED_BALANCE_OVERFLOW",
  "CLIENT_UNSIGNED_INPUT_UNAVAILABLE",
  "CLIENT_AMBIGUOUS_TREE",
  "CLIENT_MISSING_SPL_TOKEN_ACCOUNT",
  "CLIENT_ADDRESS_RESOLUTION",
  "CLIENT_USER_REGISTRY_RECORD_NOT_FOUND",
  "CLIENT_MULTIPLE_PUBLIC_SPL_ASSETS",
  "CLIENT_WITHDRAWAL_ALREADY_SET",
  "CLIENT_EDDSA_INPUT_NOT_SOLANA_OWNED",
  "CLIENT_MERGE_INPUT_RAIL_MISMATCH",
  "CLIENT_MERGE_INPUT_ASSET_MISMATCH",
  "CLIENT_MERGE_DISABLED",
  "CLIENT_NOTHING_TO_MERGE",
  "CLIENT_DUPLICATE_INPUT_UTXO",
  "CLIENT_MERGE_VIEWING_KEY_MISMATCH",
  "CLIENT_SPLIT_NOT_DIVISIBLE",
  "CLIENT_INPUT_UTXO_UNAVAILABLE",
  "CLIENT_INPUT_UTXO_TREE_MISMATCH",
  "CLIENT_SPLIT_INPUT_HAS_DATA",
  "CLIENT_SPLIT_INPUT_ZONE_MISMATCH",
  "CLIENT_P256_SIGNATURE",
  "CLIENT_PROVER",
  "CLIENT_INPUT_TREE_INDEX_COUNT_MISMATCH",
];

/** Canonical variants TypeScript splits into finer codes, listed with those codes. */
const NARROWED_INTO_FINER_CODES: Readonly<
  Partial<Record<CanonicalClientErrorCode, readonly ClientErrorCode[]>>
> = {
  CLIENT_RPC: ["CLIENT_RPC_HTTP", "CLIENT_RPC_JSON", "CLIENT_RPC_ENVELOPE"],
};

/** Canonical variants no TypeScript path reaches, each with the Rust producer that has no port. */
const NO_TYPESCRIPT_PRODUCER: Readonly<Partial<Record<CanonicalClientErrorCode, string>>> = {
  CLIENT_ACCOUNT_NOT_FOUND:
    "constructed only by program-tests/spp-test-validator/tests/deposit_action.rs, not by either SDK",
  CLIENT_DEPOSIT_SENDER_NOT_SIGNER:
    "constructed only by program-tests/spp-test-validator/tests/deposit_action.rs, not by either SDK",
};

const KEYPAIR_SOURCE = path.join(repositoryRoot, "sdk-libs/ts/keypair/src");

/**
 * Detail values `@zolana/keypair` may attach: a quoted label, a numeric bound,
 * a module constant, the length of some value, or the leading tag byte of a
 * public key. The sanitizer in `keypair/src/error.ts` bounds which detail keys
 * survive, not what they hold, so a call site that passed a computed value
 * would carry it intact to `ClientError.cause.details`.
 */
const LABEL = /^"[^"]*"$/u;
const SAFE_DETAIL_VALUES: readonly RegExp[] = [
  LABEL,
  /^-?\d[\d_]*$/u,
  /^0x[\da-f_]+$/iu,
  /^[A-Z][A-Z\d_]*$/u,
  /^[\w$.#]+\.length$/u,
  /^[\w$.#[\]]+\[0\] \?\? 0$/u,
];

/**
 * Parameters forwarded into a detail literal rather than written there. Each
 * one was traced to a literal or a length at every call site that reaches it.
 * Adding a name here asserts that trace; it is not a way to quiet the scan.
 */
const AUDITED_DETAIL_PARAMETERS: ReadonlySet<string> = new Set([
  "actual",
  "expected",
  "index",
  "info",
  "inputCount",
  "length",
  "name",
  "type",
  "width",
]);

interface SourceExpression {
  readonly location: string;
  readonly expression: string;
}

/** The text `source[open]` encloses, counting brackets and skipping string bodies. */
function balancedSlice(source: string, open: number): string {
  let depth = 0;
  let quote: string | undefined;
  for (let index = open; index < source.length; index++) {
    const character = source[index];
    if (quote !== undefined) {
      if (character === "\\") index++;
      else if (character === quote) quote = undefined;
      continue;
    }
    if (character === '"' || character === "'" || character === "`") quote = character;
    else if (character === "(" || character === "{" || character === "[") depth++;
    else if (character === ")" || character === "}" || character === "]") {
      depth--;
      if (depth === 0) return source.slice(open + 1, index);
    }
  }
  throw new Error(`unbalanced expression at offset ${String(open)}`);
}

function splitTopLevel(text: string): readonly string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | undefined;
  let start = 0;
  for (let index = 0; index < text.length; index++) {
    const character = text[index];
    if (quote !== undefined) {
      if (character === "\\") index++;
      else if (character === quote) quote = undefined;
      continue;
    }
    if (character === '"' || character === "'" || character === "`") quote = character;
    else if (character === "(" || character === "{" || character === "[") depth++;
    else if (character === ")" || character === "}" || character === "]") depth--;
    else if (character === "," && depth === 0) {
      parts.push(text.slice(start, index));
      start = index + 1;
    }
  }
  return [...parts, text.slice(start)].map((part) => part.trim()).filter((part) => part !== "");
}

async function keypairSources(): Promise<readonly (readonly [string, string])[]> {
  const sources: (readonly [string, string])[] = [];
  for (const entry of await readdir(KEYPAIR_SOURCE, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".ts")) continue;
    const file = path.join(entry.parentPath, entry.name);
    sources.push([path.relative(repositoryRoot, file), await readFile(file, "utf8")]);
  }
  return sources;
}

function locate(file: string, source: string, offset: number): string {
  return `${file}:${String(source.slice(0, offset).split("\n").length)}`;
}

function normalize(expression: string): string {
  return expression.trim().replace(/\s+/gu, " ");
}

/** Every value a `new KeypairError(...)` detail literal attaches. */
function detailValues(file: string, source: string): readonly SourceExpression[] {
  const values: SourceExpression[] = [];
  for (const match of source.matchAll(/new KeypairError\(/gu)) {
    const [, details] = splitTopLevel(balancedSlice(source, match.index + match[0].length - 1));
    if (details === undefined || !details.startsWith("{")) continue;
    for (const entry of splitTopLevel(balancedSlice(details, 0))) {
      const separator = entry.indexOf(":");
      const expression = separator === -1 ? entry : entry.slice(separator + 1);
      values.push({
        location: locate(file, source, match.index),
        expression: normalize(expression),
      });
    }
  }
  return values;
}

/** The label every `checkedBytes(...)` names its rejected argument with. */
function checkedBytesLabels(file: string, source: string): readonly SourceExpression[] {
  const labels: SourceExpression[] = [];
  for (const match of source.matchAll(/checkedBytes\s*(?:<[^>]*>)?\(/gu)) {
    if (/\bfunction\s+$/u.test(source.slice(0, match.index))) continue;
    const argument = splitTopLevel(balancedSlice(source, match.index + match[0].length - 1))[2];
    labels.push({
      location: locate(file, source, match.index),
      expression: normalize(argument ?? "<missing>"),
    });
  }
  return labels;
}

async function producedClientErrorCodes(): Promise<ReadonlySet<string>> {
  const workspace = JSON.parse(
    await readFile(path.join(repositoryRoot, "package.json"), "utf8"),
  ) as Readonly<{ workspaces: readonly string[] }>;
  const produced = new Set<string>();
  for (const packageDirectory of workspace.workspaces) {
    const sources = path.join(repositoryRoot, packageDirectory, "src");
    for (const entry of await readdir(sources, { recursive: true, withFileTypes: true })) {
      if (!entry.isFile() || !entry.name.endsWith(".ts")) continue;
      const source = await readFile(path.join(entry.parentPath, entry.name), "utf8");
      for (const [, code] of source.matchAll(PRODUCER)) produced.add(code);
    }
  }
  return produced;
}

interface ErrorVector {
  readonly code: string;
  readonly details: Readonly<Record<string, unknown>> | null;
}

function errorVectors(value: unknown): readonly ErrorVector[] {
  if (typeof value !== "object" || value === null) throw new Error("invalid error fixture");
  const fixture = value as Record<string, unknown>;
  if (
    fixture["schema"] !== "zolana-ts-fixtures-v1" ||
    fixture["id"] !== "fx-p09-client-errors-v1" ||
    fixture["rustPath"] !==
      "sdk-libs/client/src/error.rs; sdk-libs/keypair/src/error.rs; sdk-libs/transaction/src/error.rs; program-libs/hasher/src/errors.rs" ||
    fixture["rustSymbol"] !== "ClientError; KeypairError; TransactionError; HasherError"
  ) {
    throw new Error("invalid error fixture provenance");
  }
  const expected = fixture["expected"];
  if (typeof expected !== "object" || expected === null) throw new Error("invalid error fixture");
  const variants = (expected as Record<string, unknown>)["variants"];
  if (!Array.isArray(variants)) throw new Error("invalid error fixture");
  return Object.freeze(
    variants.map((variant) => {
      if (typeof variant !== "object" || variant === null) throw new Error("invalid error vector");
      const code = (variant as Record<string, unknown>)["code"];
      const details = (variant as Record<string, unknown>)["details"];
      if (
        typeof code !== "string" ||
        (details !== null && (typeof details !== "object" || Array.isArray(details)))
      ) {
        throw new Error("invalid error vector");
      }
      return Object.freeze({
        code,
        details: details === null ? null : Object.freeze({ ...details }),
      });
    }),
  );
}

describe("ClientError", () => {
  it("matches every Rust ClientError variant and structured field", async () => {
    const vectors = errorVectors(fixtureJson);
    const fixtureBytes = await readFile(
      path.join(repositoryRoot, "sdk-libs/ts/fixtures/client/errors-v1.json"),
    );
    // Manifest is the machine-readable baseline; ts-fixtures owns the pin.
    expect(manifestJson.frozenCommit).toMatch(/^[0-9a-f]{40}$/u);
    expect(manifestJson.historicalBaselineCommit).toBe(manifestJson.frozenCommit);
    // Shape first: missing stamps would make the equality below hold vacuously.
    expect(fixtureJson.sourceRevision).toMatch(/^[0-9a-f]{40}$/u);
    expect(manifestJson.canonicalSourceRevisions.client).toBe(fixtureJson.sourceRevision);
    expect(manifestJson.files).toContainEqual({
      path: "client/errors-v1.json",
      sha256: createHash("sha256").update(fixtureBytes).digest("hex"),
    });
    expect(vectors).toHaveLength(61);
    expect(new Set(vectors.map(({ code }) => code)).size).toBe(vectors.length);
    expect(vectors.map(({ code }) => code)).toEqual(CANONICAL_CLIENT_ERROR_CODES);

    const treeMismatch = vectors.find(({ code }) => code === "CLIENT_TREE_MISMATCH");
    expect(treeMismatch?.details).toEqual({
      clientTree: "02".repeat(32),
      transactionTree: "01".repeat(32),
    });
    expect(vectors.find(({ code }) => code === "CLIENT_INCOMPLETE_INPUT_PROOFS")?.details).toEqual({
      expected: 2,
      nullifier: 0,
      state: 1,
    });
    expect(vectors.find(({ code }) => code === "CLIENT_POLL_TIMED_OUT")?.details).toEqual({
      attempts: 3,
      lastCause: { category: "indexer" },
    });
    expect(vectors.map(({ code }) => code)).toContain("CLIENT_PROOF_INPUT_COUNT_MISMATCH");

    for (const vector of vectors) {
      expect(
        new ClientError(vector.code, {
          ...(vector.details === null ? {} : { details: vector.details }),
        }),
      ).toBeInstanceOf(ClientError);
    }
  });

  it("preserves wrapped categories and non-secret structured fields", () => {
    const keypair = fromClientCause(
      new KeypairError("KEYPAIR_INVALID_SECRET_KEY", {
        reason: "destroyed",
        secret: "must not escape",
      }),
    );
    expect(keypair).toMatchObject({
      code: "CLIENT_KEYPAIR",
      details: { code: "KEYPAIR_INVALID_SECRET_KEY" },
    });
    // Exact, not a subset: a key that survived sanitizing must fail here.
    expect(keypair.cause).toEqual({
      category: "keypair",
      code: "KEYPAIR_INVALID_SECRET_KEY",
      details: { reason: "destroyed" },
    });

    const transaction = fromClientCause(
      new TransactionError("TRANSACTION_INSUFFICIENT_BALANCE", {
        requested: "11",
        available: "10",
      }),
    );
    expect(transaction).toMatchObject({
      code: "CLIENT_TRANSACTION",
      details: { code: "TRANSACTION_INSUFFICIENT_BALANCE" },
    });
    expect(transaction.cause).toEqual({
      category: "transaction",
      code: "TRANSACTION_INSUFFICIENT_BALANCE",
      details: { requested: "11", available: "10" },
    });
    expect(JSON.stringify([keypair, transaction])).not.toContain("must not escape");
  });

  it("translates a keypair rejection at the assembly boundary", () => {
    const proofInputs = Object.assign(Object.create(SppProofInputs.prototype) as object, {
      inputUtxos: [
        {
          isDummy: () => false,
          utxo: {
            owner: {
              signatureType(): never {
                throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { prefix: 9 });
              },
            },
          },
        },
      ],
      outputs: [],
      checkShape: () => ({ inputs: 1, outputs: 1 }),
    }) as SppProofInputs;

    expect(() => assemble(proofInputs, [{} as never])).toThrow(
      expect.objectContaining({
        code: "CLIENT_KEYPAIR",
        details: { code: "KEYPAIR_INVALID_SIGNATURE_TYPE" },
        cause: {
          category: "keypair",
          code: "KEYPAIR_INVALID_SIGNATURE_TYPE",
          details: { prefix: 9 },
        },
      }),
    );
  });

  it("translates a transaction rejection at the assembly boundary", () => {
    const proofInputs = Object.assign(Object.create(SppProofInputs.prototype) as object, {
      checkShape(): never {
        throw new TransactionError("TRANSACTION_UNSUPPORTED_SHAPE", {
          inputs: 3,
          outputs: 7,
        });
      },
    }) as SppProofInputs;

    expect(() => assemble(proofInputs, [])).toThrow(
      expect.objectContaining({
        code: "CLIENT_TRANSACTION",
        details: { code: "TRANSACTION_UNSUPPORTED_SHAPE" },
        cause: {
          category: "transaction",
          code: "TRANSACTION_UNSUPPORTED_SHAPE",
          details: { inputs: 3, outputs: 7 },
        },
      }),
    );
  });

  it("preserves the hasher category at the hashing boundary", () => {
    expect(() => poseidon([])).toThrow(
      expect.objectContaining({
        code: "CLIENT_HASHER",
        details: { code: "InvalidNumFields" },
      }),
    );
    expect(hasherError("Poseidon", new Error("private preimage")).cause).toEqual({
      category: "hasher",
      code: "Poseidon",
    });
  });

  it("deeply copies and freezes details and recursively sanitizes causes", () => {
    const details = {
      attempts: 3,
      lastCause: { category: "indexer" } as { category: "indexer" | "rpc" },
    };
    const externalDetails = {
      public: { nested: ["kept"] },
      private: { nested: ["must not escape"] },
      nested: { seed: "must not escape", value: 4 },
    };
    const error = new ClientError("CLIENT_POLL_TIMED_OUT", {
      details,
      cause: { code: "REMOTE_FAILURE", message: "sensitive response body" },
    });
    const wrapped = fromClientCause(
      new KeypairError("KEYPAIR_INVALID_SECRET_KEY", externalDetails),
    );
    details.lastCause.category = "rpc";
    externalDetails.public.nested[0] = "changed";

    expect(error.details).toEqual({ attempts: 3, lastCause: { category: "indexer" } });
    expect(Object.isFrozen(error.details)).toBe(true);
    expect(Object.isFrozen(error.details?.lastCause)).toBe(true);
    expect(error.cause).toEqual({ category: "external", code: "REMOTE_FAILURE" });
    expect(Object.isFrozen(error.cause)).toBe(true);
    // `KeypairError` now keeps a closed set of primitive diagnostics, so a
    // nested object never reaches the client wrapper in the first place.
    expect(wrapped.cause).toEqual({
      category: "keypair",
      code: "KEYPAIR_INVALID_SECRET_KEY",
    });
    expect(JSON.stringify(error)).not.toContain("sensitive response body");
    expect(JSON.stringify(wrapped)).not.toContain("must not escape");
  });

  it("drops key material a keypair error carries, whatever shape it arrives in", () => {
    const material = "de".repeat(32);
    const carriers: Readonly<Record<string, KeypairError>> = {
      "under an unknown key": new KeypairError("KEYPAIR_INVALID_SECRET_KEY", {
        viewingKey: material,
      } as never),
      "as bytes under a known key": new KeypairError("KEYPAIR_INVALID_SECRET_KEY", {
        name: new Uint8Array(32).fill(0xde),
      } as never),
      "nested under a known key": new KeypairError("KEYPAIR_INVALID_SECRET_KEY", {
        name: { hex: material },
      } as never),
      // `encryption.ts` and `poseidon.ts` hand the underlying @noble rejection
      // to the wrapper, and that message can quote the bytes it rejected.
      "inside a dependency rejection": new KeypairError(
        "KEYPAIR_HKDF",
        undefined,
        new Error(`ikm=${material}`),
      ),
    };

    for (const [shape, carrier] of Object.entries(carriers)) {
      const wrapped = fromClientCause(carrier);
      expect([shape, wrapped.cause]).toEqual([shape, { category: "keypair", code: carrier.code }]);
      expect([shape, JSON.stringify(wrapped).includes(material)]).toEqual([shape, false]);
      expect([shape, Object.hasOwn(wrapped.cause ?? {}, "cause")]).toEqual([shape, false]);
    }
  });

  it("keeps a known detail key verbatim, so its value is the call site's responsibility", () => {
    const material = "de".repeat(32);
    const wrapped = fromClientCause(new KeypairError("KEYPAIR_INVALID_LENGTH", { name: material }));

    // Neither sanitizer can tell a label from a secret that is shaped like one:
    // `name` is a known key, so whatever it holds crosses intact. Nothing below
    // this line protects the value, which is why the next test reads the call
    // sites instead of the runtime.
    expect(wrapped.cause).toEqual({
      category: "keypair",
      code: "KEYPAIR_INVALID_LENGTH",
      details: { name: material },
    });
  });

  it("attaches only labels, bounds, and lengths at every keypair error call site", async () => {
    const sources = await keypairSources();
    const values = sources.flatMap(([file, source]) => detailValues(file, source));
    const labels = sources.flatMap(([file, source]) => checkedBytesLabels(file, source));

    // A rename that stopped either scan matching would pass vacuously.
    expect(values.length).toBeGreaterThan(20);
    expect(labels.length).toBeGreaterThan(20);

    expect(
      values.filter(
        ({ expression }) =>
          !AUDITED_DETAIL_PARAMETERS.has(expression) &&
          !SAFE_DETAIL_VALUES.some((form) => form.test(expression)),
      ),
    ).toEqual([]);
    expect(labels.filter(({ expression }) => !LABEL.test(expression))).toEqual([]);
  });

  it("rejects unknown codes and malformed code-specific details at runtime", () => {
    expect(() => new ClientError("CLIENT_NOT_REAL" as ClientErrorCode)).toThrow(TypeError);
    expect(
      () =>
        new ClientError("CLIENT_UNSIGNED_INPUT_UNAVAILABLE", {
          details: { index: "3" as unknown as number },
        }),
    ).toThrow(TypeError);
    expect(
      () =>
        new ClientError("CLIENT_NO_INPUTS", {
          details: { unexpected: true },
        } as never),
    ).toThrow(TypeError);
    for (const lastCause of [
      { category: "external", code: "REMOTE_FAILURE" },
      { category: "client", code: "CLIENT_NO_INPUTS" },
      { category: "indexer", code: "leaked" },
      { category: "external", code: 4 },
    ]) {
      expect(
        () =>
          new ClientError("CLIENT_POLL_TIMED_OUT", {
            details: { attempts: 1, lastCause: lastCause as never },
          }),
      ).toThrow(TypeError);
    }
    let getterCalls = 0;
    const accessor = Object.defineProperty({}, "index", {
      enumerable: true,
      get() {
        getterCalls++;
        return 1;
      },
    });
    expect(
      () =>
        new ClientError("CLIENT_UNSIGNED_INPUT_UNAVAILABLE", {
          details: accessor as { index: number },
        }),
    ).toThrow(TypeError);
    expect(getterCalls).toBe(0);
  });

  it("rejects an open canonical client code at compile time", () => {
    const code: ClientErrorCode = "CLIENT_NO_INPUTS";
    expect(code).toBe("CLIENT_NO_INPUTS");

    // @ts-expect-error Canonical client codes are a closed union.
    const invalid: ClientErrorCode = "CLIENT_NOT_A_RUST_VARIANT";
    expect(invalid).toBe("CLIENT_NOT_A_RUST_VARIANT");
  });

  it("derives the produced codes from the sources and dispositions the rest", async () => {
    const produced = await producedClientErrorCodes();
    const declared = new Set<string>([
      ...CANONICAL_CLIENT_ERROR_CODES,
      ...TYPESCRIPT_CLIENT_ERROR_CODES,
    ]);

    expect([...produced].filter((code) => !declared.has(code))).toEqual([]);
    expect(produced.size).toBeGreaterThan(TYPESCRIPT_CLIENT_ERROR_CODES.length);

    const dispositioned = [
      ...WRAPPED_IN_LOWER_LEVEL_ERROR,
      ...Object.keys(NARROWED_INTO_FINER_CODES),
      ...Object.keys(NO_TYPESCRIPT_PRODUCER),
    ];
    expect(new Set(dispositioned).size).toBe(dispositioned.length);

    const undispositioned = CANONICAL_CLIENT_ERROR_CODES.filter(
      (code) => !produced.has(code) && !dispositioned.includes(code),
    );
    expect(undispositioned).toEqual([]);

    // A code the SDK cannot reach at all must stay unreachable; a canonical code
    // split into finer TypeScript codes must keep at least one of them reachable.
    expect(Object.keys(NO_TYPESCRIPT_PRODUCER).filter((code) => produced.has(code))).toEqual([]);
    for (const [code, finer] of Object.entries(NARROWED_INTO_FINER_CODES)) {
      expect([code, finer.some((narrowed) => produced.has(narrowed))]).toEqual([code, true]);
    }
  });
});
