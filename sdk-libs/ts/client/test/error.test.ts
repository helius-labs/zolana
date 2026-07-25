import { KeypairError } from "@zolana/keypair";
import { SppProofInputs, TransactionError } from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import fixtureJson from "../../fixtures/client/errors-v1.json" with { type: "json" };
import manifestJson from "../../fixtures/manifest.json" with { type: "json" };
import {
  CANONICAL_CLIENT_ERROR_CODES,
  ClientError,
  type ClientErrorCode,
} from "../src/index.js";
import { fromClientCause, hasherError } from "../src/error.js";
import { poseidon } from "../src/internal.js";
import { assemble } from "../src/prover/index.js";

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
  it("matches every Rust ClientError variant and structured field", () => {
    const vectors = errorVectors(fixtureJson);
    expect(manifestJson.frozenCommit).toBe("43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f");
    expect(manifestJson.canonicalSourceRevisions.client).toBe(
      "6d757791552874e1068cb527bc27875740c70362",
    );
    expect(manifestJson.files).toContainEqual({
      path: "client/errors-v1.json",
      sha256: "b0ab2fc759fcc0fbafb9556d0b7b7b387bee234ca2fe6bc029b1bf23622c115e",
    });
    expect(vectors).toHaveLength(58);
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
      cause: {
        category: "keypair",
        code: "KEYPAIR_INVALID_SECRET_KEY",
        details: { reason: "destroyed" },
      },
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
      cause: {
        category: "transaction",
        code: "TRANSACTION_INSUFFICIENT_BALANCE",
        details: { requested: "11", available: "10" },
      },
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
      lastCause: {
        category: "external" as const,
        code: "REMOTE_FAILURE",
      },
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
    details.lastCause.code = "CHANGED";
    externalDetails.public.nested[0] = "changed";

    expect(error.details).toEqual({
      attempts: 3,
      lastCause: { category: "external", code: "REMOTE_FAILURE" },
    });
    expect(Object.isFrozen(error.details)).toBe(true);
    expect(Object.isFrozen(error.details?.lastCause)).toBe(true);
    expect(error.cause).toEqual({ category: "external", code: "REMOTE_FAILURE" });
    expect(Object.isFrozen(error.cause)).toBe(true);
    expect(wrapped.cause).toMatchObject({
      details: { public: { nested: ["kept"] }, nested: { value: 4 } },
    });
    expect(Object.isFrozen((wrapped.cause as { details?: object }).details)).toBe(true);
    expect(JSON.stringify(error)).not.toContain("sensitive response body");
    expect(JSON.stringify(wrapped)).not.toContain("must not escape");
  });

  it("rejects unknown codes and malformed code-specific details at runtime", () => {
    expect(
      () => new ClientError("CLIENT_NOT_REAL" as ClientErrorCode),
    ).toThrow(TypeError);
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
    expect(
      () =>
        new ClientError("CLIENT_POLL_TIMED_OUT", {
          details: {
            attempts: 1,
            lastCause: { category: "external", code: 4 } as never,
          },
        }),
    ).toThrow(TypeError);
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

  it("records a producer disposition for every canonical code", () => {
    const direct = new Set<ClientErrorCode>([
      "CLIENT_KEYPAIR",
      "CLIENT_TRANSACTION",
      "CLIENT_HASHER",
      "CLIENT_FEE_PAYER_MISMATCH",
      "CLIENT_TREE_MISMATCH",
      "CLIENT_NO_INPUTS",
      "CLIENT_MISSING_P256_SIGNATURE",
      "CLIENT_MERGE_SIGNING_KEY_MISMATCH",
      "CLIENT_MERGE_NULLIFIER_KEY_MISMATCH",
      "CLIENT_MERGE_TREE_MISMATCH",
      "CLIENT_FIELD_TOO_LONG",
      "CLIENT_PROVER_SERVER",
      "CLIENT_PROOF_PARSE",
      "CLIENT_MISSING_INPUT_MERKLE_PROOF",
      "CLIENT_INCOMPLETE_INPUT_PROOFS",
      "CLIENT_STATE_PROOF_LEAF_MISMATCH",
      "CLIENT_STATE_PROOF_TREE_MISMATCH",
      "CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH",
      "CLIENT_NULLIFIER_PROOF_TREE_MISMATCH",
      "CLIENT_MISSING_OUTPUT",
      "CLIENT_INDEXER",
      "CLIENT_UNSUPPORTED_RPC_METHOD",
      "CLIENT_INDEXER_TIMEOUT",
      "CLIENT_INDEXER_NOT_CAUGHT_UP",
      "CLIENT_POLL_TIMED_OUT",
      "CLIENT_PROOF_PATH_LENGTH",
      "CLIENT_PROOF_INPUT_COUNT_MISMATCH",
    ]);
    const lowerLevelWrapped = new Set<ClientErrorCode>([
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
    ]);
    const structuredTransport = new Set<ClientErrorCode>([
      "CLIENT_SOLANA_TRANSACTION_SIGNING",
      "CLIENT_RPC",
    ]);
    const rustWorkflowBoundary = new Set<ClientErrorCode>([
      "CLIENT_ACCOUNT_NOT_FOUND",
      "CLIENT_DEPOSIT_SENDER_NOT_SIGNER",
    ]);
    const dispositions = [
      ...direct,
      ...lowerLevelWrapped,
      ...structuredTransport,
      ...rustWorkflowBoundary,
    ];

    expect(new Set(dispositions).size).toBe(dispositions.length);
    expect(dispositions.sort()).toEqual([...CANONICAL_CLIENT_ERROR_CODES].sort());
  });
});
