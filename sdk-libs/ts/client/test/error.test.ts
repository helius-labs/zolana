import { KeypairError } from "@zolana/keypair";
import { SppProofInputs, TransactionError } from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import fixtureJson from "../../fixtures/client/errors-v1.json" with { type: "json" };
import manifestJson from "../../fixtures/manifest.json" with { type: "json" };
import { CANONICAL_CLIENT_ERROR_CODES, ClientError, type ClientErrorCode } from "../src/index.js";
import { fromClientCause } from "../src/error.js";
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
    expect(manifestJson.files).toContainEqual({
      path: "client/errors-v1.json",
      sha256: "49acb09fb6205e33efa8209263e6f83698a48ec72ca59bf5d5ef784156874d1d",
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
      lastError: "transient",
    });
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
  });

  it("copies and freezes details and sanitizes external causes", () => {
    const details = { index: 3 };
    const error = new ClientError("CLIENT_UNSIGNED_INPUT_UNAVAILABLE", {
      details,
      cause: { code: "REMOTE_FAILURE", message: "sensitive response body" },
    });
    details.index = 4;

    expect(error.details).toEqual({ index: 3 });
    expect(Object.isFrozen(error.details)).toBe(true);
    expect(error.cause).toEqual({ category: "external", code: "REMOTE_FAILURE" });
    expect(Object.isFrozen(error.cause)).toBe(true);
    expect(JSON.stringify(error)).not.toContain("sensitive response body");
  });

  it("rejects an open canonical client code at compile time", () => {
    const code: ClientErrorCode = "CLIENT_NO_INPUTS";
    expect(code).toBe("CLIENT_NO_INPUTS");

    // @ts-expect-error Canonical client codes are a closed union.
    const invalid: ClientErrorCode = "CLIENT_NOT_A_RUST_VARIANT";
    expect(invalid).toBe("CLIENT_NOT_A_RUST_VARIANT");
  });
});
