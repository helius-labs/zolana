import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/indexer-schema-rejects-v1.json" with { type: "json" };
import { IndexerSchemaError, base64String, hash, limit } from "../../src/index.js";
import {
  getEncryptedUtxosByTagsMethod,
  getMerkleProofsMethod,
  getNonInclusionProofsMethod,
  getNullifierQueueElementsMethod,
  getShieldedTransactionsByTagsMethod,
} from "../../src/methods/index.js";

type Surface =
  | "base64String"
  | "hash"
  | "limit"
  | "ringsByTagsRequest"
  | "merkleProofsRequest"
  | "nonInclusionProofsRequest"
  | "nullifierQueueRequest"
  | "encryptedUtxosResponse"
  | "shieldedTransactionsResponse"
  | "merkleProofsResponse"
  | "nonInclusionProofsResponse"
  | "nullifierQueueResponse";

type Case = Readonly<{
  accepted: boolean;
  id: string;
  kind?: string;
  rustError?: string;
  surface: Surface;
  wire: unknown;
}>;

function invoke(surface: Surface, wire: unknown): unknown {
  switch (surface) {
    case "base64String":
      return base64String(wire as string);
    case "hash":
      return hash(wire as string);
    case "limit":
      return limit(BigInt(wire as number | string));
    case "ringsByTagsRequest":
      return getEncryptedUtxosByTagsMethod.decodeRequest(wire);
    case "merkleProofsRequest":
      return getMerkleProofsMethod.decodeRequest(wire);
    case "nonInclusionProofsRequest":
      return getNonInclusionProofsMethod.decodeRequest(wire);
    case "nullifierQueueRequest":
      return getNullifierQueueElementsMethod.decodeRequest(wire);
    case "encryptedUtxosResponse":
      return getEncryptedUtxosByTagsMethod.decodeResponse(wire);
    case "shieldedTransactionsResponse":
      return getShieldedTransactionsByTagsMethod.decodeResponse(wire);
    case "merkleProofsResponse":
      return getMerkleProofsMethod.decodeResponse(wire);
    case "nonInclusionProofsResponse":
      return getNonInclusionProofsMethod.decodeResponse(wire);
    case "nullifierQueueResponse":
      return getNullifierQueueElementsMethod.decodeResponse(wire);
    default: {
      const _exhaustive: never = surface;
      throw new Error(`unknown surface ${String(_exhaustive)}`);
    }
  }
}

function typescriptAccepted(surface: Surface, wire: unknown): boolean {
  try {
    invoke(surface, wire);
    return true;
  } catch (error) {
    if (error instanceof IndexerSchemaError) return false;
    throw error;
  }
}

describe("indexer schema rejects (Rust-generated)", () => {
  it("pins the generator identity", () => {
    expect(fixture.id).toBe("indexer-schema-rejects-v1");
    expect(fixture.rustPath).toBe("sdk-libs/indexer-api/src/lib.rs");
  });

  for (const testCase of fixture.accepts as Case[]) {
    it(`accepts ${testCase.id}`, () => {
      expect(testCase.accepted).toBe(true);
      expect(typescriptAccepted(testCase.surface, testCase.wire)).toBe(true);
    });
  }

  for (const testCase of [
    ...(fixture.scalars as Case[]),
    ...(fixture.rejects as Case[]),
    ...(fixture.tampers as Case[]),
  ]) {
    it(`rejects ${testCase.id} (${testCase.kind ?? "reject"})`, () => {
      expect(testCase.accepted).toBe(false);
      const accepted = typescriptAccepted(testCase.surface, testCase.wire);
      // A mismatch here is the finding this suite exists to surface: TypeScript
      // and Rust disagree on the accept/reject decision for the same wire.
      expect(accepted).toBe(false);
    });
  }
});
