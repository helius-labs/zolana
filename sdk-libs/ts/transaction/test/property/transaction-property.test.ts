import type { Address, Bytes31, Bytes32 } from "@zolana/interface";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { OutputData, deriveBlinding } from "../../src/index.js";
import {
  decodeConfidential,
  decodeMerge,
  decodeProofless,
  encodeConfidential,
  encodeMerge,
  encodeProofless,
} from "../../src/serialization/index.js";

describe("transaction properties", () => {
  it("preserves bigint amounts and arbitrary canonical data", () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 0n, max: 0xffff_ffff_ffff_ffffn }),
        fc.uint8Array({ maxLength: 512 }),
        fc.uint8Array({ minLength: 31, maxLength: 31 }),
        (amount, memo, blinding) => {
          const value = {
            assetId: 1n,
            amount,
            blinding: blinding as Bytes31,
            data: new OutputData([{ kind: "memo" as const, bytes: memo }]),
          };
          const decoded = decodeConfidential(encodeConfidential(value));
          expect(decoded.amount).toBe(amount);
          expect(decoded.data.memo()).toEqual(memo);
        },
      ),
    );
  });

  it("round-trips fixed merge and variable proofless layouts", () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 0n, max: 0xffff_ffff_ffff_ffffn }),
        fc.uint8Array({ minLength: 31, maxLength: 31 }),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.option(fc.uint8Array({ maxLength: 128 }), { nil: undefined }),
        (amount, blinding, field, memo) => {
          const merge = {
            amount,
            assetField: field as Bytes32,
            blinding: blinding as Bytes31,
          };
          expect(decodeMerge(encodeMerge(merge))).toEqual(merge);

          const proofless = {
            owner: field as Bytes32,
            blinding: blinding as Bytes31,
            asset: "11111111111111111111111111111111" as Address,
            amount,
            ...(memo === undefined ? {} : { memo }),
          };
          expect(decodeProofless(encodeProofless(proofless))).toEqual(proofless);
        },
      ),
    );
  });

  it("derives stable, position-bound blindings", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 31, maxLength: 31 }),
        fc.integer({ min: 0, max: 254 }),
        (seed, position) => {
          const first = deriveBlinding(seed as Bytes31, position);
          expect(first).toEqual(deriveBlinding(seed as Bytes31, position));
          expect(first).not.toEqual(deriveBlinding(seed as Bytes31, position + 1));
        },
      ),
    );
  });
});
