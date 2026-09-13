import { describe, expect, it } from "vitest";

import {
  FIXED_TRANSACT_ADDRESSES,
  MAX_TRANSACTION_ADDRESSES,
  SPP_SUPPORTED_SHAPES,
  ownerSignerSlots,
  signerWidth,
} from "../src/interface/shape.js";

describe("signerWidth", () => {
  it("reserves one payer slot plus one owner slot per input on every listed shape", () => {
    for (const shape of SPP_SUPPORTED_SHAPES) {
      expect(signerWidth(shape)).toBe(shape.inputs + 1);
    }
    expect(signerWidth({ inputs: 1, outputs: 1 })).toBe(2);
    expect(signerWidth({ inputs: 5, outputs: 4 })).toBe(6);
  });

  it("narrows the wide consolidation shape to the address budget", () => {
    expect(ownerSignerSlots(30)).toBe(30);
    expect(ownerSignerSlots(31)).toBe(29);
    expect(signerWidth({ inputs: 36, outputs: 2 })).toBe(25);
  });

  it("never exceeds the transaction address budget", () => {
    for (
      let inputs = 0;
      inputs <= MAX_TRANSACTION_ADDRESSES - FIXED_TRANSACT_ADDRESSES;
      inputs += 1
    ) {
      expect(ownerSignerSlots(inputs) + inputs + FIXED_TRANSACT_ADDRESSES).toBeLessThanOrEqual(
        MAX_TRANSACTION_ADDRESSES,
      );
    }
  });

  it("rejects a non-integer input count", () => {
    expect(() => ownerSignerSlots(1.5)).toThrow();
    expect(() => ownerSignerSlots(-1)).toThrow();
  });
});
