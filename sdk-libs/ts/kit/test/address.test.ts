import type { Address } from "@zolana/interface";
import { describe, expect, it } from "vitest";

import { fromKitAddress, KitError, toKitAddress } from "../src/index.js";

const SYSTEM_PROGRAM = "11111111111111111111111111111111" as Address;
const SHIELDED_POOL = "sppzgEd25DF4PC1FgNerLWVZndUAV82LV9Dy5yCvRVA" as Address;

describe("address conversion", () => {
  it("round-trips a Solana address through Kit and back", () => {
    for (const address of [SYSTEM_PROGRAM, SHIELDED_POOL]) {
      expect(fromKitAddress(toKitAddress(address))).toBe(address);
    }
  });

  it("rejects what Zolana's cast lets through", () => {
    // These values typecheck as Zolana `Address` because the brand is a cast,
    // not a validating constructor.
    for (const value of ["", "not base58 0OIl", "11111111111111111111111111111", "x".repeat(64)]) {
      expect(() => toKitAddress(value as Address)).toThrow(KitError);
    }
  });

  it("rejects a Kit address asserted onto untrusted input", () => {
    expect(() => fromKitAddress("" as ReturnType<typeof toKitAddress>)).toThrow(KitError);
    expect(() => fromKitAddress("0OIl" as ReturnType<typeof toKitAddress>)).toThrow(KitError);
  });

  it("reports the failure with a code rather than a bare Error", () => {
    try {
      toKitAddress("" as Address);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(KitError);
      expect((error as KitError).code).toBe("KIT_INVALID_ADDRESS");
    }
  });
});
