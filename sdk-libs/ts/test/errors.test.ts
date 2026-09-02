import { describe, expect, it } from "vitest";

import { InterfaceError } from "../src/interface/index.js";
import { RingError, wrapRingError } from "../src/ring/error.js";
import { WalletError, wrapWalletError } from "../src/wallet/error.js";

describe("error envelope", () => {
  it("strips secret-named keys and byte buffers from details", () => {
    const error = new WalletError("WALLET_SYNC", {
      details: {
        field: "amount",
        count: 3,
        big: 7n,
        blindingSeed: "sensitive",
        bytes: Uint8Array.of(1, 2, 3),
      },
    });
    expect(error.details).toEqual({ field: "amount", count: 3, big: "7" });
  });

  it("keeps the cause reachable but out of serialization", () => {
    const cause = new Error("inner");
    const error = new RingError("RING_RPC", { cause });
    expect(error.cause).toBe(cause);
    expect(JSON.stringify(error)).not.toContain("inner");
    expect(JSON.parse(JSON.stringify(error))).toEqual({ name: "RingError", code: "RING_RPC" });
  });

  it("keeps the outer operation code and records the wrapped chain", () => {
    const inner = new WalletError("WALLET_INSUFFICIENT_BALANCE");
    const outer = wrapWalletError("WALLET_BUILD_TRANSFER", inner);
    expect(outer.code).toBe("WALLET_BUILD_TRANSFER");
    expect(outer.causeCode).toBe("WALLET_INSUFFICIENT_BALANCE");
    const doubled = wrapWalletError("WALLET_SYNC", outer);
    expect(doubled.causeCodes).toEqual(["WALLET_BUILD_TRANSFER", "WALLET_INSUFFICIENT_BALANCE"]);
  });

  it("returns a same-code wrap unchanged", () => {
    const inner = new RingError("RING_BUILD_TRANSFER");
    expect(wrapRingError("RING_BUILD_TRANSFER", inner)).toBe(inner);
  });

  it("sanitizes interface details and lifts the wrapped code", () => {
    const error = new InterfaceError(
      "INTERFACE_TRANSACTION_TOO_LARGE",
      { size: 1290, limit: 1232, signature: "leaky" },
      new WalletError("WALLET_SYNC"),
    );
    expect(error.details).toEqual({ size: 1290, limit: 1232 });
    expect(error.causeCode).toBe("WALLET_SYNC");
    expect(JSON.stringify(error)).not.toContain("WalletError");
  });
});
