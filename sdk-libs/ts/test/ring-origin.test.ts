import { describe, expect, it } from "vitest";
import { address, type Address, type Signature } from "@solana/kit";

import { SHIELDED_POOL_PROGRAM_ID } from "../src/interface/program.js";
import { RingError } from "../src/ring/error.js";
import {
  CachedTransactionOrigin,
  confirmedInstructionGroups,
  ringInvokedIn,
  RpcTransactionOrigin,
  type OriginInstructionGroup,
  type TransactionOrigin,
} from "../src/ring/origin.js";

// Mirrors sdk-libs/ring-client/tests/origin.rs.
const RING = address("zYYvj4LTBF4Lz2FBhDaAbJ7CsVWvHjyanxQJPmN2dSU");
const OTHER = address("ComputeBudget111111111111111111111111111111");
const POOL = SHIELDED_POOL_PROGRAM_ID;
const PAYER = address("11111111111111111111111111111112");
const SIGNATURE = "5".repeat(87) as Signature;

function group(
  outer: Address,
  inner: readonly (readonly [Address, number])[],
): OriginInstructionGroup {
  return {
    outer: { programId: outer, stackHeight: 1 },
    inner: inner.map(([programId, stackHeight]) => ({ programId, stackHeight })),
  };
}

function origin(reason: "missing stack height" | "no parent", groups: OriginInstructionGroup[]) {
  let error: unknown;
  try {
    ringInvokedIn(groups, RING);
  } catch (cause) {
    error = cause;
  }
  expect(error).toBeInstanceOf(RingError);
  expect((error as RingError).code).toBe("RING_ORIGIN_STACK");
  expect((error as RingError).details?.["reason"]).toBe(reason);
}

describe("ringInvokedIn", () => {
  it("attributes the pool directly under the ring", () => {
    expect(
      ringInvokedIn(
        [
          group(RING, [
            [POOL, 2],
            [OTHER, 3],
          ]),
        ],
        RING,
      ),
    ).toBe(true);
  });

  it("does not attribute the pool at top level", () => {
    expect(ringInvokedIn([group(POOL, [[OTHER, 2]])], RING)).toBe(false);
  });

  it("does not attribute the pool under an intermediary", () => {
    expect(
      ringInvokedIn(
        [
          group(RING, [
            [OTHER, 2],
            [POOL, 3],
          ]),
        ],
        RING,
      ),
    ).toBe(false);
  });

  it("follows the ring nested under another program", () => {
    expect(
      ringInvokedIn(
        [
          group(OTHER, [
            [RING, 2],
            [POOL, 3],
            [OTHER, 2],
            [POOL, 3],
          ]),
        ],
        RING,
      ),
    ).toBe(true);
    expect(
      ringInvokedIn(
        [
          group(OTHER, [
            [RING, 2],
            [OTHER, 2],
            [POOL, 3],
          ]),
        ],
        RING,
      ),
    ).toBe(false);
  });

  it("rejects malformed stack heights", () => {
    origin("missing stack height", [
      { outer: { programId: RING, stackHeight: 1 }, inner: [{ programId: POOL }] },
    ]);
    origin("no parent", [group(RING, [[POOL, 4]])]);
    origin("no parent", [group(RING, [[POOL, 1]])]);
  });
});

function v0Transaction(): unknown {
  return {
    slot: 7,
    blockTime: null,
    transaction: {
      signatures: [SIGNATURE],
      message: {
        header: {
          numRequiredSignatures: 1,
          numReadonlySignedAccounts: 0,
          numReadonlyUnsignedAccounts: 1,
        },
        accountKeys: [PAYER, RING],
        recentBlockhash: PAYER,
        instructions: [{ programIdIndex: 1, accounts: [0], data: "", stackHeight: null }],
        addressTableLookups: [],
      },
    },
    meta: {
      err: null,
      status: { Ok: null },
      fee: 5000,
      preBalances: [1, 0],
      postBalances: [0, 0],
      innerInstructions: [
        {
          index: 0,
          instructions: [{ programIdIndex: 3, accounts: [2], data: "", stackHeight: 2 }],
        },
      ],
      loadedAddresses: { writable: [OTHER], readonly: [POOL] },
    },
    version: 0,
  };
}

describe("confirmedInstructionGroups", () => {
  it("resolves v0 program ids from loadedAddresses", () => {
    const groups = confirmedInstructionGroups(v0Transaction());
    expect(groups).toEqual([
      { outer: { programId: RING }, inner: [{ programId: POOL, stackHeight: 2 }] },
    ]);
    expect(ringInvokedIn(groups, RING)).toBe(true);
  });

  it("refuses a transaction without inner instructions", () => {
    const transaction = v0Transaction() as { meta: Record<string, unknown> };
    delete transaction.meta["innerInstructions"];
    expect(() => confirmedInstructionGroups(transaction)).toThrow(RingError);
  });
});

function rpcWith(result: unknown | Error): ConstructorParameters<typeof RpcTransactionOrigin>[0] {
  const getTransaction = () => ({
    send: () => (result instanceof Error ? Promise.reject(result) : Promise.resolve(result)),
  });
  return { getTransaction } as unknown as ConstructorParameters<typeof RpcTransactionOrigin>[0];
}

describe("RpcTransactionOrigin", () => {
  it("walks the fetched transaction", async () => {
    const origin = new RpcTransactionOrigin(rpcWith(v0Transaction()));
    await expect(origin.ringInvoked(SIGNATURE, RING)).resolves.toBe(true);
    await expect(origin.ringInvoked(SIGNATURE, OTHER)).resolves.toBe(false);
  });

  it("treats an unknown signature and an RPC failure as errors", async () => {
    for (const result of [null, new Error("rpc down")]) {
      const origin = new RpcTransactionOrigin(rpcWith(result));
      await expect(origin.ringInvoked(SIGNATURE, RING)).rejects.toMatchObject({
        code: "RING_ORIGIN_UNAVAILABLE",
      });
    }
  });
});

describe("CachedTransactionOrigin", () => {
  it("asks once per signature", async () => {
    let calls = 0;
    const inner: TransactionOrigin = {
      ringInvoked: () => {
        calls += 1;
        return Promise.resolve(true);
      },
    };
    const cached = new CachedTransactionOrigin(inner);
    await expect(cached.ringInvoked(SIGNATURE, RING)).resolves.toBe(true);
    await expect(cached.ringInvoked(SIGNATURE, RING)).resolves.toBe(true);
    expect(calls).toBe(1);
  });
});
