import { describe, expect, it } from "vitest";
import { address, getBase58Decoder, type Address, type Signature } from "@solana/kit";

import { encodeTransactInstructionData } from "../src/interface/codecs/index.js";
import {
  InstructionTag,
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
} from "../src/interface/program.js";
import type {
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes64,
  InterfaceTransfer,
} from "../src/interface/types.js";
import { SOL_MINT } from "../src/transaction/wallet/asset.js";
import { RingError } from "../src/ring/error.js";
import {
  CachedTransactionOrigin,
  confirmedInstructionGroups,
  confirmedRingWithdrawals,
  ringInvokedIn,
  RpcTransactionOrigin,
  type OriginInstructionGroup,
  type TransactionOrigin,
} from "../src/ring/origin.js";

// Mirrors custom-rings/client/tests/origin.rs.
const RING = address("zYYvj4LTBF4Lz2FBhDaAbJ7CsVWvHjyanxQJPmN2dSU");
const OTHER = address("ComputeBudget111111111111111111111111111111");
const POOL = SHIELDED_POOL_PROGRAM_ID;
const PAYER = address("11111111111111111111111111111112");
const SIGNATURE = "5".repeat(87) as Signature;

function group(
  outer: Address,
  inner: readonly (readonly [Address, number])[],
): OriginInstructionGroup {
  const empty = { accounts: [], data: new Uint8Array() };
  return {
    outer: { programId: outer, stackHeight: 1, ...empty },
    inner: inner.map(([programId, stackHeight]) => ({ programId, stackHeight, ...empty })),
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
      {
        outer: { programId: RING, stackHeight: 1, accounts: [], data: new Uint8Array() },
        inner: [{ programId: POOL, accounts: [], data: new Uint8Array() }],
      },
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
      {
        outer: { programId: RING, accounts: [PAYER], data: new Uint8Array() },
        inner: [{ programId: POOL, accounts: [OTHER], data: new Uint8Array(), stackHeight: 2 }],
      },
    ]);
    expect(ringInvokedIn(groups, RING)).toBe(true);
  });

  it("refuses a transaction without inner instructions", () => {
    const transaction = v0Transaction() as { meta: Record<string, unknown> };
    delete transaction.meta["innerInstructions"];
    expect(() => confirmedInstructionGroups(transaction)).toThrow(RingError);
  });
});

const RECIPIENT = address("So11111111111111111111111111111111111111112");
const DEPOSITOR = address("Vote111111111111111111111111111111111111111");
const MINT = address("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const SPL_INTERFACE = address("SysvarRent111111111111111111111111111111111");
const TOKEN_ACCOUNT = address("Stake11111111111111111111111111111111111111");
const TOKEN_PROGRAM = address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const SETTLEMENT_KEYS: readonly Address[] = [
  PAYER,
  RING,
  OTHER,
  POOL,
  SOL_INTERFACE,
  RECIPIENT,
  DEPOSITOR,
  SHIELDED_POOL_CPI_AUTHORITY,
  MINT,
  SPL_INTERFACE,
  TOKEN_ACCOUNT,
  TOKEN_PROGRAM,
];

const keyIndex = (account: Address) => SETTLEMENT_KEYS.indexOf(account);
const zeros = (length: number) => new Uint8Array(length);

/** A real `ring_transact` payload, so the tail is read against decoded transfers. */
function transactData(transfers: readonly InterfaceTransfer[]): string {
  const encoded = encodeTransactInstructionData({
    expiryUnixTs: 0n,
    privateTxHash: zeros(32) as Bytes32,
    circuit: { kind: "ringEddsa", inputs: 1, outputs: 2, publicAssetSlots: 1 },
    txViewingPk: zeros(33) as Bytes33,
    salt: zeros(16) as Bytes16,
    proof: { a: zeros(32) as Bytes32, b: zeros(64) as Bytes64, c: zeros(32) as Bytes32 },
    inputs: [
      { nullifierHash: zeros(32) as Bytes32, nullifierTreeRootIndex: 0, utxoTreeRootIndex: 0 },
    ],
    interfaceTransfers: transfers,
    outputs: [],
    messages: [],
  });
  return getBase58Decoder().decode(Uint8Array.from([InstructionTag.ringTransact, ...encoded]));
}

function poolInstruction(
  transfers: readonly InterfaceTransfer[],
  tail: readonly Address[],
  stackHeight = 2,
): unknown {
  return {
    programIdIndex: keyIndex(POOL),
    accounts: [keyIndex(PAYER), ...tail.map(keyIndex)],
    data: transactData(transfers),
    stackHeight,
  };
}

function callerInstruction(programId: Address, accounts: readonly Address[] = []): unknown {
  return { programIdIndex: keyIndex(programId), accounts: accounts.map(keyIndex), data: "" };
}

function settlementTransaction(outer: readonly unknown[], inner: readonly unknown[]): unknown {
  return {
    slot: 7,
    blockTime: null,
    transaction: {
      signatures: [SIGNATURE],
      message: {
        accountKeys: [...SETTLEMENT_KEYS],
        recentBlockhash: PAYER,
        instructions: outer,
        addressTableLookups: [],
      },
    },
    meta: {
      err: null,
      innerInstructions: inner.length === 0 ? [] : [{ index: 0, instructions: inner }],
    },
    version: 0,
  };
}

const SOL_LEG = { recipient: RECIPIENT, asset: SOL_MINT, amount: 7n };

describe("confirmedRingWithdrawals", () => {
  it("names the recipient of a SOL withdrawal", () => {
    const transaction = settlementTransaction(
      [callerInstruction(RING)],
      [poolInstruction([{ kind: "solWithdrawal", amount: 7n }], [SOL_INTERFACE, RECIPIENT])],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([SOL_LEG]);
  });

  it("leaves a SOL deposit out", () => {
    const transaction = settlementTransaction(
      [callerInstruction(RING)],
      [poolInstruction([{ kind: "solDeposit", amount: 7n }], [SOL_INTERFACE, DEPOSITOR])],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([]);
  });

  it("names the recipient when the same instruction also deposits", () => {
    const transaction = settlementTransaction(
      [callerInstruction(RING)],
      [
        poolInstruction(
          [
            { kind: "solDeposit", amount: 3n },
            { kind: "solWithdrawal", amount: 7n },
          ],
          [SOL_INTERFACE, DEPOSITOR, SOL_INTERFACE, RECIPIENT],
        ),
      ],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([SOL_LEG]);
  });

  it("follows the ring nested under another program", () => {
    const transaction = settlementTransaction(
      [callerInstruction(OTHER)],
      [
        { programIdIndex: keyIndex(RING), accounts: [], data: "", stackHeight: 2 },
        poolInstruction([{ kind: "solWithdrawal", amount: 7n }], [SOL_INTERFACE, RECIPIENT], 3),
      ],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([SOL_LEG]);
  });

  it("ignores an unrelated instruction that names the interface", () => {
    const transaction = settlementTransaction(
      [callerInstruction(OTHER, [SOL_INTERFACE, RECIPIENT])],
      [],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([]);
  });

  it("ignores a pool instruction another program invoked", () => {
    const transaction = settlementTransaction(
      [callerInstruction(OTHER)],
      [poolInstruction([{ kind: "solWithdrawal", amount: 7n }], [SOL_INTERFACE, RECIPIENT])],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([]);
  });

  it("names the token account and the mint of an SPL withdrawal", () => {
    const transaction = settlementTransaction(
      [callerInstruction(RING)],
      [
        poolInstruction(
          [{ kind: "splWithdrawal", amount: 9n, splInterfaceBump: 254 }],
          [SHIELDED_POOL_CPI_AUTHORITY, MINT, SPL_INTERFACE, TOKEN_ACCOUNT, TOKEN_PROGRAM],
        ),
      ],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([
      { recipient: TOKEN_ACCOUNT, asset: MINT, amount: 9n },
    ]);
  });

  it("refuses a settlement tail that does not match its transfers", () => {
    const transaction = settlementTransaction(
      [callerInstruction(RING)],
      [poolInstruction([{ kind: "solWithdrawal", amount: 7n }], [RECIPIENT, SOL_INTERFACE])],
    );
    expect(() => confirmedRingWithdrawals(transaction, RING)).toThrow(RingError);
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
