import {
  encodeBase58,
  encodeBase64,
  InstructionTag,
  SHIELDED_POOL_PROGRAM_ID,
  type Address,
  type Bytes16,
  type Bytes32,
  type Bytes33,
  type Bytes64,
  type Signature,
  type TransactInstructionData,
} from "@zolana/interface";
import { transactInstructionDataCodec } from "@zolana/interface/codecs";
import { describe, expect, it } from "vitest";

import { createKitRpc, KitError, type KitConnection } from "../src/index.js";

const PAYER = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR" as Address;
const OWNER_ACCOUNT = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi" as Address;
const SIGNATURE = encodeBase58(new Uint8Array(64).fill(9)) as Signature;

type Call = Readonly<{
  args: readonly unknown[];
  config?: Readonly<{ abortSignal?: AbortSignal }>;
}>;

/**
 * Proxy stand-in for Kit's connection: each method returns a pending request,
 * and missing handlers fail instead of being skipped.
 */
function connection(handlers: Readonly<Record<string, (args: readonly unknown[]) => unknown>>): {
  rpc: KitConnection;
  calls: Call[];
} {
  const calls: Call[] = [];
  const rpc = new Proxy(
    {},
    {
      get(_target, method: string) {
        return (...args: readonly unknown[]) => ({
          send(config?: Readonly<{ abortSignal?: AbortSignal }>) {
            calls.push({ args, ...(config === undefined ? {} : { config }) });
            const handler = handlers[method];
            if (handler === undefined) throw new Error(`unexpected Kit call: ${method}`);
            return Promise.resolve(handler(args));
          },
        });
      },
    },
  ) as unknown as KitConnection;
  return { rpc, calls };
}

const CONFIRMED = {
  context: { slot: 1n },
  value: [{ slot: 1n, confirmations: null, confirmationStatus: "finalized", err: null }],
};

describe("chain reads", () => {
  it("unwraps the account envelope Kit returns", async () => {
    const { rpc } = connection({
      getAccountInfo: () => ({
        context: { slot: 1n },
        value: {
          data: [encodeBase64(Uint8Array.of(1, 2, 3)), "base64"],
          executable: false,
          lamports: 7n,
          owner: SHIELDED_POOL_PROGRAM_ID,
        },
      }),
    });
    await expect(createKitRpc(rpc).getAccount(PAYER)).resolves.toEqual({
      owner: SHIELDED_POOL_PROGRAM_ID,
      data: Uint8Array.of(1, 2, 3),
      lamports: 7n,
    });
  });

  it("reads a missing account as undefined rather than null", async () => {
    const { rpc } = connection({
      getAccountInfo: () => ({ context: { slot: 1n }, value: null }),
    });
    await expect(createKitRpc(rpc).getAccount(PAYER)).resolves.toBeUndefined();
  });

  it("refuses a getMultipleAccounts answer of the wrong length", async () => {
    const { rpc } = connection({
      getMultipleAccounts: () => ({ context: { slot: 1n }, value: [] }),
    });
    await expect(createKitRpc(rpc).getMultipleAccounts([PAYER])).rejects.toThrow(KitError);
  });

  it("takes the rent exemption and the slot straight, not out of an envelope", async () => {
    const { rpc, calls } = connection({ getMinimumBalanceForRentExemption: () => 890_880n });
    await expect(createKitRpc(rpc).getMinimumBalanceForRentExemption?.(165)).resolves.toBe(
      890_880n,
    );
    expect(calls[0]?.args[0]).toBe(165n);
  });

  it("passes a RequestContext signal through to Kit", async () => {
    const { rpc, calls } = connection({ getBalance: () => ({ context: { slot: 1n }, value: 1n }) });
    const controller = new AbortController();
    await createKitRpc(rpc).getBalance(PAYER, { signal: controller.signal });
    expect(calls[0]?.config?.abortSignal).toBe(controller.signal);
  });

  it("turns a timeout into a signal Kit understands", async () => {
    const { rpc, calls } = connection({ getBalance: () => ({ context: { slot: 1n }, value: 1n }) });
    await createKitRpc(rpc).getBalance(PAYER, { timeoutMs: 50 });
    expect(calls[0]?.config?.abortSignal).toBeInstanceOf(AbortSignal);
  });
});

describe("sending", () => {
  const messageBytes = new Uint8Array([
    1,
    0,
    1,
    2,
    ...new Uint8Array(64).fill(1),
    ...new Uint8Array(32).fill(2),
    0,
  ]);
  const transaction = Object.freeze({
    messageBytes,
    signatures: Object.freeze([encodeBase58(new Uint8Array(64).fill(3)) as Signature]),
  });

  it("sends base64 and returns the signature once it confirms", async () => {
    const { rpc, calls } = connection({
      sendTransaction: () => SIGNATURE,
      getSignatureStatuses: () => CONFIRMED,
    });
    await expect(createKitRpc(rpc).sendTransaction(transaction)).resolves.toBe(SIGNATURE);
    expect(calls[0]?.args[1]).toMatchObject({ encoding: "base64", skipPreflight: false });
  });

  it("defaults preflight to finalized only on the config path", async () => {
    const { rpc, calls } = connection({
      sendTransaction: () => SIGNATURE,
      getSignatureStatuses: () => CONFIRMED,
    });
    const kit = createKitRpc(rpc);
    await kit.sendTransaction(transaction);
    await kit.sendTransactionWithConfig?.(transaction, {});
    expect(calls[0]?.args[1]).toMatchObject({ preflightCommitment: "confirmed" });
    expect(calls[2]?.args[1]).toMatchObject({ preflightCommitment: "finalized" });
  });

  it("reports an unconfirmed transaction rather than waiting for ever", async () => {
    const { rpc } = connection({
      sendTransaction: () => SIGNATURE,
      getSignatureStatuses: () => ({ context: { slot: 1n }, value: [null] }),
    });
    await expect(
      createKitRpc(rpc, { confirmationTimeoutMs: 0 }).sendTransaction(transaction),
    ).rejects.toThrow(KitError);
  });

  it("rejects a confirmation timeout that is not a count of milliseconds", () => {
    const { rpc } = connection({});
    expect(() => createKitRpc(rpc, { confirmationTimeoutMs: -1 })).toThrow(KitError);
  });
});

function bytes(length: number, fill: number): Uint8Array {
  return new Uint8Array(length).fill(fill);
}

function transactData(): TransactInstructionData {
  return {
    proof: {
      rail: "eddsa",
      a: bytes(32, 1) as Bytes32,
      b: bytes(64, 2) as Bytes64,
      c: bytes(32, 3) as Bytes32,
    },
    expiryUnixTs: 42n,
    relayerFee: 0,
    privateTxHash: bytes(32, 4) as Bytes32,
    txViewingPk: bytes(33, 5) as Bytes33,
    salt: bytes(16, 6) as Bytes16,
    inputs: [
      {
        nullifierHash: bytes(32, 7) as Bytes32,
        nullifierTreeRootIndex: 0,
        utxoTreeRootIndex: 0,
        treeIndex: 0,
        eddsaSignerIndex: 0,
      },
    ],
    outputs: [
      {
        utxoHash: bytes(32, 12) as Bytes32,
        ownerTag: { kind: "inline", value: bytes(32, 13) as Bytes32 },
      },
      { utxoHash: bytes(32, 15) as Bytes32, ownerTag: { kind: "account", index: 1 } },
    ],
    messages: [],
  };
}

function confirmedTransaction(programIdIndex: number): unknown {
  const data = new Uint8Array([
    InstructionTag.transact,
    ...transactInstructionDataCodec.encode(transactData()),
  ]);
  return {
    meta: { innerInstructions: [], loadedAddresses: { readonly: [], writable: [] } },
    transaction: {
      message: {
        accountKeys: [PAYER, OWNER_ACCOUNT, SHIELDED_POOL_PROGRAM_ID],
        instructions: [{ accounts: [0, 1], data: encodeBase58(data), programIdIndex }],
      },
    },
  };
}

describe("transact output view tags", () => {
  it("reads the inline tag and resolves the account tag against the message", async () => {
    const { rpc } = connection({ getTransaction: () => confirmedTransaction(2) });
    const tags = await createKitRpc(rpc).transactOutputViewTags(SIGNATURE);
    expect(tags).toHaveLength(2);
    expect(tags).toContainEqual(new Uint8Array(32).fill(13));
  });

  it("scans inner instructions too, so a CPI into transact is found", async () => {
    const outer = confirmedTransaction(2) as {
      meta: { innerInstructions: unknown[] };
      transaction: { message: { instructions: unknown[] } };
    };
    const inner = outer.transaction.message.instructions[0];
    outer.transaction.message.instructions = [{ accounts: [], data: "", programIdIndex: 0 }];
    outer.meta.innerInstructions = [{ index: 0, instructions: [inner] }];
    const { rpc } = connection({ getTransaction: () => outer });
    await expect(createKitRpc(rpc).transactOutputViewTags(SIGNATURE)).resolves.toHaveLength(2);
  });

  it("says so when the transaction called no shielded-pool transact", async () => {
    const { rpc } = connection({ getTransaction: () => confirmedTransaction(0) });
    await expect(createKitRpc(rpc).transactOutputViewTags(SIGNATURE)).rejects.toThrow(KitError);
  });
});

describe("proof methods", () => {
  it("rejects the three an indexer answers", async () => {
    const { rpc } = connection({});
    const kit = createKitRpc(rpc);
    await expect(kit.getMerkleProofs(PAYER, [])).rejects.toThrow(KitError);
    await expect(kit.getNonInclusionProofs(PAYER, [])).rejects.toThrow(KitError);
    await expect(kit.getInputMerkleProofs([])).rejects.toThrow(KitError);
  });
});
