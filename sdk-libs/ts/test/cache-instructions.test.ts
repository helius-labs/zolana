import { AccountRole, address, type TransactionSigner } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { getCacheAddress } from "../src/addresses.js";
import {
  getCloseCacheInstruction,
  getCreateCacheInstructionAsync,
  getMergeTransactInstructionAsync,
} from "../src/instructions.js";
import { NO_CACHE_WRITES, validCacheAccess, validCacheWrites } from "../src/interface/cache.js";
import {
  encodeMergeTransactInstructionData,
  encodeTransactInstructionData,
  mergeExternalDataHash,
} from "../src/interface/codecs/index.js";
import {
  CACHE_ACCOUNT_SIZE,
  CACHE_CAPACITY,
  InstructionTag,
  StateDiscriminator,
  TransactCacheAccounts,
  bindCacheWrite,
  cachedInputFields,
  decodeCache,
  emptyCachedInputFields,
  ringTransactAccounts,
  transactInstruction,
} from "../src/interface/index.js";
import { ringTransactInstruction } from "../src/ring/instructions.js";
import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes128,
  CacheWrite,
  CircuitId,
  MergeTransactInstructionData,
  TransactInstructionData,
} from "../src/interface/types.js";

const PAYER = address("k7FaK87WHGVXzkaoHb7CdVPgkKDQhZ29VLDeBVbDfYn");
const TREE = address("2RJD1KnDRGEkvuFfAGrJ7PD28LRE9LRDjZznDywagzmr");
const OUTPUT_TREE = address("2VDW9dFE1ZXz4zWAbaBDQFynNVdRpQ73HyfSHMzBSL6Z");
const RING_AUTH = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const CACHE = address("4Ss5JMkXAD9Z7cktFEdrqeMuT6jGMF1pVozTyPHZ6zT4");
const OTHER_CACHE = address("7JYZmXDUtQ9S4pQjzhmGaoNdTCpcKq2mX3j4Q8CqLbJx");
const WRITER = address("6k78AbasGMFFrhG95Pj6jQbqkVt7FQMhVgemxJovWKR6");
const RENT_RECIPIENT = address("5bV6jUfhDHCQVA1WfKBUnXUsboJgoKgkzkKcxr3joew5");

function filled(value: number, length: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}

function field(seed: number): Bytes32 {
  const value = filled(seed, 32);
  value[0] = 0;
  return value as Bytes32;
}

function signer(account: Address): TransactionSigner {
  return {
    address: account,
    signTransactions: () => Promise.reject(new Error("not signing in this test")),
  };
}

function transactData(circuit: CircuitId): TransactInstructionData {
  return {
    expiryUnixTs: 0xffff_ffff_ffff_ffffn,
    privateTxHash: field(41),
    circuit,
    txViewingPk: filled(3, 33) as Bytes33,
    salt: filled(42, 16) as Bytes16,
    proof: {
      a: filled(43, 32) as Bytes32,
      b: filled(44, 128) as Bytes128,
      c: filled(45, 32) as Bytes32,
    },
    inputs: Array.from({ length: circuit.inputs }, (_, index) => ({
      nullifierHash: field(0x10 + index),
      treeIndex: 0,
    })),
    treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
    interfaceTransfers: [],
    outputs: [],
    messages: [],
  };
}

function writes(pairs: readonly (readonly [number, number])[]): readonly CacheWrite[] {
  return [
    ...pairs.map(([output, slot]) => ({ output, slot })),
    ...NO_CACHE_WRITES.slice(pairs.length),
  ];
}

function cachedCircuit(
  readBitmap: bigint,
  pairs: readonly (readonly [number, number])[] = [],
): CircuitId {
  return {
    kind: "confidentialEddsaCached",
    inputs: 2,
    outputs: 2,
    publicAssetSlots: 3,
    cacheAccess: { readBitmap, writeSlots: writes(pairs) },
  };
}

const UNCACHED: CircuitId = {
  kind: "confidentialEddsa",
  inputs: 2,
  outputs: 2,
  publicAssetSlots: 3,
};

function mergeData(cacheSlot?: number): MergeTransactInstructionData {
  return {
    expiryUnixTs: 42n,
    proof: {
      a: field(1),
      b: filled(2, 128) as Bytes128,
      c: field(3),
    },
    outputUtxoHash: field(9),
    eddsaOwner: true,
    privateTxHash: field(3),
    nullifiers: Array.from({ length: 8 }, (_, index) => field(index + 1)),
    utxoTreeRootIndex: 4,
    nullifierTreeRootIndex: 10,
    ...(cacheSlot === undefined ? {} : { cacheSlot }),
  };
}

function lastAccounts(accounts: readonly { address: Address; role: AccountRole }[], count: number) {
  return accounts.slice(-count).map((account) => [account.address, account.role]);
}

describe("cache access validation", () => {
  it.each([
    [0n, [], 2, 2, false],
    [1n, [], 2, 2, true],
    [
      0n,
      [
        [0, 0],
        [1, 2],
      ],
      2,
      2,
      true,
    ],
    [
      3n,
      [
        [0, 0],
        [1, 2],
      ],
      2,
      2,
      true,
    ],
    [
      4n,
      [
        [0, 0],
        [1, 2],
      ],
      2,
      2,
      true,
    ],
    [0b111n, [], 2, 2, false],
    [1n << 35n, [], 1, 1, true],
    [1n << 36n, [], 1, 1, false],
    [0n, [[0, 35]], 1, 1, true],
    [0n, [[0, 36]], 1, 1, false],
    [0n, [[1, 4]], 2, 2, true],
    [
      0n,
      [
        [1, 30],
        [0, 2],
      ],
      2,
      2,
      true,
    ],
    [
      0n,
      [
        [0, 3],
        [1, 3],
      ],
      2,
      2,
      false,
    ],
    [
      0n,
      [
        [0, 3],
        [0, 4],
      ],
      2,
      2,
      false,
    ],
    [0n, [[2, 3]], 2, 2, false],
    [1n, [], 64, 1, true],
  ] as const)(
    "reads %s and writes %j over %s inputs and %s outputs is %s, as Rust decides",
    (readBitmap, pairs, inputs, outputs, valid) => {
      expect(validCacheAccess({ readBitmap, writeSlots: writes(pairs) }, inputs, outputs)).toBe(
        valid,
      );
    },
  );

  it("mirrors Rust's write slot rules", () => {
    expect(validCacheWrites(NO_CACHE_WRITES, 1)).toBe(true);
    expect(validCacheWrites(writes([[0, 35]]), 1)).toBe(true);
    const gap = [...writes([[0, 1]])];
    gap[2] = { output: 1, slot: 2 };
    expect(validCacheWrites(gap, 2)).toBe(false);
    expect(validCacheWrites(writes([[0, 1]]).slice(0, 7), 2)).toBe(false);
    expect(validCacheWrites(writes([[-1, 1]]), 2)).toBe(false);
  });

  it("refuses to encode a cached selector the program would reject", () => {
    for (const circuit of [
      cachedCircuit(0n),
      cachedCircuit(0b111n),
      cachedCircuit(0n, [
        [0, 1],
        [1, 1],
      ]),
      cachedCircuit(1n << 64n),
    ]) {
      expect(() => encodeTransactInstructionData(transactData(circuit))).toThrow(
        expect.objectContaining({ code: "INTERFACE_INVALID_SHAPE" }),
      );
    }
  });

  it("encodes a cached selector as its tag, shape, read bitmap and write pairs", () => {
    const uncached = encodeTransactInstructionData(transactData(UNCACHED));
    const cached = encodeTransactInstructionData(
      transactData(
        cachedCircuit(0b10n, [
          [1, 7],
          [0, 8],
        ]),
      ),
    );
    expect(cached.length - uncached.length).toBe(24);
    const at = uncached.findIndex((_, index) => uncached[index] !== cached[index]);
    expect(Array.from(cached.slice(at, at + 2 + 3 + 24))).toEqual([
      4,
      0,
      2,
      2,
      3,
      2,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1,
      7,
      0,
      8,
      ...Array.from({ length: 12 }, () => 0xff),
    ]);
  });
});

describe("transact cache accounts", () => {
  it("appends a read-only cache after the settlement accounts for a read", async () => {
    const plain = await transactInstruction({
      payer: PAYER,
      inputTree: TREE,
      outputTree: OUTPUT_TREE,
      data: transactData(UNCACHED),
    });
    const read = await transactInstruction({
      payer: PAYER,
      inputTree: TREE,
      outputTree: OUTPUT_TREE,
      cache: TransactCacheAccounts.read(CACHE),
      data: transactData(cachedCircuit(1n)),
    });
    expect(read.accounts?.slice(0, -1)).toEqual(plain.accounts);
    expect(lastAccounts(read.accounts ?? [], 1)).toEqual([[CACHE, AccountRole.READONLY]]);
  });

  it("appends a writable cache and its signing writer for a write", async () => {
    const writer = signer(WRITER);
    const write = await transactInstruction({
      payer: PAYER,
      inputTree: TREE,
      outputTree: OUTPUT_TREE,
      cache: TransactCacheAccounts.write({ cache: CACHE, writer }),
      data: transactData(
        cachedCircuit(0n, [
          [0, 0],
          [1, 1],
        ]),
      ),
    });
    const accounts = write.accounts ?? [];
    expect(lastAccounts(accounts, 2)).toEqual([
      [CACHE, AccountRole.WRITABLE],
      [WRITER, AccountRole.READONLY_SIGNER],
    ]);
    expect(accounts.at(-1)).toMatchObject({ signer: writer });
  });

  it("appends the read cache, then the write cache and its writer, when both are used", async () => {
    const both = await transactInstruction({
      payer: PAYER,
      inputTree: TREE,
      outputTree: OUTPUT_TREE,
      cache: TransactCacheAccounts.readAndWrite(OTHER_CACHE, { cache: CACHE, writer: WRITER }),
      data: transactData(cachedCircuit(1n, [[1, 3]])),
    });
    expect(lastAccounts(both.accounts ?? [], 3)).toEqual([
      [OTHER_CACHE, AccountRole.READONLY],
      [CACHE, AccountRole.WRITABLE],
      [WRITER, AccountRole.READONLY_SIGNER],
    ]);
  });

  it.each([
    ["an uncached selector with a cache", UNCACHED, TransactCacheAccounts.read(CACHE)],
    ["a cached read without its cache", cachedCircuit(1n), undefined],
    [
      "a cached write with read-only accounts",
      cachedCircuit(0n, [[0, 0]]),
      TransactCacheAccounts.read(CACHE),
    ],
    [
      "a cached read with write accounts",
      cachedCircuit(1n),
      TransactCacheAccounts.write({ cache: CACHE, writer: WRITER }),
    ],
    [
      "a cached read and write without the read cache",
      cachedCircuit(1n, [[0, 0]]),
      TransactCacheAccounts.write({ cache: CACHE, writer: WRITER }),
    ],
  ] as const)("refuses %s", async (_name, circuit, cache) => {
    await expect(
      transactInstruction({
        payer: PAYER,
        inputTree: TREE,
        outputTree: OUTPUT_TREE,
        ...(cache === undefined ? {} : { cache }),
        data: transactData(circuit),
      }),
    ).rejects.toMatchObject({ code: "INTERFACE_INVALID_SHAPE" });
  });

  it("appends the cache after the ring transact settlement accounts", async () => {
    const data = transactData(UNCACHED);
    const accounts = await ringTransactAccounts({
      payer: PAYER,
      inputTrees: [TREE],
      outputTree: OUTPUT_TREE,
      ringAuth: RING_AUTH,
      inputs: data.inputs,
      treeContexts: data.treeContexts,
      cache: TransactCacheAccounts.write({ cache: CACHE, writer: WRITER }),
    });
    expect(lastAccounts(accounts, 2)).toEqual([
      [CACHE, AccountRole.WRITABLE],
      [WRITER, AccountRole.READONLY_SIGNER],
    ]);
  });

  it("refuses a cached circuit on the custom-ring transact, which the ring program rejects", async () => {
    await expect(
      ringTransactInstruction({
        ringProgramId: RING_AUTH,
        payer: PAYER,
        inputTrees: [TREE],
        outputTree: OUTPUT_TREE,
        proof: new Uint8Array(),
        data: transactData({
          kind: "ringEddsaCached",
          inputs: 2,
          outputs: 2,
          publicAssetSlots: 3,
          cacheAccess: { readBitmap: 1n, writeSlots: NO_CACHE_WRITES },
        }),
      }),
    ).rejects.toMatchObject({
      code: "RING_CACHE_UNSUPPORTED",
      details: { kind: "ringEddsaCached" },
    });
  });
});

describe("merge cache accounts", () => {
  it("appends a writable cache and its signing writer after the nullifier accounts", async () => {
    const plain = await getMergeTransactInstructionAsync({
      inputTree: TREE,
      outputTree: TREE,
      payer: PAYER,
      userRecord: OUTPUT_TREE,
      data: mergeData(),
    });
    const cached = await getMergeTransactInstructionAsync({
      inputTree: TREE,
      outputTree: TREE,
      payer: PAYER,
      userRecord: OUTPUT_TREE,
      cache: { cache: CACHE, writer: WRITER },
      data: mergeData(7),
    });
    expect(cached.accounts?.slice(0, -2)).toEqual(plain.accounts);
    expect(lastAccounts(cached.accounts ?? [], 2)).toEqual([
      [CACHE, AccountRole.WRITABLE],
      [WRITER, AccountRole.READONLY_SIGNER],
    ]);
    expect(cached.data).toHaveLength(1 + 528);
    expect(Array.from(cached.data?.slice(-2) ?? [])).toEqual([1, 7]);
    expect(plain.data?.at(-1)).toBe(0);
  });

  it.each([
    ["cache accounts without a slot", undefined, { cache: CACHE, writer: WRITER }],
    ["a slot without cache accounts", 3, undefined],
  ] as const)("refuses %s", async (_name, slot, cache) => {
    await expect(
      getMergeTransactInstructionAsync({
        inputTree: TREE,
        outputTree: TREE,
        payer: PAYER,
        userRecord: OUTPUT_TREE,
        ...(cache === undefined ? {} : { cache }),
        data: mergeData(slot),
      }),
    ).rejects.toMatchObject({ code: "INTERFACE_INVALID_SHAPE" });
  });

  it("refuses a slot the cache does not have", () => {
    expect(() => encodeMergeTransactInstructionData(mergeData(CACHE_CAPACITY))).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_INTEGER" }),
    );
    expect(encodeMergeTransactInstructionData(mergeData(CACHE_CAPACITY - 1)).at(-1)).toBe(35);
  });

  it("commits the external data hash to the cache address and slot", () => {
    const hash = (cache?: Readonly<{ address: Address; slot: number }>) =>
      Buffer.from(
        mergeExternalDataHash({
          instructionTag: InstructionTag.mergeTransact,
          expiryUnixTs: 42n,
          outputUtxoHash: field(7),
          ...(cache === undefined ? {} : { cache }),
        }),
      ).toString("hex");
    const hashes = [
      hash(),
      hash({ address: CACHE, slot: 0 }),
      hash({ address: CACHE, slot: 1 }),
      hash({ address: WRITER, slot: 0 }),
    ];
    expect(new Set(hashes).size).toBe(hashes.length);
  });
});

describe("cache instructions", () => {
  it("creates the cache at the sponsor's nonce address with the sponsor signing", async () => {
    const payer = signer(PAYER);
    const instruction = await getCreateCacheInstructionAsync({
      payer,
      data: { writeAuthority: WRITER, nonce: 3n, treeId: 0, expiresAt: -1n },
    });
    expect(instruction.data?.[0]).toBe(InstructionTag.createCache);
    expect(instruction.data).toHaveLength(51);
    expect(instruction.accounts?.map((account) => [account.address, account.role])).toEqual([
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [await getCacheAddress(PAYER, 3n), AccountRole.WRITABLE],
      [address("11111111111111111111111111111111"), AccountRole.READONLY],
    ]);
    expect(instruction.accounts?.[0]).toMatchObject({ signer: payer });
  });

  it.each([
    ["a nonce past u64", { nonce: 1n << 64n, treeId: 0, expiresAt: 0n }],
    ["a tree id past u16", { nonce: 0n, treeId: 0x1_0000, expiresAt: 0n }],
    ["an expiry past i64", { nonce: 0n, treeId: 0, expiresAt: 1n << 63n }],
  ] as const)("refuses %s", async (_name, data) => {
    await expect(
      getCreateCacheInstructionAsync({ payer: PAYER, data: { writeAuthority: WRITER, ...data } }),
    ).rejects.toMatchObject({ code: "INTERFACE_INVALID_INTEGER" });
  });

  it("closes a cache after expiry without a writer", () => {
    const instruction = getCloseCacheInstruction({ cache: CACHE, rentRecipient: RENT_RECIPIENT });
    expect(Array.from(instruction.data ?? [])).toEqual([InstructionTag.closeCache]);
    expect(instruction.accounts?.map((account) => [account.address, account.role])).toEqual([
      [CACHE, AccountRole.WRITABLE],
      [RENT_RECIPIENT, AccountRole.WRITABLE],
    ]);
  });
});

describe("cache account decoding", () => {
  function account(): Uint8Array {
    const data = new Uint8Array(CACHE_ACCOUNT_SIZE);
    data[0] = StateDiscriminator.cache;
    return data;
  }

  it("refuses an account of another size", () => {
    expect(() => decodeCache(account().slice(1))).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }),
    );
    expect(() => decodeCache(new Uint8Array(CACHE_ACCOUNT_SIZE + 1))).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }),
    );
  });

  it("refuses an account of another kind", () => {
    const data = account();
    data[0] = StateDiscriminator.ringConfig;
    expect(() => decodeCache(data)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_DISCRIMINATOR" }),
    );
  });

  it("reads a negative expiry and keeps every slot, empty ones as zero", () => {
    const data = account();
    data.fill(0xff, 4, 12);
    data.set(field(9), CACHE_ACCOUNT_SIZE - 32);
    const decoded = decodeCache(data);
    expect(decoded.expiresAt).toBe(-1n);
    expect(decoded.utxoHashes).toHaveLength(CACHE_CAPACITY);
    expect(decoded.utxoHashes[0]).toEqual(new Uint8Array(32));
    expect(decoded.utxoHashes.at(-1)).toEqual(field(9));
    data.fill(0);
    expect(decoded.utxoHashes.at(-1)).toEqual(field(9));
  });
});

function slots(filledSlots: readonly (readonly [number, Bytes32])[]): Uint8Array[] {
  const all: Uint8Array[] = Array.from({ length: CACHE_CAPACITY }, () => new Uint8Array(32));
  for (const [slot, hash] of filledSlots) all[slot] = hash;
  return all;
}

describe("cached input fields", () => {
  it("publishes the empty selection when no slot is read, whatever the tree", () => {
    expect(cachedInputFields(0n, 9, slots([[4, field(1)]]), 3)).toEqual(emptyCachedInputFields(3));
  });

  it("lists the read slots in slot order whatever the input count", () => {
    const [treeId, chain] = cachedInputFields(
      (1n << 30n) | (1n << 3n),
      5,
      slots([
        [30, field(2)],
        [3, field(1)],
      ]),
      2,
    );
    const [, direct] = cachedInputFields(
      0b11n,
      5,
      slots([
        [0, field(1)],
        [1, field(2)],
      ]),
      2,
    );
    expect(chain).toEqual(direct);
    expect(treeId.at(-1)).toBe(5);
  });

  it("refuses selections no cached spend can declare", () => {
    expect(() => cachedInputFields(1n, 0, [field(1)], 1)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_LENGTH" }),
    );
    expect(() => cachedInputFields(0b111n, 0, slots([]), 2)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_SHAPE" }),
    );
    expect(() => cachedInputFields(1n << 36n, 0, slots([]), 2)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_SHAPE" }),
    );
    expect(() => cachedInputFields(1n << 64n, 0, slots([]), 1)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_INTEGER" }),
    );
    expect(() => cachedInputFields(1n, 0x1_0000, slots([]), 1)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_INTEGER" }),
    );
    expect(() => cachedInputFields(1n, 0, slots([[0, filled(0xff, 32) as Bytes32]]), 2)).toThrow(
      expect.objectContaining({ code: "INTERFACE_HASH" }),
    );
    expect(() => emptyCachedInputFields(CACHE_CAPACITY + 1)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_INTEGER" }),
    );
  });

  it("refuses a write binding over a malformed hash or write list", () => {
    expect(() => bindCacheWrite(new Uint8Array(31))).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_LENGTH" }),
    );
    expect(() =>
      bindCacheWrite(field(1), { cache: CACHE, writeSlots: writes([[0, 1]]).slice(0, 7) }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_LENGTH" }));
    expect(() =>
      bindCacheWrite(field(1), { cache: CACHE, writeSlots: writes([[256, 1]]) }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_INTEGER" }));
  });
});
