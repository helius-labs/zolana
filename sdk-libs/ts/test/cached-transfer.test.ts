import { address, type Address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { ClientError, LocalKeys, ZolanaClient } from "../src/client/index.js";
import { bytesField, bytesToBigInt } from "../src/client/internal.js";
import { assemble, transferPublicInputHash } from "../src/client/prover/assembly.js";
import { assembleMergeWithProofs } from "../src/client/prover/merge.js";
import type { TransferInputs } from "../src/client/prover/types.js";
import type { NonInclusionProof, SpendProof } from "../src/client/rpc.js";
import { proofFor } from "./helpers/proofs.js";
import {
  CACHE_CAPACITY,
  NO_CACHE_WRITES,
  NO_UTXO_ROOT,
  bindCacheWrite,
  cachedInputFields,
  emptyCachedInputFields,
} from "../src/interface/index.js";
import {
  encodeMergeTransactInstructionData,
  mergeExternalDataHash,
} from "../src/interface/codecs/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { InstructionTag } from "../src/interface/program.js";
import { inputTreeSlots } from "../src/interface/tree-slot.js";
import type { Bytes16, Bytes32, Bytes128 } from "../src/interface/types.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import {
  Merge,
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  TransactionError,
  Utxo,
  createExternalData,
  createProofOutput,
  outputBlindingSeed,
  transactOutputBlinding,
  type ProofOutputUtxo,
} from "../src/transaction/index.js";

const TREE_ID = 0;
const TREE = treeAddress(TREE_ID);
const CACHE = address("4Ss5JMkXAD9Z7cktFEdrqeMuT6jGMF1pVozTyPHZ6zT4");
const OTHER_CACHE = address("7JYZmXDUtQ9S4pQjzhmGaoNdTCpcKq2mX3j4Q8CqLbJx");
const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const STATE_ROOT_INDEX = 4;
const NULLIFIER_ROOT_INDEX = 7;
function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function blindingSeed(value: number): Bytes32 {
  const seed = bytes(value);
  seed[0] = 0;
  return seed;
}

function nonInclusionProof(leaf: Bytes32, tree: Address = TREE): NonInclusionProof {
  return {
    leaf,
    merkleContext: { treeType: 1, tree },
    path: Array.from({ length: 40 }, () => bytes(0)),
    lowElement: bytes(4),
    lowElementIndex: 0n,
    highElement: bytes(5),
    highElementIndex: 1n,
    root: bytes(6),
    rootSeq: 1n,
    rootIndex: NULLIFIER_ROOT_INDEX,
  };
}

function spendProof(input: ProofInputUtxo): SpendProof {
  return {
    state: {
      leaf: input.hash(),
      merkleContext: { treeType: 0, tree: TREE },
      path: Array.from({ length: 32 }, () => bytes(2)),
      leafIndex: 3n,
      root: bytes(3),
      rootSeq: 1n,
      rootIndex: STATE_ROOT_INDEX,
    },
    nullifier: nonInclusionProof(input.nullifier()),
  };
}

type Fixture = Readonly<{
  keypair: ShieldedKeypair;
  proofInputs: SppProofInputs;
  inputs: readonly ProofInputUtxo[];
}>;

function fixture(
  options: Readonly<{
    realInputs?: number;
    dummyInputs?: number;
    inputTreeIds?: readonly number[];
    ownedOutputs?: number;
  }> = {},
): Fixture {
  const keypair = ShieldedKeypair.generate();
  const real = Array.from({ length: options.realInputs ?? 1 }, (_, index) =>
    ProofInputUtxo.fromKeypair(
      new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 7n,
        blinding: bytes(1 + index),
      }),
      keypair,
      {},
      options.inputTreeIds?.[index] ?? TREE_ID,
    ),
  );
  const inputs = [
    ...real,
    ...Array.from({ length: options.dummyInputs ?? 0 }, (_, index) =>
      ProofInputUtxo.dummy(bytes(10 + index)),
    ),
  ];
  const seed = blindingSeed(9);
  const firstNullifier = inputs[0]?.nullifier() ?? bytes(0);
  const outputSeed = outputBlindingSeed(firstNullifier, seed);
  const ownerTag = bytes(8);
  const owned = options.ownedOutputs ?? 1;
  const outputs = [0, 1].map((index) =>
    createProofOutput({
      ...(index < owned ? { ownerAddress: keypair.shieldedAddress() } : { ownerTag }),
      asset: SOL_MINT,
      amount: index === 0 ? 7n * BigInt(real.length) : 0n,
      blinding: transactOutputBlinding(firstNullifier, outputSeed, index),
    }),
  );
  const proofInputs = new SppProofInputs({
    payer: keypair.shieldedAddress().solanaAddress(),
    inputUtxos: inputs,
    outputs,
    externalData: createExternalData({
      txViewingPublicKey: keypair.viewingPublicKey(),
      salt: new Uint8Array(16) as Bytes16,
      outputs: outputs.map((entry) => ({
        utxoHash: entry.hash(TREE_ID),
        ownerTag: { kind: "inline", value: ownerTag },
      })),
      resolvedOwnerTags: outputs.map(() => ownerTag),
      messages: [],
    }),
    blindingSeed: seed,
    outputTreeId: TREE_ID,
  });
  return { keypair, proofInputs, inputs };
}

type CacheSpec = Readonly<{
  reads?: readonly (number | undefined)[];
  writes?: readonly (number | undefined)[];
  read?: Address;
  write?: Address;
  outputs?: (outputs: readonly ProofOutputUtxo[]) => readonly ProofOutputUtxo[];
}>;

function withCache(proofInputs: SppProofInputs, spec: CacheSpec): SppProofInputs {
  const outputs = proofInputs.outputs.map((entry, index) => {
    const slot = spec.writes?.[index];
    return slot === undefined ? entry : entry.withCacheSlot(slot);
  });
  const rebuilt = new SppProofInputs({
    payer: proofInputs.payer,
    inputUtxos: proofInputs.inputUtxos.map((entry, index) => {
      const slot = spec.reads?.[index];
      return slot === undefined ? entry : entry.withCacheSlot(slot);
    }),
    outputs: spec.outputs === undefined ? outputs : spec.outputs(outputs),
    externalData: proofInputs.externalData,
    blindingSeed: proofInputs.blindingSeed,
    outputTreeId: proofInputs.outputTreeId,
  });
  const reading = spec.read === undefined ? rebuilt : rebuilt.withReadCache(spec.read);
  return spec.write === undefined ? reading : reading.withWriteCache(spec.write);
}

function writeSlots(pairs: readonly (readonly [number, number])[]) {
  return [
    ...pairs.map(([output, slot]) => ({ output, slot })),
    ...NO_CACHE_WRITES.slice(pairs.length),
  ];
}

function cacheSlots(filledSlots: readonly (readonly [number, Uint8Array])[]): Uint8Array[] {
  const all: Uint8Array[] = Array.from({ length: CACHE_CAPACITY }, () => new Uint8Array(32));
  for (const [slot, hash] of filledSlots) all[slot] = hash;
  return all;
}

function input(value: Fixture, index: number): ProofInputUtxo {
  const selected = value.inputs[index];
  if (selected === undefined) throw new Error(`fixture has no input ${String(index)}`);
  return selected;
}

function fields(value: readonly Uint8Array[]): readonly bigint[] {
  return value.map(bytesToBigInt);
}

function recomputedPublicInputHash(payload: TransferInputs, utxoRoot: Bytes32): bigint {
  return transferPublicInputHash({
    nullifiers: payload.inputs.map((entry) => entry.nullifier),
    outputHashes: payload.outputs.map((entry) => entry.hash),
    treeSlots: inputTreeSlots([{ id: TREE_ID, utxoRoot, nullifierRoot: bytes(6) }]),
    outputTreeId: TREE_ID,
    privateTxHash: payload.privateTxHash,
    externalDataHash: payload.externalDataHash,
    publicSlots: payload.publicAssets.flatMap((asset, index) => [
      asset,
      payload.publicAmounts[index] ?? 0n,
    ]),
    ringProgramId: payload.ringProgramId,
    signerPublicKeyHashes: payload.signerPublicKeyHashes,
    inputFlags: payload.inputFlags,
    publishedOutputOwnerPublicKeyHashes: payload.publishedOutputOwnerPublicKeyHashes,
    cacheTreeId: payload.cacheTreeId,
    cacheReadHashChain: payload.cacheReadHashChain,
    cacheReadHashes: payload.cacheReadHashes,
    cacheIsCached: payload.cacheIsCached,
    cacheReadIndex: payload.cacheReadIndex,
  });
}

function rejects(run: () => unknown, code: ClientError["code"]): unknown {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(ClientError);
    const clientError = error as ClientError;
    expect(clientError.code).toBe(code);
    return clientError.details;
  }
  throw new Error(`expected ${code}`);
}

function transactionRejects(run: () => unknown, code: TransactionError["code"]): unknown {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(TransactionError);
    const transactionError = error as TransactionError;
    expect(transactionError.code).toBe(code);
    return transactionError.details;
  }
  throw new Error(`expected ${code}`);
}

describe("a UTXO named for a cache slot", () => {
  it("keeps the commitment and nullifier of the input it reads", () => {
    const spent = input(fixture(), 0);
    const cached = spent.withCacheSlot(35);
    expect(cached.cacheSlot).toBe(35);
    expect(spent.cacheSlot).toBeUndefined();
    expect(cached.hash()).toEqual(spent.hash());
    expect(cached.nullifier()).toEqual(spent.nullifier());
  });

  it.each([36, -1, 1.5])("refuses slot %s on an input and an output", (slot) => {
    const value = fixture();
    expect(
      transactionRejects(
        () => input(value, 0).withCacheSlot(slot),
        "TRANSACTION_CACHE_SLOT_OUT_OF_RANGE",
      ),
    ).toEqual({ slot });
    const output = value.proofInputs.outputs[0];
    expect(output).toBeDefined();
    expect(
      transactionRejects(() => output?.withCacheSlot(slot), "TRANSACTION_CACHE_SLOT_OUT_OF_RANGE"),
    ).toEqual({ slot });
  });

  it("refuses padding on either side", () => {
    transactionRejects(
      () => ProofInputUtxo.dummy(bytes(1)).withCacheSlot(0),
      "TRANSACTION_CACHED_DUMMY_INPUT",
    );
    const padding = fixture().proofInputs.outputs[1];
    expect(padding?.isDummy()).toBe(true);
    transactionRejects(() => padding?.withCacheSlot(0), "TRANSACTION_CACHED_DUMMY_OUTPUT");
  });

  it("keeps the commitment of the output it writes", () => {
    const output = fixture().proofInputs.outputs[0];
    const written = output?.withCacheSlot(3);
    expect(written?.cacheSlot).toBe(3);
    expect(written?.hash(TREE_ID)).toEqual(output?.hash(TREE_ID));
  });

  it("leaves cached inputs out of the Merkle path request and in the non-inclusion one", () => {
    const value = fixture({ realInputs: 2 });
    const [first, second] = [input(value, 0), input(value, 1)];
    const proofInputs = withCache(value.proofInputs, {
      reads: [undefined, 4],
      read: CACHE,
    }).withWriteCache(OTHER_CACHE);
    expect(proofInputs.cacheAccounts).toEqual({ read: CACHE, write: OTHER_CACHE });
    expect(proofInputs.inputUtxoHashes()).toEqual([first.hash()]);
    expect(proofInputs.inputContexts().map((entry) => entry.utxoHash)).toEqual([first.hash()]);
    expect(proofInputs.dummyNullifiers()).toEqual([second.nullifier()]);
    expect(value.proofInputs.dummyNullifiers()).toEqual([]);
  });
});

describe("a transfer reading its input from a cache", () => {
  it("proves the input against the slot it names and publishes no state root", () => {
    const value = fixture();
    const spent = input(value, 0);
    const assembled = assemble(
      withCache(value.proofInputs, { reads: [5], read: CACHE }),
      [],
      [nonInclusionProof(spent.nullifier())],
    );
    const { payload } = assembled.proverInputs;

    expect(assembled.instructionData.circuit).toEqual({
      kind: "confidentialEddsaCached",
      inputs: 1,
      outputs: 2,
      publicAssetSlots: 3,
      cacheAccess: { readBitmap: 1n << 5n, writeSlots: NO_CACHE_WRITES },
    });
    expect(assembled.instructionData.treeContexts).toEqual([
      { utxoTreeRootIndex: NO_UTXO_ROOT, nullifierTreeRootIndex: NULLIFIER_ROOT_INDEX },
    ]);
    expect(payload.treeSlots[0]?.utxoRoot).toBe(0n);
    expect(payload.inputs[0]?.statePathElements.every((element) => element === 0n)).toBe(true);
    expect([payload.cacheTreeId, payload.cacheReadHashChain]).toEqual(
      fields(cachedInputFields(1n << 5n, TREE_ID, cacheSlots([[5, spent.hash()]]), 1)),
    );
    expect(payload.cacheReadHashes).toEqual([bytesToBigInt(spent.hash())]);
    expect(payload.cacheIsCached).toEqual([1n]);
    expect(payload.cacheReadIndex).toEqual([0n]);
    expect(payload.publicInputHash).toBe(recomputedPublicInputHash(payload, bytes(0)));
  });

  it("differs from the uncached proof of the same spend only in the cache selection", () => {
    const value = fixture({ realInputs: 2 });
    const [first, second] = [input(value, 0), input(value, 1)];
    const proof = spendProof(second);
    const cached = assemble(
      withCache(value.proofInputs, { reads: [undefined, 0], read: CACHE }),
      [spendProof(first)],
      [nonInclusionProof(second.nullifier())],
    ).proverInputs.payload;
    const uncached = assemble(value.proofInputs, [
      spendProof(first),
      {
        ...proof,
        state: {
          ...proof.state,
          path: Array.from({ length: 32 }, () => bytes(0)),
          leafIndex: 0n,
        },
      },
    ]).proverInputs.payload;

    const strip = ({
      cacheTreeId: _tree,
      cacheReadHashChain: _chain,
      cacheReadHashes: _hashes,
      cacheIsCached: _cached,
      cacheReadIndex: _index,
      publicInputHash: _hash,
      ...rest
    }: TransferInputs) => rest;
    expect(strip(cached)).toEqual(strip(uncached));
    expect([uncached.cacheTreeId, uncached.cacheReadHashChain]).toEqual(
      fields(emptyCachedInputFields(2)),
    );
    expect(uncached.cacheReadHashes).toEqual([]);
    expect(cached.publicInputHash).not.toBe(uncached.publicInputHash);
  });

  it.each([
    ["after", [undefined, 30]],
    ["before", [30, undefined]],
  ] as const)(
    "proves a cached input %s an input proven by path against the path's state root",
    (_name, reads) => {
      const value = fixture({ realInputs: 2 });
      const [first, second] = [input(value, 0), input(value, 1)];
      const [proven, cached] = reads[0] === undefined ? [first, second] : [second, first];
      const assembled = assemble(
        withCache(value.proofInputs, { reads, read: CACHE }),
        [spendProof(proven)],
        [nonInclusionProof(cached.nullifier())],
      );
      const { payload } = assembled.proverInputs;
      const cachedIndex = reads[0] === undefined ? 1 : 0;

      expect(assembled.instructionData.treeContexts).toEqual([
        { utxoTreeRootIndex: STATE_ROOT_INDEX, nullifierTreeRootIndex: NULLIFIER_ROOT_INDEX },
      ]);
      expect(payload.treeSlots[0]?.utxoRoot).toBe(bytesField(bytes(3), "root"));
      expect(payload.inputs[1 - cachedIndex]?.statePathElements[0]).toBe(
        bytesField(bytes(2), "path"),
      );
      expect(
        payload.inputs[cachedIndex]?.statePathElements.every((element) => element === 0n),
      ).toBe(true);
      expect(payload.cacheReadHashChain).toBe(
        bytesToBigInt(
          cachedInputFields(1n << 30n, TREE_ID, cacheSlots([[30, cached.hash()]]), 2)[1],
        ),
      );
      expect(payload.cacheIsCached).toEqual(reads.map((slot) => (slot === undefined ? 0n : 1n)));
      expect(payload.cacheReadIndex).toEqual([0n, 0n]);
      expect(payload.publicInputHash).toBe(recomputedPublicInputHash(payload, bytes(3)));
    },
  );

  it("lists two reads in slot order whatever the order of their inputs", () => {
    const value = fixture({ realInputs: 2 });
    const [first, second] = [input(value, 0), input(value, 1)];
    const { payload } = assemble(
      withCache(value.proofInputs, { reads: [9, 2], read: CACHE }),
      [],
      [nonInclusionProof(first.nullifier()), nonInclusionProof(second.nullifier())],
    ).proverInputs;
    expect(payload.cacheReadHashes).toEqual([
      bytesToBigInt(second.hash()),
      bytesToBigInt(first.hash()),
    ]);
    expect(payload.cacheReadIndex).toEqual([1n, 0n]);
    expect(payload.cacheIsCached).toEqual([1n, 1n]);
  });

  it("takes the next padding non-inclusion proof for each cached input, in slot order", () => {
    const value = fixture({ realInputs: 1, dummyInputs: 1 });
    const [spent, padding] = [input(value, 0), input(value, 1)];
    const proofInputs = withCache(value.proofInputs, { reads: [3], read: CACHE });
    const assembled = assemble(
      proofInputs,
      [],
      [nonInclusionProof(spent.nullifier()), nonInclusionProof(padding.nullifier())],
    );
    expect(assembled.instructionData.treeContexts[0]?.utxoTreeRootIndex).toBe(NO_UTXO_ROOT);
    rejects(
      () =>
        assemble(
          proofInputs,
          [],
          [nonInclusionProof(padding.nullifier()), nonInclusionProof(spent.nullifier())],
        ),
      "CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH",
    );
  });

  it("selects the ring twin of the rail on a ring transfer", () => {
    const value = fixture();
    const assembled = assemble(
      withCache(value.proofInputs, { reads: [0], read: CACHE }),
      [],
      [nonInclusionProof(input(value, 0).nullifier())],
      { kind: "ring", ring: RING },
    );
    expect(assembled.instructionData.circuit.kind).toBe("ringEddsaCached");
    expect(assembled.proverInputs.circuit).toBe("transferRing");
  });
});

describe("a transfer writing its outputs to a cache", () => {
  it.each([
    [
      "every output",
      [3, 4],
      [
        [0, 3],
        [1, 4],
      ],
    ],
    ["a non-first output alone", [undefined, 20], [[1, 20]]],
    [
      "outputs to descending slots",
      [4, 3],
      [
        [0, 4],
        [1, 3],
      ],
    ],
  ] as const)("binds the external data hash to the cache for %s", (_name, writes, pairs) => {
    const value = fixture({ ownedOutputs: 2 });
    const spent = input(value, 0);
    const cached = assemble(withCache(value.proofInputs, { writes, write: CACHE }), [
      spendProof(spent),
    ]);
    const uncached = assemble(value.proofInputs, [spendProof(spent)]);
    const payload = cached.proverInputs.payload;

    expect(cached.instructionData.circuit).toMatchObject({
      kind: "confidentialEddsaCached",
      cacheAccess: { readBitmap: 0n, writeSlots: writeSlots(pairs) },
    });
    expect(payload.externalDataHash).toBe(
      bytesField(
        bindCacheWrite(value.proofInputs.externalData.hash(), {
          cache: CACHE,
          writeSlots: writeSlots(pairs),
        }),
        "external data hash",
      ),
    );
    expect(payload.privateTxHash).not.toBe(uncached.proverInputs.payload.privateTxHash);
    expect([payload.cacheTreeId, payload.cacheReadHashChain]).toEqual(
      fields(emptyCachedInputFields(1)),
    );
    expect(cached.instructionData.treeContexts).toEqual(uncached.instructionData.treeContexts);
    expect(payload.publicInputHash).toBe(recomputedPublicInputHash(payload, bytes(3)));
  });

  it("binds the write cache, not the read cache, when a transfer uses both", () => {
    const value = fixture({ realInputs: 2 });
    const [first, second] = [input(value, 0), input(value, 1)];
    const assembled = assemble(
      withCache(value.proofInputs, {
        reads: [undefined, 7],
        read: OTHER_CACHE,
        writes: [7],
        write: CACHE,
      }),
      [spendProof(first)],
      [nonInclusionProof(second.nullifier())],
    );
    expect(assembled.proverInputs.payload.externalDataHash).toBe(
      bytesField(
        bindCacheWrite(value.proofInputs.externalData.hash(), {
          cache: CACHE,
          writeSlots: writeSlots([[0, 7]]),
        }),
        "external data hash",
      ),
    );
    expect(assembled.instructionData.circuit).toMatchObject({
      cacheAccess: { readBitmap: 1n << 7n, writeSlots: writeSlots([[0, 7]]) },
    });
  });
});

describe("a cache selection the client refuses before proving", () => {
  function refused(
    options: Parameters<typeof fixture>[0],
    spec: CacheSpec,
    code: ClientError["code"],
  ): unknown {
    const value = fixture(options);
    return rejects(() => assemble(withCache(value.proofInputs, spec), [], []), code);
  }

  it("names an input reading a slot an earlier input reads", () => {
    expect(
      refused(
        { realInputs: 2 },
        { reads: [4, 4], read: CACHE },
        "CLIENT_DUPLICATE_CACHE_READ_SLOT",
      ),
    ).toEqual({ index: 1, slot: 4 });
  });

  it("names a cached input of another tree than the first cached input", () => {
    expect(
      refused(
        { realInputs: 2, inputTreeIds: [TREE_ID, 1] },
        { reads: [1, 2], read: CACHE },
        "CLIENT_CACHE_READ_TREE_MISMATCH",
      ),
    ).toEqual({ index: 1, treeId: 1, cacheTreeId: TREE_ID });
  });

  it("names a cached input of a transfer that reads no cache", () => {
    expect(refused({}, { reads: [0] }, "CLIENT_CACHED_INPUT_WITHOUT_READ_CACHE")).toEqual({
      index: 0,
    });
  });

  it("refuses a read cache no input reads from", () => {
    refused({}, { read: CACHE }, "CLIENT_UNUSED_READ_CACHE");
  });

  it("names an output writing a slot an earlier output writes", () => {
    expect(
      refused(
        { ownedOutputs: 2 },
        { writes: [5, 5], write: CACHE },
        "CLIENT_DUPLICATE_CACHE_WRITE_SLOT",
      ),
    ).toEqual({ index: 1, slot: 5 });
  });

  it("names a cached output of a transfer that writes no cache", () => {
    expect(refused({}, { writes: [5] }, "CLIENT_CACHED_OUTPUT_WITHOUT_WRITE_CACHE")).toEqual({
      index: 0,
    });
  });

  it("refuses a write cache no output is written to", () => {
    refused({}, { write: CACHE }, "CLIENT_UNUSED_WRITE_CACHE");
  });

  it.each([36, -1])("names an output built around the SDK writing slot %s", (slot) => {
    expect(
      refused(
        {},
        {
          write: CACHE,
          outputs: ([first, ...rest]) => [
            ...(first === undefined ? [] : [{ ...first, cacheSlot: slot }]),
            ...rest,
          ],
        },
        "CLIENT_CACHE_WRITE_SLOT_OUT_OF_RANGE",
      ),
    ).toEqual({ index: 0, slot });
  });

  it("refuses an output built around the SDK naming a fractional slot", () => {
    expect(
      refused(
        {},
        {
          write: CACHE,
          outputs: ([first, ...rest]) => [
            ...(first === undefined ? [] : [{ ...first, cacheSlot: 1.5 }]),
            ...rest,
          ],
        },
        "CLIENT_INVALID_CACHE_ACCESS",
      ),
    ).toEqual({ field: "cacheSlot", index: 0 });
  });

  it("names a padding output built around the SDK for a cache slot", () => {
    expect(
      refused(
        {},
        {
          write: CACHE,
          outputs: ([first, padding]) => [
            ...(first === undefined ? [] : [first]),
            ...(padding === undefined ? [] : [{ ...padding, cacheSlot: 1 }]),
          ],
        },
        "CLIENT_CACHED_DUMMY_OUTPUT",
      ),
    ).toEqual({ index: 1 });
  });

  it("refuses a missing or foreign nullifier proof for a cached input", () => {
    const value = fixture();
    const spent = input(value, 0);
    const proofInputs = withCache(value.proofInputs, { reads: [0], read: CACHE });
    const assembleWith = (proofs: readonly NonInclusionProof[]) => () =>
      assemble(proofInputs, [], proofs);
    rejects(assembleWith([]), "CLIENT_MISSING_INPUT_MERKLE_PROOF");
    rejects(assembleWith([nonInclusionProof(bytes(1))]), "CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH");
    rejects(
      assembleWith([nonInclusionProof(spent.nullifier(), treeAddress(1))]),
      "CLIENT_PROOF_TREE_MISMATCH",
    );
  });
});

function proverFetch(): ReturnType<typeof vi.fn<typeof globalThis.fetch>> {
  return vi.fn<typeof globalThis.fetch>(async (_url, init) =>
    Response.json(proofFor(String(init?.body))),
  );
}

function client(fetch: typeof globalThis.fetch): ZolanaClient {
  return new ZolanaClient({
    solanaRpcUrl: "http://127.0.0.1:8899",
    indexerUrl: "http://127.0.0.1:8784",
    proverUrl: "http://127.0.0.1:3001",
    tree: TREE,
    fetch,
    indexerConfig: { poll: { numRetries: 1, delayMs: 0n, maxDelayMs: 0n } },
  });
}

describe("ZolanaClient.proveTransact reading from a cache", () => {
  it("fetches only a nullifier proof for a fully cached run", async () => {
    const value = fixture();
    const spent = input(value, 0);
    const fetch = proverFetch();
    const instance = client(fetch);
    const getMerkleProofs = vi.spyOn(instance, "getMerkleProofs");
    const getAccount = vi.spyOn(instance, "getAccount");
    const getNonInclusionProofs = vi.spyOn(instance, "getNonInclusionProofs").mockResolvedValue({
      context: { blockTime: 1n, slot: 1n },
      proofs: [nonInclusionProof(spent.nullifier())],
    });

    const data = await instance.proveTransact(
      withCache(value.proofInputs, { reads: [3], read: CACHE }),
      LocalKeys.fromKeypair(value.keypair, instance.proofService),
    );

    expect(getMerkleProofs).not.toHaveBeenCalled();
    expect(getAccount).not.toHaveBeenCalled();
    expect(getNonInclusionProofs.mock.calls[0]?.slice(0, 2)).toEqual([TREE, [spent.nullifier()]]);
    expect(data.circuit).toMatchObject({
      kind: "confidentialEddsaCached",
      cacheAccess: { readBitmap: 1n << 3n, writeSlots: NO_CACHE_WRITES },
    });
    expect(data.treeContexts).toEqual([
      { utxoTreeRootIndex: NO_UTXO_ROOT, nullifierTreeRootIndex: NULLIFIER_ROOT_INDEX },
    ]);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("requests the proven inputs' nullifiers before the cached ones in one request", async () => {
    const value = fixture({ realInputs: 2 });
    const [first, second] = [input(value, 0), input(value, 1)];
    const instance = client(proverFetch());
    const getMerkleProofs = vi.spyOn(instance, "getMerkleProofs").mockResolvedValue({
      context: { blockTime: 1n, slot: 1n },
      proofs: [spendProof(first).state],
    });
    const getNonInclusionProofs = vi.spyOn(instance, "getNonInclusionProofs").mockResolvedValue({
      context: { blockTime: 1n, slot: 1n },
      proofs: [nonInclusionProof(first.nullifier()), nonInclusionProof(second.nullifier())],
    });

    const data = await instance.proveTransact(
      withCache(value.proofInputs, { reads: [undefined, 11], read: CACHE }),
      LocalKeys.fromKeypair(value.keypair, instance.proofService),
    );

    expect(getMerkleProofs.mock.calls[0]?.slice(0, 2)).toEqual([TREE, [first.hash()]]);
    expect(getNonInclusionProofs).toHaveBeenCalledOnce();
    expect(getNonInclusionProofs.mock.calls[0]?.slice(0, 2)).toEqual([
      TREE,
      [first.nullifier(), second.nullifier()],
    ]);
    expect(data.treeContexts).toEqual([
      { utxoTreeRootIndex: STATE_ROOT_INDEX, nullifierTreeRootIndex: NULLIFIER_ROOT_INDEX },
    ]);
  });

  it("refuses a duplicate read before any request", async () => {
    const value = fixture({ realInputs: 2 });
    const fetch = vi.fn<typeof globalThis.fetch>();
    const instance = client(fetch);
    const getNonInclusionProofs = vi.spyOn(instance, "getNonInclusionProofs");
    await expect(
      instance.proveTransact(
        withCache(value.proofInputs, { reads: [6, 6], read: CACHE }),
        LocalKeys.fromKeypair(value.keypair, instance.proofService),
      ),
    ).rejects.toMatchObject({
      code: "CLIENT_DUPLICATE_CACHE_READ_SLOT",
      details: { index: 1, slot: 6 },
    });
    expect(getNonInclusionProofs).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });
});

function mergeFixture() {
  const owner = ShieldedKeypair.generate();
  const prepared = Merge.fromKeypair(owner, [
    ProofInputUtxo.fromKeypair(
      new Utxo({
        owner: owner.signingPublicKey(),
        asset: SOL_MINT,
        amount: 5n,
        blinding: bytes(1),
      }),
      owner,
    ),
  ]).prepare();
  return {
    owner,
    prepared,
    proofs: prepared.inputs.filter((entry) => !entry.isDummy()).map(spendProof),
    dummyProofs: prepared.dummyNullifiers().map((leaf) => nonInclusionProof(leaf)),
  };
}

describe("a merge writing its output to a cache slot", () => {
  const PROOF = { a: bytes(0), b: new Uint8Array(128) as Bytes128, c: bytes(0) };

  it("names the slot in its data and commits its external data hash to the cache", () => {
    const { prepared, proofs, dummyProofs } = mergeFixture();
    const cached = assembleMergeWithProofs(prepared, proofs, TREE, dummyProofs, {
      address: CACHE,
      slot: 5,
    });
    const plain = assembleMergeWithProofs(prepared, proofs, TREE, dummyProofs);
    const data = cached.instructionData(PROOF);

    expect(cached.cacheSlot).toBe(5);
    expect(plain.cacheSlot).toBeUndefined();
    expect(data.cacheSlot).toBe(5);
    expect(encodeMergeTransactInstructionData(data)).toHaveLength(528);
    expect(cached.externalDataHash).toEqual(
      mergeExternalDataHash({
        instructionTag: InstructionTag.mergeTransact,
        expiryUnixTs: prepared.expiryUnixTs,
        outputUtxoHash: prepared.outputHash(),
        cache: { address: CACHE, slot: 5 },
      }),
    );
    expect(cached.externalDataHash).not.toEqual(plain.externalDataHash);
    expect(cached.publicInputHash).not.toEqual(plain.publicInputHash);
    expect(cached.proverInputs.externalDataHash).toBe(bytesToBigInt(cached.externalDataHash));
    expect(cached.outputHash).toEqual(plain.outputHash);
  });

  it.each([36, -1, 1.5])("refuses slot %s", (slot) => {
    const { prepared, proofs, dummyProofs } = mergeFixture();
    expect(
      rejects(
        () =>
          assembleMergeWithProofs(prepared, proofs, TREE, dummyProofs, { address: CACHE, slot }),
        "CLIENT_INVALID_CACHE_ACCESS",
      ),
    ).toEqual({ field: "slot" });
  });

  it("proves the merge for the slot through the client", async () => {
    const { owner, prepared, proofs, dummyProofs } = mergeFixture();
    const instance = client(proverFetch());
    vi.spyOn(instance, "getInputMerkleProofs").mockResolvedValue(proofs);
    vi.spyOn(instance, "getNonInclusionProofs").mockResolvedValue({
      context: { blockTime: 1n, slot: 1n },
      proofs: dummyProofs,
    });
    const proved = await instance.proveMerge({
      prepared,
      keys: LocalKeys.fromKeypair(owner, instance.proofService),
      cache: { address: CACHE, slot: 2 },
    });
    expect(proved.data.cacheSlot).toBe(2);
    expect(proved.outputHash).toEqual(prepared.outputHash());
  });
});
