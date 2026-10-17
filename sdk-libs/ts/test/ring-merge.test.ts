import { ProverClient } from "../src/client/prover/client.js";
import { proveThroughAuthority } from "../src/client/prover/indexed.js";
import { asField } from "../src/client/prover/assembly.js";
import { proofFor } from "./helpers/proofs.js";
import {
  address,
  AccountRole,
  decompileTransactionMessage,
  getCompiledTransactionMessageDecoder,
  getTransactionSize,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";
import { ClientError, LocalKeys, ZolanaClient } from "../src/client/index.js";
import { initializePoseidon } from "../src/hasher/index.js";
import { assembleMergeWithProofs, prepareMerge } from "../src/client/prover/merge.js";
import { mergeProverRequestBody } from "../src/client/prover/client.js";
import type { NonInclusionProof, SpendProof } from "../src/client/rpc.js";
import { treeAddress, ringAuthAddress, ringCoSignerAddress } from "../src/interface/pda/index.js";
import type { Address, Bytes32, Bytes128 } from "../src/interface/types.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import {
  mergeDummyNullifier,
  mergeOutputBlinding,
  mergeOutputKey,
  mergePrivateTxBlinding,
} from "../src/keypair/merge/index.js";
import { Merge, PreparedMerge } from "../src/transaction/instructions/builders.js";
import { privateTxHash } from "../src/transaction/instructions/transact.js";
import { Data } from "../src/transaction/data.js";
import { Utxo, ProofInputUtxo } from "../src/transaction/utxo.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import { MAX_MERGE_INPUTS, MAX_RING_MERGE_INPUTS } from "../src/interface/constants.js";
import { ringMergeInstruction } from "../src/ring/instructions.js";
import { approveUnattended, intentHash } from "../src/transaction/wallet/intent.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import { Wallet } from "../src/transaction/wallet/state.js";
import { buildRingMergeTransaction } from "../src/ring/merge.js";
import type { MergeAssembler } from "../src/client/ports.js";
import { BLOCKHASH } from "./helpers/clients.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
function field(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
}
const owner = ShieldedKeypair.generate();

function input(
  amount: bigint,
  ringProgramId: Address = RING,
  data = new Data(),
  ringDataHash?: Bytes32,
): ProofInputUtxo {
  return ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: owner.signingPublicKey(),
      asset: SOL_MINT,
      amount,
      blinding: field(Number(amount)),
      ringProgramId,
      data,
    }),
    owner,
    ringDataHash === undefined ? {} : { ringDataHash },
    7,
  );
}
function merge(
  inputs: readonly ProofInputUtxo[],
  outputTreeId = 7,
  outputDataHash?: Bytes32,
): Merge {
  const first = inputs[0];
  if (first === undefined) throw new Error("empty fixture");
  const key = owner.nullifierKey();
  try {
    return new Merge({
      address: owner.shieldedAddress(),
      inputs,
      outputTreeId,
      ring: { programId: RING, ...(outputDataHash === undefined ? {} : { outputDataHash }) },
      outputBlinding: mergeOutputBlinding(key, first.nullifier()),
      privateTxBlinding: mergePrivateTxBlinding(key, first.nullifier()),
      dummyNullifiers: PreparedMerge.dummySlots(inputs.length).map((slot) =>
        mergeDummyNullifier(key, first.nullifier(), slot),
      ),
      outputKey: mergeOutputKey(key, first.nullifier()),
    });
  } finally {
    key.destroy();
  }
}
function nonInclusion(leaf: Bytes32): NonInclusionProof {
  return {
    leaf,
    merkleContext: { tree: treeAddress(7), treeType: 1 },
    path: Array.from({ length: 40 }, () => field(0)),
    lowElement: field(0),
    lowElementIndex: 0n,
    highElement: field(255),
    highElementIndex: 1n,
    root: field(2),
    rootSeq: 1n,
    rootIndex: 0,
  };
}
function spendProof(input: ProofInputUtxo): SpendProof {
  return {
    state: {
      leaf: input.hash(),
      merkleContext: { tree: treeAddress(7), treeType: 0 },
      path: Array.from({ length: 32 }, () => field(0)),
      leafIndex: 0n,
      root: field(1),
      rootSeq: 1n,
      rootIndex: 0,
    },
    nullifier: nonInclusion(input.nullifier()),
  };
}

function ringWallet(amounts: readonly bigint[], hashes: readonly Bytes32[] = []): Wallet {
  const wallet = new Wallet({ identity: owner.shieldedAddress(), registry: new AssetRegistry() });
  wallet._replace({
    utxos: amounts.map((amount, index) => {
      const proof = input(amount, RING, new Data(), hashes[index]);
      return {
        utxo: proof.utxo,
        outputContext: { hash: proof.hash(), tree: treeAddress(7), leafIndex: BigInt(index) },
        nullifier: proof.nullifier(),
        ...(proof.ringDataHash === undefined ? {} : { ringDataHash: proof.ringDataHash }),
        spent: false,
      };
    }),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}
function provenMerge(prepared: PreparedMerge) {
  return prepareMerge(prepared, treeAddress(7))
    .finish({
      slot: { id: 7, utxoRoot: field(1), nullifierRoot: field(2) },
      utxoRootIndex: 0,
      nullifierRootIndex: 0,
    })
    .instructionData({ a: field(0), b: new Uint8Array(128) as Bytes128, c: field(0) });
}
function ringMergeParams({
  proveMerge,
  wallet,
  keys,
  proofDataSource,
}: Readonly<{
  proveMerge: MergeAssembler["proveMerge"];
  wallet: Wallet;
  keys: LocalKeys;
  proofDataSource: "client" | "prover";
}>) {
  return {
    client: {
      proofDataSource,
      tree: treeAddress(7),
      treeId: 7,
      getAccount: async () => undefined,
      getLatestBlockhash: async () => BLOCKHASH,
      proveMerge,
    },
    ringProgramId: RING,
    wallet,
    keys,
    feePayer: owner.shieldedAddress().solanaAddress(),
  };
}

await initializePoseidon();
describe("ring merge", () => {
  it.each([false, true])(
    "forwards the inherited ring hash and refuses mixed commitments (mixed=%s)",
    async (mixed) => {
      const wallet = ringWallet([3n, 5n], [field(7), field(mixed ? 8 : 7)]);
      const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
        expect(prepared.output.ringDataHash).toEqual(field(7));
        const data = provenMerge(prepared);
        return { data, outputHash: data.outputUtxoHash };
      });
      const keys = LocalKeys.fromKeypair(owner, { prove: vi.fn(), proveMerge: vi.fn() });
      const derive = vi.spyOn(keys, "derive");
      try {
        const build = () =>
          buildRingMergeTransaction(
            ringMergeParams({ proveMerge, wallet, keys, proofDataSource: "client" }),
          );
        if (mixed) {
          await expect(build()).rejects.toMatchObject({
            code: "RING_BUILD_MERGE",
            causeCode: "TRANSACTION_MERGE_RING_DATA_MISMATCH",
          });
          expect(proveMerge).not.toHaveBeenCalled();
          expect(derive).not.toHaveBeenCalled();
          expect(wallet._reservationEntries()).toHaveLength(0);
        } else {
          const transaction = await build();
          const compiled = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
          if (compiled.version !== 1) throw new Error("expected V1");
          const instruction = decompileTransactionMessage(compiled, {
            lastValidBlockHeight: 1n,
          }).instructions.find((instruction) => instruction.programAddress === RING);
          expect(instruction?.data?.slice(1, 33)).toEqual(field(7));
          expect(proveMerge).toHaveBeenCalledOnce();
        }
      } finally {
        keys.destroy();
      }
    },
  );

  it.each(["input", "output", "public"] as const)(
    "rejects changed %s ring data in structural merge requests before proving",
    async (changed) => {
      const inputs = [input(3n, RING, new Data(), field(7)), input(5n, RING, new Data(), field(7))];
      const prepared = merge(inputs).prepare();
      const indexed = prepareMerge(prepared, treeAddress(7)).inputs;
      const complete = assembleMergeWithProofs(
        prepared,
        inputs.map(spendProof),
        treeAddress(7),
        prepared.dummyNullifiers().map(nonInclusion),
      );
      const alter = <T extends typeof indexed.payload>(payload: T): T => ({
        ...payload,
        ...(changed === "input"
          ? {
              inputs: payload.inputs.map((input, index) =>
                index === 1
                  ? { ...input, circuit: { ...input.circuit, ringDataHash: asField(8n) } }
                  : input,
              ),
            }
          : {}),
        ...(changed === "output"
          ? {
              output: {
                ...payload.output,
                circuit: { ...payload.output.circuit, ringDataHash: asField(8n) },
              },
            }
          : {}),
        ...(changed === "public" ? { outputRingDataHash: asField(8n) } : {}),
      });
      const fetch = vi.fn<typeof globalThis.fetch>(async () => {
        throw new Error("network reached");
      });
      const prover = new ProverClient({ tee: false, url: "https://prover.example", fetch });
      const authority = { prove: vi.fn(), proveMerge: vi.fn(), proveIndexed: vi.fn() };
      const refusal = {
        code: "CLIENT_TRANSACTION",
        details: { code: "TRANSACTION_MERGE_RING_DATA_MISMATCH" },
      };
      await expect(prover.proveMerge(alter(complete.proverInputs))).rejects.toMatchObject(refusal);
      await expect(
        proveThroughAuthority(authority, { ...indexed, payload: alter(indexed.payload) }),
      ).rejects.toMatchObject(refusal);
      expect(fetch).not.toHaveBeenCalled();
      expect(authority.proveIndexed).not.toHaveBeenCalled();
    },
  );

  it("inherits the common committed ring data hash and rejects changed input or output hashes", async () => {
    const hash = field(7);
    const inputs = [input(3n, RING, new Data(), hash), input(5n, RING, new Data(), hash)];
    const prepared = merge(inputs).prepare();
    expect(prepared.output.ringDataHash).toEqual(hash);
    expect(prepareMerge(prepared, treeAddress(7)).inputs.payload.outputRingDataHash).toBe(7n);
    expect(() => merge(inputs, 7, field(8))).toThrow(
      expect.objectContaining({ code: "TRANSACTION_MERGE_RING_DATA_MISMATCH" }),
    );
    expect(() => merge([inputs[0]!, input(5n)])).toThrow(
      expect.objectContaining({ code: "TRANSACTION_MERGE_RING_DATA_MISMATCH" }),
    );
    expect(() => merge([inputs[0]!, input(5n, RING, new Data(), field(8))])).toThrow(
      expect.objectContaining({ code: "TRANSACTION_MERGE_RING_DATA_MISMATCH" }),
    );
    // Public byte buffers can change after construction, so the client rechecks them.
    inputs[1]?.ringDataHash?.set(field(9));
    const fetch = vi.fn<typeof globalThis.fetch>(async () => {
      throw new Error("network reached");
    });
    const keys = LocalKeys.fromKeypair(owner, { prove: vi.fn(), proveMerge: vi.fn() });
    try {
      for (const proofDataSource of ["client", "prover"] as const) {
        const client = new ZolanaClient({ treeId: 7, proofDataSource, fetch });
        await expect(client.proveMerge({ prepared, keys })).rejects.toMatchObject({
          code: "CLIENT_TRANSACTION",
          details: { code: "TRANSACTION_MERGE_RING_DATA_MISMATCH" },
        });
      }
      expect(fetch).not.toHaveBeenCalled();
    } finally {
      keys.destroy();
    }
  });

  it.each(["client", "prover"] as const)(
    "keeps ring merge proofs complete with %s fetching",
    async (proofDataSource) => {
      const inputs = [input(3n), input(5n)];
      const prepared = merge(inputs, 9).prepare();
      const expected = assembleMergeWithProofs(
        prepared,
        inputs.map(spendProof),
        treeAddress(7),
        prepared.dummyNullifiers().map(nonInclusion),
      );
      const fetch = vi.fn<typeof globalThis.fetch>(async () =>
        Response.json({
          ...proofFor({ circuitType: "merge-ring", inputs: Array(prepared.inputs.length) }),
          resolution: {
            publicInputHash: `0x${expected.proverInputs.publicInputHash.toString(16)}`,
            trees: [
              {
                tree: treeAddress(7),
                id: 7,
                utxoRoot: "0x1",
                nullifierRoot: "0x2",
                utxoRootIndex: 0,
                nullifierRootIndex: 0,
              },
            ],
          },
        }),
      );
      const client = new ZolanaClient({ treeId: 7, proofDataSource, fetch });
      const state = vi
        .spyOn(client, "getInputMerkleProofs")
        .mockResolvedValue(inputs.map(spendProof));
      const nullifier = vi.spyOn(client, "getNonInclusionProofs").mockResolvedValue({
        context: { blockTime: 1n, slot: 1n },
        proofs: prepared.dummyNullifiers().map(nonInclusion),
      });
      const keys = LocalKeys.fromKeypair(owner, client.proofService);
      const indexed = vi.spyOn(keys, "proveIndexed");
      try {
        const result = await client.proveMerge({ prepared, keys });
        expect(result.outputHash).toEqual(prepared.output.hash(9));
        expect(state).toHaveBeenCalledTimes(proofDataSource === "client" ? 1 : 0);
        expect(nullifier).toHaveBeenCalledTimes(proofDataSource === "client" ? 1 : 0);
        expect(indexed).toHaveBeenCalledTimes(proofDataSource === "prover" ? 1 : 0);
        expect(fetch).toHaveBeenCalledOnce();
        expect(String(fetch.mock.calls[0]?.[0])).toMatch(
          proofDataSource === "prover"
            ? /\/prove\/[a-z0-9_-]+\/indexed$/u
            : /\/prove\/[a-z0-9_-]+$/u,
        );
        const body = JSON.parse(String(fetch.mock.calls[0]?.[1]?.body));
        expect(proofDataSource === "prover" ? body.prepared : body).toMatchObject({
          circuitType: "merge-ring",
        });
        if (proofDataSource === "prover") expect(body.prepared).not.toHaveProperty("treeSlots");
        else expect(body).toHaveProperty("treeSlots");
      } finally {
        keys.destroy();
      }
    },
  );

  it.each(["spend", "dummy"] as const)(
    "refuses a %s proof from another tree on the client source",
    async (kind) => {
      const inputs = [input(3n), input(5n)];
      const prepared = merge(inputs, 9).prepare();
      const foreign = { tree: treeAddress(8), treeType: 0 };
      const client = new ZolanaClient({ treeId: 7, proofDataSource: "client", fetch: vi.fn() });
      vi.spyOn(client, "getInputMerkleProofs").mockResolvedValue(
        inputs.map(spendProof).map((proof, index) =>
          kind === "spend" && index === 1
            ? {
                state: { ...proof.state, merkleContext: foreign },
                nullifier: { ...proof.nullifier, merkleContext: foreign },
              }
            : proof,
        ),
      );
      vi.spyOn(client, "getNonInclusionProofs").mockResolvedValue({
        context: { blockTime: 1n, slot: 1n },
        proofs: prepared
          .dummyNullifiers()
          .map(nonInclusion)
          .map((proof, index) =>
            kind === "dummy" && index === 0 ? { ...proof, merkleContext: foreign } : proof,
          ),
      });
      const keys = LocalKeys.fromKeypair(owner, client.proofService);
      try {
        await expect(client.proveMerge({ prepared, keys })).rejects.toMatchObject({
          code: "CLIENT_MERGE_TREE_MISMATCH",
          details: { proofTree: treeAddress(8), submitTree: treeAddress(7) },
        });
      } finally {
        keys.destroy();
      }
    },
  );

  it("proves a ring merge through the client and retries a lagging prover indexer", async () => {
    const wallet = ringWallet([3n, 5n]);
    const answers: ("forged" | "lagging" | "proof")[] = ["forged", "lagging", "proof"];
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const answer = answers.shift();
      if (answer === "lagging") throw new ClientError("CLIENT_INDEXER_PROOF_DATA_NOT_READY");
      const data = provenMerge(prepared);
      return {
        data: answer === "forged" ? { ...data, outputUtxoHash: field(9) } : data,
        outputHash: data.outputUtxoHash,
      };
    });
    const keys = LocalKeys.fromKeypair(owner, {
      prove: vi.fn(),
      proveMerge: vi.fn(),
    });
    const build = (proofDataSource: "client" | "prover") =>
      buildRingMergeTransaction(ringMergeParams({ proveMerge, wallet, keys, proofDataSource }));
    try {
      await expect(build("client")).rejects.toMatchObject({
        code: "RING_BUILD_MERGE",
        causeCode: "RING_INTENT_MISMATCH",
      });
      await expect(build("prover")).resolves.toBeDefined();
      expect(proveMerge).toHaveBeenCalledTimes(3);
      expect(Object.keys(proveMerge.mock.calls[2]?.[0] ?? {}).sort()).toEqual(["keys", "prepared"]);
    } finally {
      keys.destroy();
    }
  });

  it.each(["client", "prover"] as const)(
    "caps custom merges at 50 before %s proving",
    async (proofDataSource) => {
      const wallet = ringWallet(Array.from({ length: 51 }, (_, index) => BigInt(index + 1)));
      const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
        const data = provenMerge(prepared);
        return { data, outputHash: data.outputUtxoHash };
      });
      const keys = LocalKeys.fromKeypair(owner, { prove: vi.fn(), proveMerge: vi.fn() });
      const derive = vi.spyOn(keys, "derive");
      const params = ringMergeParams({ proveMerge, wallet, keys, proofDataSource });
      const getAccount = vi.fn(params.client.getAccount);
      const getLatestBlockhash = vi.fn(params.client.getLatestBlockhash);
      const build = (maxInputs: number) =>
        buildRingMergeTransaction({
          ...params,
          client: { ...params.client, getAccount, getLatestBlockhash },
          maxInputs,
        });
      try {
        expect(MAX_RING_MERGE_INPUTS).toBe(50);
        for (const [maxInputs, causeCode] of [
          [51, "RING_TOO_MANY_INPUTS"],
          [52, "RING_TOO_MANY_INPUTS"],
          [1, "RING_NOTHING_TO_MERGE"],
          [-1, "RING_NOTHING_TO_MERGE"],
          [2.5, "RING_NOTHING_TO_MERGE"],
          [Number.NaN, "RING_NOTHING_TO_MERGE"],
        ] as const) {
          await expect(build(maxInputs)).rejects.toMatchObject({
            code: "RING_BUILD_MERGE",
            causeCode,
          });
        }
        expect(proveMerge).not.toHaveBeenCalled();
        expect(derive).not.toHaveBeenCalled();
        expect(getAccount).not.toHaveBeenCalled();
        expect(getLatestBlockhash).not.toHaveBeenCalled();
        expect(wallet._reservationEntries()).toHaveLength(0);
        const transaction = await build(50);
        expect(getTransactionSize(transaction)).toBeLessThanOrEqual(4096);
        const prepared = proveMerge.mock.calls[0]?.[0].prepared;
        expect(prepared?.inputs).toHaveLength(52);
        expect(prepared?.inputs.filter((spend) => !spend.isDummy())).toHaveLength(50);
        expect(proveMerge).toHaveBeenCalledOnce();
      } finally {
        keys.destroy();
      }
    },
  );

  it.each(["client", "prover"] as const)(
    "rejects extra signer bytes before %s merge proving and releases the notes",
    async (proofDataSource) => {
      const wallet = ringWallet(Array.from({ length: 50 }, (_, index) => BigInt(index + 1)));
      const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
        const data = provenMerge(prepared);
        return { data, outputHash: data.outputUtxoHash };
      });
      const keys = LocalKeys.fromKeypair(owner, { prove: vi.fn(), proveMerge: vi.fn() });
      const params = ringMergeParams({ proveMerge, wallet, keys, proofDataSource });
      const approve = vi.fn(approveUnattended);
      const getLatestBlockhash = vi.fn(params.client.getLatestBlockhash);
      try {
        await expect(
          buildRingMergeTransaction({
            ...params,
            client: { ...params.client, getLatestBlockhash },
            maxInputs: 50,
            cosigner: treeAddress(19),
            approve,
          }),
        ).rejects.toMatchObject({
          code: "RING_BUILD_MERGE",
          causeCode: "INTERFACE_TRANSACTION_TOO_LARGE",
        });
        expect(proveMerge).not.toHaveBeenCalled();
        expect(approve).not.toHaveBeenCalled();
        expect(getLatestBlockhash).not.toHaveBeenCalled();
        expect(wallet._reservationEntries()).toHaveLength(0);
        const transaction = await buildRingMergeTransaction({
          ...params,
          maxInputs: 49,
          cosigner: treeAddress(19),
          approve,
        });
        expect(getTransactionSize(transaction)).toBeLessThanOrEqual(4096);
        expect(proveMerge).toHaveBeenCalledOnce();
        expect(approve).toHaveBeenCalledOnce();
      } finally {
        keys.destroy();
      }
    },
  );

  it.each([
    [2, 8],
    [8, 8],
    [9, 24],
    [24, 24],
    [25, 52],
    [52, 52],
  ])("preserves owner, asset, value and ring for %s fragmented inputs", (count, width) => {
    const inputs = Array.from({ length: count }, (_, index) => input(BigInt(index + 1)));
    const prepared = merge(inputs).prepare();
    expect(prepared.inputs).toHaveLength(width);
    expect(prepared.inputs.map((spend) => spend.isCompact())).toEqual(
      Array.from({ length: width }, (_, index) => index >= count),
    );
    expect(provenMerge(prepared).nullifiers).toHaveLength(count);
    expect(prepared.output.amount).toBe(BigInt((count * (count + 1)) / 2));
    expect(prepared.output.asset).toBe(SOL_MINT);
    expect(prepared.output.ringProgramId).toBe(RING);
    expect(prepared.output.ownerAddress?.toBytes()).toEqual(owner.shieldedAddress().toBytes());
    expect(prepared.outputTreeId).toBe(7);
  });

  it.each([2, 25, 52])("zeroes padding in the private tx hash of a %i-input merge", (count) => {
    const inputs = Array.from({ length: count }, (_, index) => input(BigInt(index + 1)));
    const prepared = merge(inputs).prepare();
    const assembly = assembleMergeWithProofs(
      prepared,
      inputs.map(spendProof),
      treeAddress(7),
      prepared.dummyNullifiers().map(nonInclusion),
    );
    expect(assembly.privateTxHash).toEqual(
      privateTxHash({
        inputHashes: prepared.inputs.map((spend) =>
          spend.isDummy() ? (new Uint8Array(32) as Bytes32) : spend.hash(),
        ),
        outputHashes: [assembly.outputHash],
        blinding: prepared.privateTxBlinding(),
      }),
    );
  });

  it("binds a separate output tree and sends a ring merge proof request", () => {
    const inputs = [input(3n), input(5n)];
    const prepared = merge(inputs, 9).prepare();
    const assembly = assembleMergeWithProofs(
      prepared,
      inputs.map(spendProof),
      treeAddress(7),
      prepared.dummyNullifiers().map(nonInclusion),
    );
    expect(mergeProverRequestBody(assembly.proverInputs)).toMatchObject({
      circuitType: "merge-ring",
    });
    expect(assembly.proverInputs.ringProgramId).not.toBe(0n);
    expect(assembly.proverInputs.outputRingDataHash).toBe(0n);
    expect(assembly.outputHash).toEqual(prepared.output.hash(9));
    expect(assembly.outputHash).not.toEqual(prepared.output.hash(7));
  });

  it("refuses foreign rings, owner data, and more than 52 inputs", () => {
    expect(() => merge([input(3n), input(5n, treeAddress(1))])).toThrow(
      "TRANSACTION_MERGE_INPUT_RING_MISMATCH",
    );
    expect(() =>
      merge([input(3n, RING, new Data([{ kind: "utxoData", bytes: Uint8Array.of(1) }]))]),
    ).toThrow("TRANSACTION_MERGE_INPUT_HAS_DATA");
    expect(() =>
      merge(Array.from({ length: MAX_MERGE_INPUTS + 1 }, (_, index) => input(BigInt(index + 1)))),
    ).toThrow("TRANSACTION_TOO_MANY_INPUTS");
  });

  it("keeps the ordinary merge rail closed to ring notes", () => {
    expect(() => Merge.fromKeypair(owner, [input(3n)])).toThrow(
      "TRANSACTION_MERGE_INPUT_RING_MISMATCH",
    );
  });

  it("places co-signers before the SPP accounts and marks only the supplied signer", async () => {
    const inputs = [input(3n), input(5n)];
    const prepared = merge(inputs).prepare();
    const assembly = assembleMergeWithProofs(
      prepared,
      inputs.map(spendProof),
      treeAddress(7),
      prepared.dummyNullifiers().map(nonInclusion),
    );
    const cosigner = ShieldedKeypair.generate().shieldedAddress().solanaAddress();
    const instruction = await ringMergeInstruction({
      ringProgramId: RING,
      inputTree: treeAddress(7),
      outputTree: treeAddress(7),
      payer: owner.shieldedAddress().solanaAddress(),
      cosigner,
      outputRingDataHash: field(0),
      data: assembly.instructionData({
        a: field(0),
        b: new Uint8Array(128) as Bytes128,
        c: field(0),
      }),
    });
    expect(instruction.programAddress).toBe(RING);
    expect(instruction.data?.[0]).toBe(20);
    expect(instruction.accounts?.[1]?.address).toBe(await ringCoSignerAddress(RING));
    expect(instruction.accounts?.[2]).toMatchObject({
      address: cosigner,
      role: AccountRole.READONLY_SIGNER,
    });
    expect(instruction.accounts?.[5]).toMatchObject({
      address: await ringAuthAddress(RING),
      role: AccountRole.READONLY,
    });
    expect(instruction.accounts).toHaveLength(9 + inputs.length);
  });

  it("binds ring identity and destination into approval", () => {
    const intent = {
      kind: "ringMerge" as const,
      ringProgramId: RING,
      outputTree: treeAddress(7),
      asset: SOL_MINT,
      numInputs: 2,
      mergedAmount: 8n,
    };
    expect(intentHash(intent)).not.toEqual(
      intentHash({ ...intent, ringProgramId: treeAddress(1) }),
    );
    expect(intentHash(intent)).not.toEqual(intentHash({ ...intent, outputTree: treeAddress(9) }));
  });
});
