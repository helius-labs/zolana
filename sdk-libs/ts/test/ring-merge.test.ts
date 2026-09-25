import { proofFor } from "./helpers/proofs.js";
import { address, AccountRole } from "@solana/kit";
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
  mergePrivateTxBlinding,
} from "../src/keypair/merge/index.js";
import { Merge, PreparedMerge } from "../src/transaction/instructions/builders.js";
import { Data } from "../src/transaction/data.js";
import { Utxo, ProofInputUtxo } from "../src/transaction/utxo.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import { ringMergeInstruction } from "../src/ring/instructions.js";
import { intentHash } from "../src/transaction/wallet/intent.js";
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

function input(amount: bigint, ringProgramId: Address = RING, data = new Data()): ProofInputUtxo {
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
    undefined,
    7,
  );
}
function merge(inputs: readonly ProofInputUtxo[], outputTreeId = 7): Merge {
  const first = inputs[0];
  if (first === undefined) throw new Error("empty fixture");
  const key = owner.nullifierKey();
  try {
    return new Merge({
      address: owner.shieldedAddress(),
      inputs,
      outputTreeId,
      ring: { programId: RING },
      outputBlinding: mergeOutputBlinding(key, first.nullifier()),
      privateTxBlinding: mergePrivateTxBlinding(key, first.nullifier()),
      dummyNullifiers: PreparedMerge.dummySlots(inputs.length).map((slot) =>
        mergeDummyNullifier(key, first.nullifier(), slot),
      ),
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

await initializePoseidon();
describe("ring merge", () => {
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
          ...proofFor({ circuitType: "merge-ring", inputs: Array(8) }),
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
          proofDataSource === "prover" ? /\/prove\/indexed$/u : /\/prove$/u,
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
    const wallet = new Wallet({ identity: owner.shieldedAddress(), registry: new AssetRegistry() });
    wallet._replace({
      utxos: [3n, 5n].map((amount) => {
        const proof = input(amount);
        return {
          utxo: proof.utxo,
          outputContext: { hash: proof.hash(), tree: treeAddress(7), leafIndex: 0n },
          nullifier: proof.nullifier(),
          spent: false,
        };
      }),
      transactions: [],
      nullifiers: new Set(),
    });
    const answers: ("forged" | "lagging" | "proof")[] = ["forged", "lagging", "proof"];
    const proveMerge = vi.fn<MergeAssembler["proveMerge"]>(async ({ prepared }) => {
      const answer = answers.shift();
      if (answer === "lagging") throw new ClientError("CLIENT_INDEXER_PROOF_DATA_NOT_READY");
      const data = prepareMerge(prepared, treeAddress(7))
        .finish({
          slot: { id: 7, utxoRoot: field(1), nullifierRoot: field(2) },
          utxoRootIndex: 0,
          nullifierRootIndex: 0,
        })
        .instructionData({ a: field(0), b: new Uint8Array(128) as Bytes128, c: field(0) });
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
      buildRingMergeTransaction({
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
      });
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

  it.each([2, 8])("preserves owner, asset, value and ring for %s fragmented inputs", (count) => {
    const inputs = Array.from({ length: count }, (_, index) => input(BigInt(index + 1)));
    const prepared = merge(inputs).prepare();
    expect(prepared.inputs).toHaveLength(8);
    expect(prepared.output.amount).toBe(BigInt((count * (count + 1)) / 2));
    expect(prepared.output.asset).toBe(SOL_MINT);
    expect(prepared.output.ringProgramId).toBe(RING);
    expect(prepared.output.ownerAddress?.toBytes()).toEqual(owner.shieldedAddress().toBytes());
    expect(prepared.outputTreeId).toBe(7);
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

  it("refuses foreign rings, owner data, and more than eight inputs", () => {
    expect(() => merge([input(3n), input(5n, treeAddress(1))])).toThrow(
      "TRANSACTION_MERGE_INPUT_RING_MISMATCH",
    );
    expect(() =>
      merge([input(3n, RING, new Data([{ kind: "utxoData", bytes: Uint8Array.of(1) }]))]),
    ).toThrow("TRANSACTION_MERGE_INPUT_HAS_DATA");
    expect(() => merge(Array.from({ length: 9 }, (_, index) => input(BigInt(index + 1))))).toThrow(
      "TRANSACTION_TOO_MANY_INPUTS",
    );
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
    expect(instruction.accounts).toHaveLength(17);
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
