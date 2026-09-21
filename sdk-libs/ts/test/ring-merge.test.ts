import { address, AccountRole } from "@solana/kit";
import { describe, expect, it } from "vitest";
import { initializePoseidon } from "../src/hasher/index.js";
import { assembleMergeWithProofs } from "../src/client/prover/merge.js";
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
      hasPolicy: true,
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
    expect(instruction.accounts?.[6]).toMatchObject({
      address: await ringAuthAddress(RING),
      role: AccountRole.READONLY,
    });
    expect(instruction.accounts).toHaveLength(18);
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
