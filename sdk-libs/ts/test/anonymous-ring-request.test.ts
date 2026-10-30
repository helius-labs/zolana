import { bytesToHex } from "@noble/hashes/utils.js";
import { getAddressDecoder } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import vector from "../../../test-vectors/anonymous_ring_eddsa_request.json" with { type: "json" };
import { LocalKeys, ZolanaClient, signTransactMessage } from "../src/client/index.js";
import { prepareTransfer, resolvedPublicInputHash } from "../src/client/prover/assembly.js";
import type { SpendProof } from "../src/client/rpc.js";
import { solanaOwnerIdentity } from "../src/hasher/index.js";
import { bytesToBigInt } from "../src/interface/bytes.js";
import { encodeTransactInstructionData } from "../src/interface/codecs/index.js";
import type { Address, Bytes16, Bytes32 } from "../src/interface/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { inputTreeSlots } from "../src/interface/tree-slot.js";
import { ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import {
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  Utxo,
  createExternalData,
  createProofOutput,
  outputBlindingSeed,
  transactOutputBlinding,
} from "../src/transaction/index.js";
import { proofFor } from "./helpers/proofs.js";

// Mirrors the fixture of sdk-libs/client/tests/anonymous_ring_eddsa_request.rs.
const TREE_ID = 0;
const TREE = treeAddress(TREE_ID);
const RING = getAddressDecoder().decode(new Uint8Array(32).fill(0x52));
const OWNER_TAG = new Uint8Array(32).fill(0x08) as Bytes32;
const ZERO_POINT = ["0x0", "0x0"];

function fieldBytes(byte: number): Bytes32 {
  const value = new Uint8Array(32).fill(byte) as Bytes32;
  value[0] = 0;
  return value;
}

function keypair(seed: number): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
  );
}

function proofInputs(
  owner: ShieldedKeypair,
  spend: Readonly<{ ring?: Address; extraInputs?: readonly ProofInputUtxo[] }> = { ring: RING },
): SppProofInputs {
  const input = ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: owner.signingPublicKey(),
      asset: SOL_MINT,
      amount: 7n,
      blinding: fieldBytes(0x31),
      ...(spend.ring === undefined ? {} : { ringProgramId: spend.ring }),
    }),
    owner,
  );
  const blindingSeed = fieldBytes(0x41);
  const outputSeed = outputBlindingSeed(input.nullifier(), blindingSeed);
  const outputs = (
    [
      [keypair(0x22), 4n],
      [owner, 3n],
    ] as const
  ).map(([holder, amount], index) =>
    createProofOutput({
      ownerAddress: holder.shieldedAddress(),
      asset: SOL_MINT,
      amount,
      blinding: transactOutputBlinding(input.nullifier(), outputSeed, index),
      ringProgramId: RING,
    }),
  );
  return new SppProofInputs({
    payer: owner.shieldedAddress().solanaAddress(),
    inputUtxos: [input, ...(spend.extraInputs ?? [])],
    outputs,
    externalData: createExternalData({
      txViewingPublicKey: owner.viewingPublicKey(),
      salt: new Uint8Array(16).fill(0x5a) as Bytes16,
      outputs: outputs.map((output) => ({
        utxoHash: output.hash(TREE_ID),
        ownerTag: { kind: "inline", value: OWNER_TAG },
      })),
      resolvedOwnerTags: outputs.map(() => OWNER_TAG),
      messages: [],
    }),
    blindingSeed,
    outputTreeId: TREE_ID,
  });
}

function spendProof(input: ProofInputUtxo): SpendProof {
  const merkleContext = { treeType: 1, tree: TREE };
  return {
    state: {
      leaf: input.hash(),
      merkleContext,
      path: Array.from({ length: 32 }, () => fieldBytes(0x53)),
      leafIndex: 7n,
      root: fieldBytes(0x54),
      rootSeq: 11n,
      rootIndex: 5,
    },
    nullifier: {
      leaf: input.nullifier(),
      merkleContext,
      path: Array.from({ length: 40 }, () => fieldBytes(0x56)),
      lowElement: fieldBytes(0x57),
      lowElementIndex: 3n,
      highElement: fieldBytes(0x58),
      highElementIndex: 4n,
      root: fieldBytes(0x59),
      rootSeq: 13n,
      rootIndex: 9,
    },
  };
}

function hex(value: Uint8Array): string {
  return `0x${bytesToBigInt(value).toString(16)}`;
}

/** The indexed answer for the posted statement, resolved at the fixture's roots. */
function indexedResponse(
  body: Record<string, unknown>,
  proof: SpendProof,
): Record<string, unknown> {
  const slot = { id: TREE_ID, utxoRoot: proof.state.root, nullifierRoot: proof.nullifier.root };
  const statement = (body["publicInputs"] as string[]).map((value) => BigInt(value));
  return {
    ...proofFor(body["prepared"]),
    proofCommitment: ZERO_POINT,
    proofCommitmentPok: ZERO_POINT,
    resolution: {
      publicInputHash: `0x${resolvedPublicInputHash(statement, inputTreeSlots([slot])).toString(16)}`,
      trees: [
        {
          tree: TREE,
          id: TREE_ID,
          utxoRoot: hex(slot.utxoRoot),
          nullifierRoot: hex(slot.nullifierRoot),
          utxoRootIndex: proof.state.rootIndex,
          nullifierRootIndex: proof.nullifier.rootIndex,
        },
      ],
    },
  };
}

describe("ZolanaClient.proveAnonymousRingTransact", () => {
  it.each([
    ["client", "signer", "ring", vector.request, vector.circuit],
    ["client", "prepared signature", "ring", vector.request, vector.circuit],
    ["prover", "signer", "ring", vector.indexedRequest, vector.circuit],
    ["client", "signer", "default-ring", vector.defaultRing.request, vector.defaultRing.circuit],
  ] as const)(
    "posts the Rust prover's request from the %s data source and a %s spending a %s UTXO",
    async (proofDataSource, form, spent, request, selector) => {
      const owner = keypair(0x11);
      const transaction = proofInputs(owner, spent === "ring" ? { ring: RING } : {});
      const [input] = transaction.inputUtxos;
      if (input === undefined) throw new Error("no input");
      const proof = spendProof(input);
      const posted: unknown[] = [];
      const fetch = vi.fn<typeof globalThis.fetch>(async (_url, init) => {
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
        posted.push(body);
        return Response.json(
          proofDataSource === "prover"
            ? indexedResponse(body, proof)
            : { ...proofFor(body), proofCommitment: ZERO_POINT, proofCommitmentPok: ZERO_POINT },
        );
      });
      const client = new ZolanaClient({
        solanaRpcUrl: "http://127.0.0.1:8899",
        proofDataSource,
        indexerUrl: "http://127.0.0.1:8784",
        proverUrl: "http://127.0.0.1:3001",
        tree: TREE,
        fetch,
      });
      vi.spyOn(client, "getMerkleProofs").mockResolvedValue({
        context: { blockTime: 1n, slot: 1n },
        proofs: [proof.state],
      });
      vi.spyOn(client, "getNonInclusionProofs").mockResolvedValue({
        context: { blockTime: 1n, slot: 1n },
        proofs: [proof.nullifier],
      });
      const signed = await signTransactMessage(transaction, owner);
      const keys = LocalKeys.fromKeypair(owner, client.proofService);
      try {
        const proven = await client.proveAnonymousRingTransact({
          proofInputs: transaction,
          ringProgramId: RING,
          owner:
            form === "signer"
              ? owner
              : { ownerPublicKey: signed.ownerPublicKey, ownerSignature: signed.ownerSignature },
          keys,
        });
        expect(posted).toEqual([request]);
        expect(proven.ownerSigners).toEqual([]);
        const { circuit } = proven.data;
        if (circuit.kind !== "anonymousRingEddsa") throw new Error(circuit.kind);
        const unproven = {
          ...proven.data,
          circuit: {
            ...circuit,
            proofData: {
              ...circuit.proofData,
              bsb22Commitment: {
                commitment: new Uint8Array(32) as Bytes32,
                commitmentPok: new Uint8Array(32) as Bytes32,
              },
            },
          },
        };
        expect(bytesToHex(encodeTransactInstructionData(unproven))).toContain(selector);
      } finally {
        keys.destroy();
      }
    },
  );

  it.each([
    ["a ring", RING, false],
    ["a default-ring", undefined, true],
  ] as const)(
    "publishes the hidden owner only for a default-ring spend beside %s UTXO and an address",
    async (_name, inputRing, published) => {
      const owner = keypair(0x11);
      const address = ProofInputUtxo.address(owner.signingPublicKey(), fieldBytes(0x61), TREE_ID);
      const transaction = proofInputs(owner, {
        ...(inputRing === undefined ? {} : { ring: inputRing }),
        extraInputs: [address],
      });
      const authorization = await signTransactMessage(transaction, owner);
      const ownerKey = owner.signingPublicKey().ed25519();
      const prepared = prepareTransfer(transaction, {
        kind: "anonymousRingEddsa",
        ring: RING,
        authorization,
      });
      const identity = published ? bytesToBigInt(solanaOwnerIdentity(ownerKey)) : 0n;
      expect(prepared.inputs.publicInputs[5]).toBe(identity);
      const proof = spendProof(transaction.inputUtxos[0] as ProofInputUtxo);
      const { circuit } = prepared.finish([
        {
          treeId: TREE_ID,
          slot: { id: TREE_ID, utxoRoot: proof.state.root, nullifierRoot: proof.nullifier.root },
          utxoRootIndex: proof.state.rootIndex,
          nullifierRootIndex: proof.nullifier.rootIndex,
        },
      ]).instructionData;
      if (circuit.kind !== "anonymousRingEddsa") throw new Error(circuit.kind);
      expect(circuit.proofData.defaultOwnerTag).toEqual(published ? ownerKey : undefined);
    },
  );
});
