import { address, type Address } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";

import { LocalKeys, ZolanaClient, type SpendProof } from "../src/client/index.js";
import { mintAuthorizedPrivateTransaction } from "../src/client/ports.js";
import { prepareTransfer, signerIdentity } from "../src/client/prover/assembly.js";
import type { Bytes16, Bytes32 } from "../src/interface/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
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
import { intentHash, type TransactionIntent } from "../src/transaction/wallet/intent.js";
import { BLOCKHASH } from "./helpers/clients.js";
import { stateTree } from "./helpers/state-tree.js";
import { proofFor } from "./helpers/proofs.js";

const TREE = treeAddress(0);
/** Pays without owning anything the transaction spends or creates. */
const SPONSOR = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

/** A root blinding seed is a field element, so its leading byte stays zero. */
function blindingSeed(value: number): Bytes32 {
  const seed = bytes(value);
  seed[0] = 0;
  return seed;
}

const keypairs: ShieldedKeypair[] = [];

function keypair(): ShieldedKeypair {
  const generated = ShieldedKeypair.generate();
  keypairs.push(generated);
  return generated;
}

/**
 * The owner spends one UTXO and pays the recipient an output carrying data,
 * which the circuit only accepts when the recipient signs too.
 */
function dataTransfer() {
  const owner = keypair();
  const recipient = keypair();
  const input = ProofInputUtxo.fromKeypair(
    new Utxo({ owner: owner.signingPublicKey(), asset: SOL_MINT, amount: 7n, blinding: bytes(1) }),
    owner,
  );
  const seed = blindingSeed(9);
  const outputSeed = outputBlindingSeed(input.nullifier(), seed);
  const blinding = (slot: number): Bytes32 =>
    transactOutputBlinding(input.nullifier(), outputSeed, slot);
  const outputs = [
    createProofOutput({
      ownerAddress: owner.shieldedAddress(),
      asset: SOL_MINT,
      amount: 0n,
      blinding: blinding(0),
    }),
    createProofOutput({
      ownerAddress: recipient.shieldedAddress(),
      asset: SOL_MINT,
      amount: 7n,
      blinding: blinding(1),
      dataHash: bytes(5),
    }),
  ];
  const ownerTag = bytes(8);
  const proofInputs = new SppProofInputs({
    payer: SPONSOR,
    inputUtxos: [input],
    outputs,
    externalData: createExternalData({
      txViewingPublicKey: owner.viewingPublicKey(),
      salt: new Uint8Array(16) as Bytes16,
      outputs: outputs.map((output) => ({
        utxoHash: output.hash(0),
        ownerTag: { kind: "inline", value: ownerTag },
      })),
      resolvedOwnerTags: outputs.map(() => ownerTag),
      messages: [],
    }),
    blindingSeed: seed,
    outputTreeId: 0,
  });
  const state = stateTree([input.hash()]);
  const spendProof: SpendProof = {
    state: {
      leaf: input.hash(),
      merkleContext: { treeType: 0, tree: TREE },
      path: state.path(0),
      leafIndex: 0n,
      root: state.root,
      rootSeq: 1n,
      rootIndex: 4,
    },
    nullifier: {
      leaf: input.nullifier(),
      merkleContext: { treeType: 1, tree: TREE },
      path: Array.from({ length: 40 }, () => bytes(0)),
      lowElement: bytes(4),
      lowElementIndex: 0n,
      highElement: bytes(5),
      highElementIndex: 1n,
      root: bytes(6),
      rootSeq: 1n,
      rootIndex: 2,
    },
  };
  return {
    owner,
    ownerAddress: owner.shieldedAddress().solanaAddress(),
    recipient,
    recipientAddress: recipient.shieldedAddress().solanaAddress(),
    proofInputs,
    spendProof,
  };
}

/** The signer vector the prover is asked for, as the hex strings it receives. */
function signerVector(addresses: readonly Address[], width: number): readonly string[] {
  return [
    ...addresses.map((signer) => `0x${signerIdentity(signer).toString(16)}`),
    ...Array.from({ length: width - addresses.length }, () => "0x0"),
  ];
}

describe("owners of outputs that carry data", () => {
  afterEach(() => {
    for (const generated of keypairs.splice(0)) generated.destroy();
  });

  it("puts the recipient of a data output in the proof signer vector after the input owner", () => {
    const { proofInputs, ownerAddress, recipientAddress } = dataTransfer();
    const signers = prepareTransfer(proofInputs).inputs.payload.signerPublicKeyHashes;
    expect(signers.slice(0, 2)).toEqual([
      signerIdentity(ownerAddress),
      signerIdentity(recipientAddress),
    ]);
    expect(signers.slice(2).every((signer) => signer === 0n)).toBe(true);
    expect(signers).not.toContain(signerIdentity(SPONSOR));
  });

  it("asks the data output's owner to sign the assembled transaction and the proof", async () => {
    // 1. Mint an approved transfer whose recipient output carries data.
    const { owner, ownerAddress, recipient, recipientAddress, proofInputs, spendProof } =
      dataTransfer();
    const intent: TransactionIntent = {
      kind: "transfer",
      asset: SOL_MINT,
      amount: 7n,
      recipient: recipient.shieldedAddress(),
    };
    const authorized = mintAuthorizedPrivateTransaction(
      { proofInputs, tree: TREE, intent, senderOutputCount: 1, owner: owner.shieldedAddress() },
      intentHash(intent),
    );

    // 2. Assemble it against a prover that records what it is asked to prove.
    const bodies: Record<string, unknown>[] = [];
    const fetch = vi.fn<typeof globalThis.fetch>(async (_url, init) => {
      const body: unknown = JSON.parse(String(init?.body));
      if (typeof body !== "object" || body === null) throw new Error("unexpected prover body");
      bodies.push({ ...body });
      return Response.json(proofFor(body));
    });
    const client = new ZolanaClient({
      solanaRpcUrl: "http://127.0.0.1:8899",
      indexerUrl: "http://127.0.0.1:8784",
      proverUrl: "http://127.0.0.1:3001",
      proverTee: false,
      proofDataSource: "client",
      tree: TREE,
      fetch,
    });
    vi.spyOn(client, "getMerkleProofs").mockResolvedValue({
      context: { blockTime: 1n, slot: 1n },
      proofs: [spendProof.state],
    });
    vi.spyOn(client, "getNonInclusionProofs").mockResolvedValue({
      context: { blockTime: 1n, slot: 1n },
      proofs: [spendProof.nullifier],
    });
    vi.spyOn(client, "getLatestBlockhash").mockResolvedValue(BLOCKHASH);
    const keys = LocalKeys.fromKeypair(owner, client.proofService);
    try {
      const transaction = await client.assembleAuthorizedPrivateTransaction({
        authorized,
        feePayer: SPONSOR,
        keys,
      });

      // 3. The sponsor pays; the input owner and the data output's owner sign
      // too. The compiled message orders the non-payer signers itself.
      const [payer, ...signers] = Object.keys(transaction.signatures);
      expect(payer).toBe(SPONSOR);
      expect(signers.sort()).toEqual([ownerAddress, recipientAddress].sort());
      expect(bodies).toHaveLength(1);
      const signerPkHashes = bodies[0]?.["signerPkHashes"];
      expect(Array.isArray(signerPkHashes)).toBe(true);
      const width = Array.isArray(signerPkHashes) ? signerPkHashes.length : 0;
      expect(signerPkHashes).toEqual(signerVector([ownerAddress, recipientAddress], width));
    } finally {
      keys.destroy();
    }
  });
});
