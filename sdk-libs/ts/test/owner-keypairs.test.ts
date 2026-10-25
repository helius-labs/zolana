import { describe, expect, it, vi } from "vitest";

import {
  ZolanaClient,
  type IndexedProofAuthority,
  type ProofDataSource,
  type ProofService,
  type SpendProof,
} from "../src/client/index.js";
import { assemble } from "../src/client/prover/assembly.js";
import { bytesField, poseidon } from "../src/client/internal.js";
import { parseProof } from "../src/client/prover/proof.js";
import { treeAddress } from "../src/interface/pda/index.js";
import {
  ShieldedKeypair,
  ShieldedPda,
  NullifierKey,
  bytes16,
  bytes31,
  bytes32,
} from "../src/keypair/index.js";
import {
  ProgramOwner,
  ProofInputUtxo,
  Utxo,
  SOL_MINT,
  SppProofInputs,
  createExternalData,
  createProofOutput,
  outputBlindingSeed,
  transactOutputBlinding,
} from "../src/transaction/index.js";
import { proofFor } from "./helpers/proofs.js";

type Owner = ShieldedKeypair | ShieldedPda;
const bytes = (byte: number) => bytes32(new Uint8Array(32).fill(byte));
const TREE = treeAddress(0);

function fixture(owners: readonly Owner[], specialSlots = false) {
  const sender = ShieldedKeypair.generate();
  const real = owners.map((owner, index) =>
    ProofInputUtxo.fromKeypair(
      new Utxo({
        owner: owner.signingPublicKey(),
        asset: SOL_MINT,
        amount: 7n,
        blinding: bytes(index + 1),
      }),
      owner,
    ),
  );
  const inputs = specialSlots
    ? [
        ProofInputUtxo.address(sender.signingPublicKey(), bytes32(new Uint8Array(32))),
        ...real,
        ProofInputUtxo.dummy(bytes(7)),
      ]
    : real;
  const first = inputs[0];
  if (first === undefined) throw new Error("fixture requires an input");
  const blindingSeed = bytes32(new Uint8Array(32).fill(1));
  const seed = outputBlindingSeed(first.nullifier(), blindingSeed);
  const outputs = [
    createProofOutput({
      ownerAddress: sender.shieldedAddress(),
      asset: SOL_MINT,
      amount: BigInt(real.length) * 7n,
      blinding: transactOutputBlinding(first.nullifier(), seed, 0),
    }),
    createProofOutput({
      asset: SOL_MINT,
      amount: 0n,
      blinding: transactOutputBlinding(first.nullifier(), seed, 1),
      ownerTag: bytes(8),
    }),
  ];
  const proofInputs = new SppProofInputs({
    payer: sender.shieldedAddress().solanaAddress(),
    inputUtxos: inputs,
    outputs,
    externalData: createExternalData({
      txViewingPublicKey: sender.viewingPublicKey(),
      salt: bytes16(new Uint8Array(16)),
      outputs: outputs.map((output) => ({
        utxoHash: output.hash(0),
        ownerTag: { kind: "inline", value: bytes(8) },
      })),
      resolvedOwnerTags: outputs.map(() => bytes(8)),
      messages: [],
    }),
    blindingSeed,
    outputTreeId: 0,
  });
  const proofs = real.map((input, index): SpendProof => ({
    state: {
      leaf: input.hash(),
      merkleContext: { treeType: 0, tree: TREE },
      path: Array.from({ length: 32 }, () => bytes(0)),
      leafIndex: BigInt(index),
      root: bytes(3),
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
  }));
  const template = proofs[0]?.nullifier;
  const paddingProofs = inputs
    .filter((input) => !input.requiresInclusion())
    .map((input) => {
      if (template === undefined) throw new Error("fixture needs a real proof template");
      return { ...template, leaf: input.nullifier() };
    });
  return { proofInputs, proofs, paddingProofs, sender };
}

function setup(transaction: ReturnType<typeof fixture>, source: ProofDataSource = "client") {
  const network = vi.fn<typeof fetch>();
  const client = new ZolanaClient({ proofDataSource: source, fetch: network });
  const merkle = vi.spyOn(client, "getMerkleProofs").mockResolvedValue({
    context: { blockTime: 1n, slot: 1n },
    proofs: transaction.proofs.map((proof) => proof.state),
  });
  const nullifiers = vi.spyOn(client, "getNonInclusionProofs").mockResolvedValue({
    context: { blockTime: 1n, slot: 1n },
    proofs: [...transaction.proofs.map((proof) => proof.nullifier), ...transaction.paddingProofs],
  });
  const proof = parseProof(
    proofFor({ circuitType: "transfer-confidential", nInputs: 4, nOutputs: 2 }),
  );
  const prove = vi.spyOn(client.proofService, "prove").mockResolvedValue(proof);
  return { client, network, merkle, nullifiers, proof, prove };
}

function pda(sender: ShieldedKeypair, byte: number) {
  return ShieldedPda.withViewingKey(bytes(byte), ProgramOwner.nullifierKey(), sender.viewingKey());
}

describe("owner-bound proving keypairs", () => {
  it.each(["client", "prover"] as const)(
    "matches unordered mixed owners and repeated UTXOs through %s proof fetching",
    async (source) => {
      const wallet = ShieldedKeypair.generate();
      const first = pda(wallet, 11);
      const second = pda(wallet, 12);
      const tx = fixture([first, wallet, second, first]);
      const env = setup(tx, source);
      const assembled = assemble(tx.proofInputs, tx.proofs);
      const httpProver = env.client.proofService as ProofService & IndexedProofAuthority;
      const indexed = vi.spyOn(httpProver, "proveIndexed").mockResolvedValue({
        proof: env.proof,
        resolution: {
          publicInputHash: assembled.publicInputHash,
          trees: [
            {
              tree: TREE,
              id: 0,
              utxoRoot: bytes(3),
              nullifierRoot: bytes(6),
              utxoRootIndex: 4,
              nullifierRootIndex: 2,
            },
          ],
        },
      });
      const copied: NullifierKey[] = [];
      for (const owner of [wallet, first, second]) {
        const clone = owner.nullifierKey.bind(owner);
        vi.spyOn(owner, "nullifierKey").mockImplementation(() => {
          const key = clone();
          copied.push(key);
          return key;
        });
      }
      try {
        await expect(
          env.client.proveTransact(tx.proofInputs, [second, wallet, first]),
        ).resolves.toBeDefined();
        const completed =
          source === "client"
            ? env.prove.mock.calls[0]?.[0].payload.inputs
            : indexed.mock.calls[0]?.[0].payload.inputs;
        if (completed === undefined) throw new Error("proof service must receive inputs");
        expect(
          completed.map((input, index) => {
            const raw = tx.proofInputs.inputUtxos[index];
            const secret = input.nullifierSecret;
            if (raw === undefined || secret === undefined)
              throw new Error("missing completed slot");
            return {
              owner: poseidon([input.ownerPublicKeyHash, poseidon([secret])]),
              nullifier: poseidon([bytesField(raw.hash(), "hash"), input.circuit.blinding, secret]),
            };
          }),
        ).toEqual(
          tx.proofInputs.inputUtxos.map((input) => ({
            owner: poseidon([
              bytesField(input.utxo.owner.ownerProofInputHash(), "owner"),
              bytesField(input.nullifierPublicKey, "key"),
            ]),
            nullifier: bytesField(input.nullifier(), "nullifier"),
          })),
        );
        expect(copied).toHaveLength(3);
        for (const key of copied) expect(() => key.publicKey()).toThrow();
        expect(wallet.nullifierPublicKey()).toBeDefined();
        expect(first.nullifierPublicKey()).toEqual(second.nullifierPublicKey());
        expect(env.network).not.toHaveBeenCalled();
      } finally {
        wallet.destroy();
        first.destroy();
        second.destroy();
        tx.sender.destroy();
      }
    },
  );

  it("refuses a missing owner, even when another PDA supplies the public zero key", async () => {
    const wallet = ShieldedKeypair.generate();
    const first = pda(wallet, 11);
    const second = pda(wallet, 12);
    const tx = fixture([first]);
    const env = setup(tx);
    try {
      await expect(env.client.proveTransact(tx.proofInputs, [second])).rejects.toMatchObject({
        code: "CLIENT_MISSING_NULLIFIER_SECRET",
      });
      expect([
        env.merkle.mock.calls,
        env.nullifiers.mock.calls,
        env.prove.mock.calls,
        env.network.mock.calls,
      ]).toEqual([[], [], [], []]);
    } finally {
      wallet.destroy();
      first.destroy();
      second.destroy();
      tx.sender.destroy();
    }
  });

  it("matches the signing tag as well as the public-key bytes", async () => {
    const wallet = ShieldedKeypair.generate();
    const wrongTag = ShieldedPda.withViewingKey(
      wallet.signingPublicKey().ed25519(),
      wallet.nullifierKey(),
      wallet.viewingKey(),
    );
    const tx = fixture([wallet]);
    const env = setup(tx);
    try {
      await expect(env.client.proveTransact(tx.proofInputs, [wrongTag])).rejects.toMatchObject({
        code: "CLIENT_MISSING_NULLIFIER_SECRET",
      });
      expect(env.prove).not.toHaveBeenCalled();
      expect(env.merkle).not.toHaveBeenCalled();
    } finally {
      wallet.destroy();
      wrongTag.destroy();
      tx.sender.destroy();
    }
  });

  it("keeps address reservations and padding on their protocol zero-key path", async () => {
    const wallet = ShieldedKeypair.generate();
    const tx = fixture([wallet], true);
    const env = setup(tx);
    try {
      await expect(env.client.proveTransact(tx.proofInputs, [wallet])).resolves.toBeDefined();
      const slots = env.prove.mock.calls[0]?.[0].payload.inputs;
      expect(slots?.map((slot) => slot.nullifierSecret === 0n)).toEqual([true, false, true]);
      expect(env.network).not.toHaveBeenCalled();
    } finally {
      wallet.destroy();
      tx.sender.destroy();
    }
  });

  it("destroys owned key copies when proving rejects and preserves caller keys", async () => {
    const wallet = ShieldedKeypair.generate();
    const tx = fixture([wallet]);
    const env = setup(tx);
    const clone = wallet.nullifierKey.bind(wallet);
    const copies: NullifierKey[] = [];
    vi.spyOn(wallet, "nullifierKey").mockImplementation(() => {
      const copy = clone();
      copies.push(copy);
      return copy;
    });
    env.prove.mockRejectedValue(new Error("proof service failed"));
    try {
      await expect(
        env.client.proveTransact(tx.proofInputs, [wallet, wallet]),
      ).rejects.toBeDefined();
      expect(copies).toHaveLength(2);
      for (const key of copies) expect(() => key.publicKey()).toThrow();
      expect(wallet.nullifierPublicKey()).toBeDefined();
      expect(env.network).not.toHaveBeenCalled();
    } finally {
      wallet.destroy();
      tx.sender.destroy();
    }
  });

  it("rejects a keypair whose declared public role disagrees with its secret", async () => {
    const wallet = ShieldedKeypair.generate();
    const tx = fixture([wallet]);
    const env = setup(tx);
    vi.spyOn(wallet, "nullifierPublicKey").mockReturnValue(ProgramOwner.nullifierPublicKey());
    try {
      await expect(env.client.proveTransact(tx.proofInputs, [wallet])).rejects.toMatchObject({
        code: "CLIENT_INVALID_PROOF_INPUTS",
      });
      expect([env.merkle.mock.calls, env.prove.mock.calls, env.network.mock.calls]).toEqual([
        [],
        [],
        [],
      ]);
    } finally {
      wallet.destroy();
      tx.sender.destroy();
    }
  });

  it("refuses malformed keypair entries before reading proofs", async () => {
    const wallet = ShieldedKeypair.generate();
    const tx = fixture([wallet]);
    const env = setup(tx);
    try {
      for (const keys of [[null], [{}], [undefined]]) {
        await expect(
          Reflect.apply(env.client.proveTransact, env.client, [tx.proofInputs, keys]),
        ).rejects.toMatchObject({ code: "CLIENT_INVALID_PROOF_INPUTS" });
      }
      expect([env.merkle.mock.calls, env.prove.mock.calls, env.network.mock.calls]).toEqual([
        [],
        [],
        [],
      ]);
    } finally {
      wallet.destroy();
      tx.sender.destroy();
    }
  });

  it("rejects conflicting nullifier keys for one signing identity and cleans up all copies", async () => {
    const wallet = ShieldedKeypair.generate();
    const first = pda(wallet, 11);
    const conflicting = ShieldedPda.withViewingKey(
      bytes(11),
      NullifierKey.fromSecret(bytes31(new Uint8Array(31).fill(1))),
      wallet.viewingKey(),
    );
    const tx = fixture([first]);
    const env = setup(tx);
    const copies: NullifierKey[] = [];
    for (const owner of [first, conflicting]) {
      const clone = owner.nullifierKey.bind(owner);
      vi.spyOn(owner, "nullifierKey").mockImplementation(() => {
        const copy = clone();
        copies.push(copy);
        return copy;
      });
    }
    try {
      await expect(
        env.client.proveTransact(tx.proofInputs, [first, conflicting]),
      ).rejects.toMatchObject({ code: "CLIENT_INVALID_PROOF_INPUTS" });
      expect(copies).toHaveLength(2);
      for (const key of copies) expect(() => key.publicKey()).toThrow();
      expect([env.merkle.mock.calls, env.prove.mock.calls, env.network.mock.calls]).toEqual([
        [],
        [],
        [],
      ]);
    } finally {
      wallet.destroy();
      first.destroy();
      conflicting.destroy();
      tx.sender.destroy();
    }
  });

  it.each(["public key", "nullifier"])(
    "rejects an input with a wrong %s before external work",
    async (field) => {
      const wallet = ShieldedKeypair.generate();
      const tx = fixture([wallet]);
      const original = tx.proofInputs.inputUtxos[0];
      if (original === undefined) throw new Error("missing input");
      const invalid = new SppProofInputs({
        ...tx.proofInputs,
        inputUtxos: [
          new ProofInputUtxo({
            utxo: original.utxo,
            nullifierPublicKey:
              field === "public key"
                ? ProgramOwner.nullifierPublicKey()
                : original.nullifierPublicKey,
            nullifier: field === "nullifier" ? bytes(1) : original.nullifier(),
          }),
        ],
      });
      const env = setup(tx);
      try {
        await expect(env.client.proveTransact(invalid, [wallet])).rejects.toMatchObject({
          code: "CLIENT_INVALID_PROOF_INPUTS",
        });
        expect([env.merkle.mock.calls, env.prove.mock.calls, env.network.mock.calls]).toEqual([
          [],
          [],
          [],
        ]);
      } finally {
        wallet.destroy();
        tx.sender.destroy();
      }
    },
  );
});
