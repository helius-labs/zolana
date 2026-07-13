import { PublicKey as SolanaPublicKey } from "@solana/web3.js";
import { describe, expect, it } from "vitest";
import {
  AssetRegistry,
  BN254_MODULUS_DEC,
  Data,
  HEALTH_CHECK,
  NULLIFIER_TREE_HEIGHT,
  ProverClient,
  SOL_MINT,
  ShieldedKeypair,
  Transaction,
  Utxo,
  assembleTransfer,
  bigIntToBytes,
  poseidon,
  proveAssembledTransfer,
  serverAddress,
  spendUtxoFromKeypair,
  type SpendProof,
} from "../src/index.js";

const runE2e = process.env.ZOLANA_TS_E2E === "1";
const BN254_MODULUS = BigInt(BN254_MODULUS_DEC);

describe.skipIf(!runE2e)("client e2e", () => {
  it("reaches a local prover server health endpoint", async () => {
    const response = await fetch(`${serverAddress()}${HEALTH_CHECK}`);
    expect(response.ok).toBe(true);
  });

  it("proves a TS-assembled eddsa transfer through the prover server", async () => {
    const sender = ShieldedKeypair.fromEd25519(new Uint8Array(32).fill(41), ShieldedKeypair.new().viewingKey);
    const recipient = ShieldedKeypair.new();
    const input = new Utxo({
      owner: sender.signingPubkey(),
      asset: SOL_MINT,
      amount: 10n,
      blinding: new Uint8Array(31).fill(42),
      data: Data.empty(),
    });
    const tx = new Transaction(
      sender.shieldedAddress(),
      [spendUtxoFromKeypair(input, sender)],
      SolanaPublicKey.default,
    ).send(recipient.shieldedAddress(), SOL_MINT, 3n);
    const signed = tx.sign(sender, new AssetRegistry());
    const commitment = signed.inputCommitments()[0];
    expect(commitment).toBeDefined();

    const assembled = assembleTransfer(signed, [firstSpendProof(commitment!.utxoHash, commitment!.nullifier)]);
    expect(assembled.proverInputs.kind).toBe("eddsa");
    const withProof = await proveAssembledTransfer(new ProverClient(), assembled);
    expect(withProof.proof.kind).toBe("eddsa");
  }, 300_000);

  it("proves a TS-assembled P256 transfer through the prover server", async () => {
    const sender = ShieldedKeypair.new();
    const recipient = ShieldedKeypair.new();
    const input = new Utxo({
      owner: sender.signingPubkey(),
      asset: SOL_MINT,
      amount: 10n,
      blinding: new Uint8Array(31).fill(43),
      data: Data.empty(),
    });
    const tx = new Transaction(
      sender.shieldedAddress(),
      [spendUtxoFromKeypair(input, sender)],
      SolanaPublicKey.default,
    ).send(recipient.shieldedAddress(), SOL_MINT, 3n);
    const signed = tx.sign(sender, new AssetRegistry());
    const commitment = signed.inputCommitments()[0];
    expect(commitment).toBeDefined();

    const assembled = assembleTransfer(signed, [firstSpendProof(commitment!.utxoHash, commitment!.nullifier)]);
    expect(assembled.proverInputs.kind).toBe("p256");
    const withProof = await proveAssembledTransfer(new ProverClient(), assembled);
    expect(withProof.proof.kind).toBe("p256");
  }, 300_000);
});

describe.runIf(!runE2e)("client e2e disabled", () => {
  it("documents the opt-in flag", () => {
    expect(process.env.ZOLANA_TS_E2E).not.toBe("1");
  });
});

function firstSpendProof(utxoHash: Uint8Array, nullifier: Uint8Array): SpendProof {
  const state = singleLeafProof(utxoHash, 32);
  const zero = new Uint8Array(32);
  const high = bigIntToBytes(BN254_MODULUS - 1n, 32);
  const nullifierLeaf = poseidon([zero, high]);
  const nullifierTree = singleLeafProof(nullifierLeaf, NULLIFIER_TREE_HEIGHT);
  return {
    state: {
      leaf: utxoHash,
      merkleContext: { treeType: 0, tree: SolanaPublicKey.default },
      path: state.path,
      leafIndex: 0,
      root: state.root,
      rootSeq: 0,
      rootIndex: 0,
    },
    nullifier: {
      leaf: nullifier,
      merkleContext: { treeType: 0, tree: SolanaPublicKey.default },
      path: nullifierTree.path,
      lowElement: zero,
      lowElementIndex: 0,
      highElement: high,
      highElementIndex: 0,
      root: nullifierTree.root,
      rootSeq: 0,
      rootIndex: 0,
    },
  };
}

function singleLeafProof(leaf: Uint8Array, height: number): { path: Uint8Array[]; root: Uint8Array } {
  const zeros = zeroHashes(height);
  const path = Array.from({ length: height }, (_, i) => zeros[i]!);
  let root = leaf;
  for (let level = 0; level < height; level += 1) {
    root = poseidon([root, zeros[level]!]);
  }
  return { path, root };
}

function zeroHashes(height: number): Uint8Array[] {
  const zeros: Uint8Array[] = [new Uint8Array(32)];
  for (let i = 1; i <= height; i += 1) {
    zeros.push(poseidon([zeros[i - 1]!, zeros[i - 1]!]));
  }
  return zeros;
}
