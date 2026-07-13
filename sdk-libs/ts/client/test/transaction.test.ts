import { Keypair, PublicKey as SolanaPublicKey } from "@solana/web3.js";
import { describe, expect, it } from "vitest";
import {
  AssetRegistry,
  Data,
  NULLIFIER_TREE_HEIGHT,
  OutputUtxo,
  PublicKey,
  SOL_ASSET_ID,
  SOL_MINT,
  ShieldedKeypair,
  Transaction,
  Utxo,
  assembleTransfer,
  proveAssembledTransfer,
  serializeTransactIxData,
  spendUtxoFromKeypair,
  transactInstruction,
  type MerkleContext,
  type ProverClient,
  type SpendProof,
  type TransactProof,
} from "../src/index.js";

function walletInput(owner: ShieldedKeypair, amount: bigint): Utxo {
  return new Utxo({
    owner: owner.signingPubkey(),
    asset: SOL_MINT,
    amount,
    blinding: new Uint8Array(31).fill(7),
    data: Data.empty(),
  });
}

function fakeSpendProof(rootIndex: number): SpendProof {
  const context: MerkleContext = {
    treeType: 0,
    tree: SolanaPublicKey.default,
  };
  return {
    state: {
      leaf: new Uint8Array(32),
      merkleContext: context,
      path: Array.from({ length: 32 }, () => new Uint8Array(32)),
      leafIndex: 0,
      root: new Uint8Array(32).fill(11),
      rootSeq: 0,
      rootIndex,
    },
    nullifier: {
      leaf: new Uint8Array(32),
      merkleContext: context,
      path: Array.from({ length: NULLIFIER_TREE_HEIGHT }, () => new Uint8Array(32)),
      lowElement: new Uint8Array(32),
      lowElementIndex: 0,
      highElement: new Uint8Array(32),
      highElementIndex: 0,
      root: new Uint8Array(32).fill(13),
      rootSeq: 0,
      rootIndex,
    },
  };
}

describe("transaction", () => {
  it("signs and assembles a P256 confidential transfer", () => {
    const sender = ShieldedKeypair.new();
    const recipient = ShieldedKeypair.new();
    const tx = new Transaction(
      sender.shieldedAddress(),
      [spendUtxoFromKeypair(walletInput(sender, 100n), sender)],
      SolanaPublicKey.default,
    );
    tx.send(recipient.shieldedAddress(), SOL_MINT, 60n);

    const signed = tx.sign(sender, new AssetRegistry());
    expect(signed.p256Owner).toHaveLength(64);
    expect(signed.inputCommitments()).toHaveLength(1);
    expect(signed.outputs.map((output) => output.amount)).toEqual([0n, 40n, 60n]);
    expect(signed.externalData.outputCiphertexts).toHaveLength(2);

    const assembled = assembleTransfer(signed, [fakeSpendProof(5)]);
    expect(assembled.proverInputs.kind).toBe("p256");
    expect(assembled.ix.inputs).toHaveLength(2);
    expect(assembled.ix.inputs[0]?.utxoTreeRootIndex).toBe(5);
    expect(assembled.ix.inputs[1]?.utxoTreeRootIndex).toBe(5);
    expect(assembled.ix.outputUtxoHashes).toHaveLength(3);

    const proof: TransactProof = {
      kind: "p256",
      a: new Uint8Array(32).fill(1),
      b: new Uint8Array(64).fill(2),
      c: new Uint8Array(32).fill(3),
      commitment: new Uint8Array(32).fill(4),
      commitmentPok: new Uint8Array(32).fill(5),
    };
    const ixBytes = serializeTransactIxData({ ...assembled.ix, proof });
    expect(ixBytes.length).toBeGreaterThan(200);

    const instruction = transactInstruction({
      payer: Keypair.generate().publicKey,
      tree: Keypair.generate().publicKey,
      data: { ...assembled.ix, proof },
    });
    expect(instruction.data[0]).toBe(0);
    expect(instruction.keys.at(-1)?.pubkey.toBase58()).toBe(
      "sppzgEd25DF4PC1FgNerLWVZndUAV82LV9Dy5yCvRVA",
    );
  });

  it("can insert a server-formatted proof into assembled instruction data", async () => {
    const sender = ShieldedKeypair.fromEd25519(new Uint8Array(32).fill(9), ShieldedKeypair.new().viewingKey);
    const recipient = ShieldedKeypair.new();
    const tx = new Transaction(
      sender.shieldedAddress(),
      [spendUtxoFromKeypair(walletInput(sender, 20n), sender)],
      SolanaPublicKey.default,
    ).send(recipient.shieldedAddress(), SOL_MINT, 3n);
    const assembled = assembleTransfer(tx.sign(sender, new AssetRegistry()), [fakeSpendProof(1)]);
    expect(assembled.proverInputs.kind).toBe("eddsa");

    const client = {
      proveTransactTransfer: async () => ({
        kind: "eddsa" as const,
        a: new Uint8Array(32).fill(1),
        b: new Uint8Array(64).fill(2),
        c: new Uint8Array(32).fill(3),
      }),
      proveTransactTransferP256: async () => {
        throw new Error("unexpected p256 call");
      },
    } as unknown as ProverClient;
    const withProof = await proveAssembledTransfer(client, assembled);
    expect(withProof.proof.kind).toBe("eddsa");
    expect(serializeTransactIxData(withProof).length).toBeGreaterThan(150);
  });

  it("supports explicit output construction", () => {
    const recipient = ShieldedKeypair.new().shieldedAddress();
    const output = new OutputUtxo({
      ownerAddress: recipient,
      asset: SOL_MINT,
      amount: 1n,
      blinding: new Uint8Array(31).fill(3),
    });
    expect(output.hash()).toHaveLength(32);
    expect(new AssetRegistry().assetId(SOL_MINT)).toBe(SOL_ASSET_ID);
    expect(PublicKey.zeroed().isZero()).toBe(true);
  });
});
