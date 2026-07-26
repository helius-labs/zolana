import type { Address, Bytes31, Bytes32 } from "@zolana/interface";
import { NullifierKey, ShieldedKeypair, SigningKey, ViewingKey } from "@zolana/keypair";
import {
  AssetRegistry,
  ConfidentialTransfer,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  deriveBlinding,
} from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import proofFixture from "../../../fixtures/client/proof-validity-v1.json" with { type: "json" };
import rpcFixture from "../../../fixtures/client/rpc-indexer-v1.json" with { type: "json" };
import { buildUnsignedTransaction } from "../../src/client.js";
import { encodeBase58 } from "../../src/internal.js";
import { assemble } from "../../src/prover/assembly.js";
import { compressProof, parseProof } from "../../src/prover/proof.js";
import type { SpendProof } from "../../src/rpc.js";

function transactProof() {
  const c = proofFixture.expected.vanilla.uncompressed.cBytes;
  const b = proofFixture.expected.vanilla.uncompressed.bBytes;
  const g1 = [`0x${c.slice(0, 64)}`, `0x${c.slice(64)}`];
  return compressProof(
    parseProof(
      {
        ar: g1,
        bs: [
          [`0x${b.slice(0, 64)}`, `0x${b.slice(64, 128)}`],
          [`0x${b.slice(128, 192)}`, `0x${b.slice(192)}`],
        ],
        krs: g1,
      },
      false,
    ),
  ).toTransactProof();
}

function keypair(fill: number): ShieldedKeypair {
  const signing = SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(fill) as Bytes32);
  return ShieldedKeypair.fromKeys(
    signing,
    NullifierKey.fromSigningKey(signing),
    ViewingKey.fromSeed(new Uint8Array(32).fill(fill + 100) as Bytes32, 0),
  );
}

function fieldByte(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
}

function spendProofs(contexts: readonly { utxoHash: Bytes32; nullifier: Bytes32 }[]): SpendProof[] {
  const tree = encodeBase58(new Uint8Array(32).fill(45)) as Address;
  return contexts.map((context, index) => ({
    state: {
      leaf: context.utxoHash,
      merkleContext: { treeType: 1, tree },
      path: Array.from({ length: 32 }, () => fieldByte(46 + index)),
      leafIndex: BigInt(index),
      root: fieldByte(47),
      rootSeq: 48n,
      rootIndex: 49 + index,
    },
    nullifier: {
      leaf: context.nullifier,
      merkleContext: { treeType: 2, tree },
      path: Array.from({ length: 40 }, () => fieldByte(50 + index)),
      lowElement: fieldByte(51),
      lowElementIndex: 0n,
      highElement: fieldByte(52),
      highElementIndex: 1n,
      root: fieldByte(53),
      rootSeq: 54n,
      rootIndex: 55 + index,
    },
  }));
}

/// One spendable SOL note owned by `sender`, split across `recipients`
/// shielded addresses and compiled the way `finishSubmissionUnsigned` does.
function compileTransfer(recipients: number) {
  const sender = keypair(1);
  const seed = new Uint8Array(31).fill(7) as Bytes31;
  const payer = rpcFixture.inputs.feePayer as Address;
  const nullifierKey = NullifierKey.fromSigningKey(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(1) as Bytes32),
  );
  const spend = new ProofInputUtxo({
    utxo: new Utxo({
      owner: sender.signingPublicKey(),
      asset: SOL_MINT,
      amount: 1_000_000n,
      blinding: deriveBlinding(seed, 0),
    }),
    nullifierKey,
  });
  const transfer = new ConfidentialTransfer(sender.shieldedAddress(), [spend], payer);
  for (let index = 0; index < recipients; index += 1) {
    transfer.send(keypair(index + 20).shieldedAddress(), SOL_MINT, 10n);
  }
  const proofInputs = transfer.sign(sender, new AssetRegistry());
  const data = assemble(proofInputs, spendProofs(proofInputs.inputContexts())).withProof(
    transactProof(),
  );
  return buildUnsignedTransaction({
    computeUnitLimit: Number(rpcFixture.inputs.computeUnitLimit),
    feePayer: payer,
    tree: rpcFixture.inputs.tree as Address,
    recentBlockhash: encodeBase58(
      Uint8Array.from(rpcFixture.inputs.blockhashBytes.match(/.{2}/gu) ?? [], (byte) =>
        Number.parseInt(byte, 16),
      ),
    ),
    data,
  });
}

describe("oversized transact transactions", () => {
  it("refuses a one-input transfer to six recipients", () => {
    let thrown: unknown;
    try {
      compileTransfer(6);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toEqual(expect.objectContaining({ code: "INTERFACE_TRANSACTION_TOO_LARGE" }));
    const details = (thrown as { details: Record<string, number> }).details;
    expect(details["limit"]).toBe(1232);
    expect(details["size"]).toBeGreaterThan(1232);
    // `resolveShape` rounds two sender slots plus six recipients up to 1 in 8 out.
    expect(details["inputs"]).toBe(1);
    expect(details["outputs"]).toBe(8);
  });

  it("still compiles the shapes that fit", () => {
    const transaction = compileTransfer(1);
    expect(1 + 64 * transaction.signatures.length + transaction.messageBytes.length).toBeLessThan(
      1232,
    );
  });
});
