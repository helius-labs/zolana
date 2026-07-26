import type { Address, Bytes32 } from "@zolana/interface";
import { NullifierKey, ShieldedKeypair, SigningKey, ViewingKey } from "@zolana/keypair";
import { AssetRegistry, OutputData, SOL_MINT, Utxo, Wallet } from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import { LocalWalletAuthority, createMerge, createSplit } from "../../src/index.js";
import { base58, fixture, hex, hexBytes } from "../helpers/fixtures.js";

const TREE = base58(new Uint8Array(32).fill(2)) as Address;

function deterministicKeypair(signingSecret: string, viewingSeed: string): ShieldedKeypair {
  const signing = SigningKey.fromBytes(hexBytes(signingSecret) as Bytes32);
  return ShieldedKeypair.fromKeys(
    signing,
    NullifierKey.fromSigningKey(signing),
    ViewingKey.fromSeed(hexBytes(viewingSeed) as Bytes32, 0),
  );
}

function funded(keypair: ShieldedKeypair, amounts: readonly bigint[]): Wallet {
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry(),
  });
  wallet._replace({
    utxos: amounts.map((amount, index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: new Uint8Array(31).fill(index + 1) as import("@zolana/interface").Bytes31,
        data: new OutputData(),
      }),
      outputContext: {
        hash: new Uint8Array(32).fill(index + 1) as Bytes32,
        tree: TREE,
        leafIndex: BigInt(index),
      },
      nullifier: new Uint8Array(32).fill(index + 10) as Bytes32,
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

describe("wallet dependency vectors", () => {
  it("uses frozen keypair address and transaction authority behavior", async () => {
    const keypairFixture = await fixture<{
      inputs: { p256SigningSecretBytes: string; p256ViewingSecretBytes: string };
      expected: {
        p256: {
          signingPublicKeyBytes: string;
          nullifierPublicKeyBytes: string;
          viewingPublicKeyBytes: string;
          ownerHashBytes: string;
        };
      };
    }>("keypair/shielded");
    const signing = SigningKey.fromBytes(
      hexBytes(keypairFixture.inputs.p256SigningSecretBytes) as Bytes32,
    );
    const keypair = ShieldedKeypair.fromKeys(
      signing,
      NullifierKey.fromSigningKey(signing),
      ViewingKey.fromBytes(hexBytes(keypairFixture.inputs.p256ViewingSecretBytes) as Bytes32),
    );
    expect(hex(keypair.signingPublicKey().toBytes())).toBe(
      keypairFixture.expected.p256.signingPublicKeyBytes,
    );
    expect(hex(keypair.nullifierKey().publicKey())).toBe(
      keypairFixture.expected.p256.nullifierPublicKeyBytes,
    );
    expect(hex(keypair.viewingPublicKey().toBytes())).toBe(
      keypairFixture.expected.p256.viewingPublicKeyBytes,
    );
    expect(hex(keypair.shieldedAddress().ownerHash())).toBe(
      keypairFixture.expected.p256.ownerHashBytes,
    );

    const authorityFixture = await fixture<{
      inputs: {
        signingSecretBytes: string;
        viewingSeedBytes: string;
        messageHashBytes: string;
        solanaPubkeyBytes: string;
      };
      expected: {
        p256Signature: { pubkeyBytes: string; rBytes: string; sBytes: string };
      };
    }>("transaction/authority-v1");
    const authorityKeypair = deterministicKeypair(
      authorityFixture.inputs.signingSecretBytes,
      authorityFixture.inputs.viewingSeedBytes,
    );
    const authority = new LocalWalletAuthority({
      solanaPublicKey: base58(hexBytes(authorityFixture.inputs.solanaPubkeyBytes)) as Address,
      keypair: authorityKeypair,
    });
    const signature = await authority.signP256(
      hexBytes(authorityFixture.inputs.messageHashBytes) as Bytes32,
    );
    expect(hex(signature.publicKey.toBytes())).toBe(
      authorityFixture.expected.p256Signature.pubkeyBytes,
    );
    expect(hex(signature.r)).toBe(authorityFixture.expected.p256Signature.rBytes);
    expect(hex(signature.s)).toBe(authorityFixture.expected.p256Signature.sBytes);
  });

  it("preserves transaction split conservation and merge padding", async () => {
    const splitFixture = await fixture<{
      inputs: { inputAmount: string; partCount: string; partAmount: string };
      expected: { conservedAmount: string; shape: { inputs: string; outputs: string } };
    }>("transaction/split-v1");
    const keypair = ShieldedKeypair.generate();
    const split = createSplit({
      wallet: funded(keypair, [BigInt(splitFixture.inputs.inputAmount)]),
      payer: "11111111111111111111111111111111" as Address,
      asset: SOL_MINT,
      parts: Number(splitFixture.inputs.partCount),
    });
    expect(split.perOutputAmount).toBe(BigInt(splitFixture.inputs.partAmount));
    expect(split.perOutputAmount * BigInt(split.numOutputs)).toBe(
      BigInt(splitFixture.expected.conservedAmount),
    );
    expect(split.transaction.inputCount()).toBe(Number(splitFixture.expected.shape.inputs));

    const mergeFixture = await fixture<{
      inputs: {
        signingSecretBytes: string;
        viewingSeedBytes: string;
        realInputAmounts: string[];
      };
      expected: {
        outputAmount: string;
        inputCount: string;
        realInputCount: string;
        dummyCount: string;
      };
    }>("transaction/merge-v1");
    const mergeKeypair = deterministicKeypair(
      mergeFixture.inputs.signingSecretBytes,
      mergeFixture.inputs.viewingSeedBytes,
    );
    const merge = createMerge({
      wallet: funded(mergeKeypair, mergeFixture.inputs.realInputAmounts.map(BigInt)),
      keypair: mergeKeypair,
      asset: SOL_MINT,
    });
    expect(merge.mergedAmount).toBe(BigInt(mergeFixture.expected.outputAmount));
    expect(merge.numInputs).toBe(Number(mergeFixture.expected.realInputCount));
    expect(merge.prepared.inputs).toHaveLength(Number(mergeFixture.expected.inputCount));
    expect(merge.prepared.inputs.filter((input) => input.isDummy())).toHaveLength(
      Number(mergeFixture.expected.dummyCount),
    );
  });
});
