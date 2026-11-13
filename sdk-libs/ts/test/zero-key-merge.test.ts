import { describe, expect, it, vi } from "vitest";

import { LocalKeys, mergeProverRequestBody } from "../src/client/index.js";
import { prepareMerge } from "../src/client/prover/merge.js";
import { bytesToBigInt } from "../src/interface/bytes.js";
import { treeAddress } from "../src/interface/pda/index.js";
import {
  NullifierKey,
  ShieldedAddress,
  ShieldedKeypair,
  randomBlinding,
  type Bytes31,
} from "../src/keypair/index.js";
import { Merge, ProofInputUtxo, SOL_MINT, Utxo } from "../src/transaction/index.js";
import type { Bytes16, Bytes32 } from "../src/interface/index.js";

const fill = (value: number): Bytes32 => new Uint8Array(32).fill(value) as Bytes32;

describe("a zero-key ring merge", () => {
  it("proves under its seed and publishes the signer's hashed key", async () => {
    const owner = ShieldedKeypair.generate();
    const zeroNullifierKey = NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);
    try {
      const ring = owner.shieldedAddress().solanaAddress();
      const utxo = new Utxo({
        owner: owner.signingPublicKey(),
        asset: SOL_MINT,
        amount: 5n,
        blinding: randomBlinding(),
        ringProgramId: ring,
      });
      const zeroKeyOwner = ShieldedAddress.fromPublicKeys(
        owner.signingPublicKey(),
        zeroNullifierKey.publicKey(),
        owner.viewingPublicKey(),
      );
      const inputs = [ProofInputUtxo.fromNullifierKey(utxo, zeroNullifierKey)];
      const merge = (mergeSeed?: Bytes32, address = zeroKeyOwner, spends = inputs) =>
        new Merge({
          address,
          inputs: spends,
          outputBlinding: fill(1),
          privateTxBlinding: fill(2),
          dummyNullifiers: Array.from({ length: 7 }, (_, slot) => fill(slot + 3)),
          outputKey: fill(11),
          outputCiphertextSalt: new Uint8Array(16) as Bytes16,
          ring: { programId: ring },
          ...(mergeSeed === undefined ? {} : { mergeSeed }),
        })
          .withExpiry(7n)
          .prepare();
      const seed = fill(0x22);
      seed[0] = 0;
      const tree = treeAddress(inputs[0]?.treeId ?? 0);
      const zeroKey = prepareMerge(merge(seed), tree).inputs;
      const nonzero = prepareMerge(merge(), tree).inputs;
      const ownerHash = bytesToBigInt(owner.signingPublicKey().ownerProofInputHash());
      // The published owner sits after the six-element prefix and two ring fields.
      expect(zeroKey.publicInputs[8]).toBe(ownerHash);
      expect(nonzero.publicInputs[8]).toBe(0n);
      expect(zeroKey.payload.mergeSeed).toBe(bytesToBigInt(seed));
      expect(zeroKey.payload.publishedOwner).toBe(ownerHash);
      const proveIndexed = vi.fn(async () => ({}) as never);
      const keys = LocalKeys.fromKeypair(owner, {
        prove: vi.fn(),
        proveMerge: vi.fn(),
        proveIndexed,
      } as never);
      await keys.proveIndexed(zeroKey);
      expect(proveIndexed).toHaveBeenCalledWith(
        expect.objectContaining({
          payload: expect.objectContaining({ userNullifierSecret: 0n }),
        }),
        undefined,
      );
      const body = mergeProverRequestBody({
        ...zeroKey.payload,
        inputs: [],
        treeSlots: [],
        publicInputHash: zeroKey.payload.privateTxHash,
      });
      expect(body).toMatchObject({
        circuitType: "merge-ring",
        mergeSeed: `0x${bytesToBigInt(seed).toString(16)}`,
        publishedOwner: `0x${ownerHash.toString(16)}`,
        userNullifierSecret: "0x0",
      });
      expect(() => merge(new Uint8Array(32) as Bytes32)).toThrow("TRANSACTION_INVALID_MERGE_SEED");
      expect(() =>
        merge(seed, owner.shieldedAddress(), [ProofInputUtxo.fromKeypair(utxo, owner)]),
      ).toThrow("TRANSACTION_MERGE_SEED_WITH_NULLIFIER_KEY");
    } finally {
      zeroNullifierKey.destroy();
      owner.destroy();
    }
  });
});
