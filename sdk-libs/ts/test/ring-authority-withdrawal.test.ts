import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { prepareTransfer } from "../src/client/prover/assembly.js";
import { bytes16, bytes32 } from "../src/keypair/bytes.js";
import { ShieldedKeypair, randomBlinding } from "../src/keypair/index.js";
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

const RECIPIENT = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");

describe("the ring authority rail", () => {
  it("withdraws and refuses a deposit", () => {
    const keypair = ShieldedKeypair.generate();
    try {
      const ring = keypair.shieldedAddress().solanaAddress();
      const spend = ProofInputUtxo.fromKeypair(
        new Utxo({
          owner: keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: 7n,
          blinding: randomBlinding(),
          ringProgramId: ring,
        }),
        keypair,
      );
      const first = spend.nullifier();
      const seed = bytes32(new Uint8Array(32).fill(8));
      const outputSeed = outputBlindingSeed(first, seed);
      const outputs = [
        createProofOutput({
          ownerAddress: keypair.shieldedAddress(),
          asset: SOL_MINT,
          amount: 6n,
          blinding: transactOutputBlinding(first, outputSeed, 0),
          ringProgramId: ring,
        }),
        createProofOutput({
          asset: SOL_MINT,
          amount: 0n,
          blinding: transactOutputBlinding(first, outputSeed, 1),
          compact: true,
        }),
      ];
      const viewTag = keypair.signingPublicKey().confidentialViewTag();
      const withLeg = (isDeposit: boolean) =>
        prepareTransfer(
          new SppProofInputs({
            payer: keypair.shieldedAddress().solanaAddress(),
            inputUtxos: [spend, ProofInputUtxo.compact()],
            outputs,
            externalData: createExternalData({
              interfaceTransfers: [
                { kind: "sol", isDeposit, amount: 1n, userSolAccount: RECIPIENT },
              ],
              txViewingPublicKey: keypair.viewingPublicKey(),
              salt: bytes16(new Uint8Array(16)),
              outputs: [
                {
                  utxoHash: outputs[0]?.hash(0) ?? seed,
                  ownerTag: { kind: "inline", value: viewTag },
                },
              ],
              resolvedOwnerTags: [viewTag],
              messages: [],
            }),
            blindingSeed: seed,
            outputTreeId: 0,
          }),
          { kind: "ringAuthority", ring },
        );
      expect(withLeg(false).inputs.circuit).toBe("transferRingAuthority");
      expect(() => withLeg(true)).toThrow(
        expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }),
      );
    } finally {
      keypair.destroy();
    }
  });
});
