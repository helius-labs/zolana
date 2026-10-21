import { describe, expect, it, vi } from "vitest";

import {
  ShieldedKeypair,
  ShieldedPda,
  ShieldedPublicKey,
  bytes16,
  bytes32,
} from "../src/keypair/index.js";
import { ProgramOwner } from "../src/transaction/index.js";

const PDA = bytes32(new Uint8Array(32).fill(8));

describe("ShieldedPda", () => {
  it("binds supplied roles to the PDA without a signing secret", () => {
    const sender = ShieldedKeypair.generate();
    const viewing = sender.viewingKey();
    const nullifier = ProgramOwner.nullifierKey();
    const pda = ShieldedPda.withViewingKey(PDA, nullifier, viewing);
    const hash = bytes32(new Uint8Array(32).fill(1));
    const blinding = bytes32(new Uint8Array(32).fill(2));
    try {
      expect({
        signing: pda.signingPublicKey().toBytes(),
        curve: pda.curve(),
        viewing: pda.viewingPublicKey().toBytes(),
        nullifier: pda.nullifierPublicKey(),
        address: pda.shieldedAddress().ownerHash(),
        compressed: pda.compressedAddress().ownerHash,
        owner: pda.ownerHash(),
        spend: pda.nullifier(hash, blinding),
      }).toEqual({
        signing: ShieldedPublicKey.fromPda(PDA).toBytes(),
        curve: "pda",
        viewing: sender.viewingPublicKey().toBytes(),
        nullifier: nullifier.publicKey(),
        address: pda.ownerHash(),
        compressed: pda.ownerHash(),
        owner: pda.shieldedAddress().ownerHash(),
        spend: nullifier.nullifier(hash, blinding),
      });
      expect(() => pda.sign(Uint8Array.of(1))).toThrow(
        expect.objectContaining({ code: "KEYPAIR_PDA_CANNOT_SIGN", rustVariant: "PdaCannotSign" }),
      );
      const copy = pda.nullifierKey();
      copy.destroy();
      const viewingCopy = pda.viewingKey();
      viewingCopy.destroy();
      expect(pda.nullifierPublicKey()).toEqual(nullifier.publicKey());
      expect(pda.publicKey().equals(sender.viewingPublicKey())).toBe(true);
    } finally {
      pda.destroy();
      sender.destroy();
    }
    expect(() => nullifier.publicKey()).toThrow();
    expect(() => viewing.publicKey()).toThrow();
  });

  it("forwards encryption to its supplied viewing key", () => {
    const sender = ShieldedKeypair.generate();
    const pda = ShieldedPda.withViewingKey(PDA, ProgramOwner.nullifierKey(), sender.viewingKey());
    const salt = bytes16(new Uint8Array(16));
    const encrypt = vi.spyOn(pda, "viewingPublicKey");
    try {
      const tx = pda.transactionViewingKey(bytes32(new Uint8Array(32).fill(3)));
      try {
        const ciphertext = tx.encryptSlot(pda.viewingPublicKey(), Uint8Array.of(1, 2), salt, 0);
        expect(pda.decryptUtxo(ciphertext, tx.publicKey(), salt, 0)).toEqual(Uint8Array.of(1, 2));
        expect(encrypt).toHaveBeenCalled();
      } finally {
        tx.destroy();
      }
    } finally {
      pda.destroy();
      sender.destroy();
    }
  });

  it("destroys both supplied role keys if construction fails", () => {
    const sender = ShieldedKeypair.generate();
    const viewing = sender.viewingKey();
    const nullifier = ProgramOwner.nullifierKey();
    const destroyView = vi.spyOn(viewing, "destroy");
    const destroyNullifier = vi.spyOn(nullifier, "destroy");
    try {
      expect(() =>
        Reflect.apply(ShieldedPda.withViewingKey, ShieldedPda, [
          "invalid-address",
          nullifier,
          viewing,
        ]),
      ).toThrow();
      expect([destroyView.mock.calls.length, destroyNullifier.mock.calls.length]).toEqual([1, 1]);
      expect(() => viewing.publicKey()).toThrow();
      expect(() => nullifier.publicKey()).toThrow();
    } finally {
      sender.destroy();
    }
  });
});
