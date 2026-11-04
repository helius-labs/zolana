import { address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import {
  NullifierKey,
  ShieldedKeypair,
  ShieldedPda,
  ShieldedPublicKey,
  ViewingKey,
  bytes16,
  bytes31,
  bytes32,
  ringNullifierKey,
} from "../src/keypair/index.js";
import { ProgramOwner } from "../src/transaction/index.js";

const PDA = bytes32(new Uint8Array(32).fill(8));
const RING_A = address("11111111111111111111111111111111");
const RING_B = address("Sysvar1nstructions1111111111111111111111111");

function secretHex(key: NullifierKey): string {
  return Buffer.from(key.secretBytes()).toString("hex");
}

describe("ring nullifier keys", () => {
  it("separate rings and leave the wallet root unreachable", () => {
    const wallet = ShieldedKeypair.generate();
    const first = wallet.ringNullifierKey(RING_A);
    const second = wallet.ringNullifierKey(RING_B);
    expect(secretHex(first)).not.toBe(secretHex(second));
    expect(secretHex(first)).not.toBe(secretHex(wallet.nullifierKey()));
    expect(secretHex(first)).toBe(secretHex(wallet.ringNullifierKey(RING_A)));
    const fromRingSecret = ringNullifierKey(first, RING_B);
    expect(secretHex(fromRingSecret)).not.toBe(secretHex(second));
    expect(secretHex(fromRingSecret)).not.toBe(secretHex(wallet.nullifierKey()));
  });

  it("refuse a zero root", () => {
    const zero = NullifierKey.fromSecret(bytes31(new Uint8Array(31)));
    expect(() => ringNullifierKey(zero, RING_A)).toThrow(
      expect.objectContaining({
        code: "KEYPAIR_ZERO_NULLIFIER_SECRET",
        rustVariant: "ZeroNullifierSecret",
      }),
    );
  });

  it("separate one holder's PDAs and match across both holders", () => {
    const holder = ViewingKey.generate();
    const peer = ViewingKey.generate();
    const sole = ShieldedPda.fromViewingKey(PDA, holder);
    const other = ShieldedPda.fromViewingKey(bytes32(new Uint8Array(32).fill(9)), holder);
    expect(secretHex(sole.ringNullifierKey(RING_A))).not.toBe(
      secretHex(other.ringNullifierKey(RING_A)),
    );
    expect(secretHex(sole.ringNullifierKey(RING_A))).not.toBe(
      secretHex(sole.ringNullifierKey(RING_B)),
    );
    expect(
      secretHex(
        ShieldedPda.fromKeyExchange(PDA, holder, peer.publicKey()).ringNullifierKey(RING_A),
      ),
    ).toBe(
      secretHex(
        ShieldedPda.fromKeyExchange(PDA, peer, holder.publicKey()).ringNullifierKey(RING_A),
      ),
    );
  });

  it("refuse a destroyed PDA, whose wiped root would give a public key", () => {
    const pda = ShieldedPda.fromViewingKey(PDA, ViewingKey.generate());
    pda.destroy();
    expect(() => pda.ringNullifierKey(RING_A)).toThrow(
      expect.objectContaining({ code: "KEYPAIR_PDA_ROOT_NOT_HELD" }),
    );
  });

  it("refuse a PDA with supplied roles", () => {
    const pda = ShieldedPda.withViewingKey(
      PDA,
      NullifierKey.fromSecret(bytes31(new Uint8Array(31).fill(9))),
      ViewingKey.generate(),
    );
    expect(() => pda.ringNullifierKey(RING_A)).toThrow(
      expect.objectContaining({ code: "KEYPAIR_PDA_ROOT_NOT_HELD", rustVariant: "PdaRootNotHeld" }),
    );
  });
});

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
