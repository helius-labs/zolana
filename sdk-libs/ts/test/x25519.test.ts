import { describe, expect, it } from "vitest";
import { X25519PublicKey, X25519Keypair, isSmallOrder } from "../src/keypair/x25519.js";

describe("X25519 envelope keys", () => {
  it("rejects key aliases and P-256 tags", () => {
    const basepoint = Uint8Array.of(4, 9, ...new Uint8Array(31));
    expect(X25519PublicKey.fromBytes(basepoint).toBytes()).toEqual(basepoint);
    for (const tag of [0, 2, 3, 5]) {
      expect(() => X25519PublicKey.fromBytes(Uint8Array.of(tag, ...basepoint.subarray(1)))).toThrow(
        "KEYPAIR_INVALID_PUBLIC_KEY",
      );
    }
    const p = new Uint8Array(33).fill(255);
    p[0] = 4;
    p[1] = 237;
    p[32] = 127;
    expect(() => X25519PublicKey.fromBytes(p)).toThrow("KEYPAIR_INVALID_PUBLIC_KEY");
    p[1] = 236;
    expect(X25519PublicKey.fromBytes(p).toBytes()).toEqual(p);
    basepoint[32] = 128;
    expect(() => X25519PublicKey.fromBytes(basepoint)).toThrow("KEYPAIR_INVALID_PUBLIC_KEY");
  });
  it("clamps byte secrets, rejects zero DH, and destroys secrets", () => {
    const a = X25519Keypair.fromBytes(new Uint8Array(32));
    const b = X25519Keypair.fromBytes(new Uint8Array(32).fill(9));
    try {
      const ab = a.ecdh(b.publicKey());
      const ba = b.ecdh(a.publicKey());
      try {
        expect(ab).toEqual(ba);
      } finally {
        ab.fill(0);
        ba.fill(0);
      }
      for (const u of [0, 1]) {
        const peer = X25519PublicKey.fromBytes(Uint8Array.of(4, u, ...new Uint8Array(31)));
        expect(() => a.ecdh(peer)).toThrow("KEYPAIR_NON_CONTRIBUTORY_KEY");
      }
    } finally {
      a.destroy();
      b.destroy();
    }
    expect(() => a.secretBytes()).toThrow("KEYPAIR_INVALID_SECRET_KEY");
    expect(() => a.publicKey()).toThrow("KEYPAIR_INVALID_SECRET_KEY");
  });
  it("flags exactly the keys every secret's ECDH rejects", () => {
    const p = (1n << 255n) - 19n;
    const smallOrder = [
      0n,
      1n,
      p - 1n,
      325606250916557431795983626356110631294008115727848805560023387167927233504n,
      39382357235489614581723060781553021112529911719440698176882885853963445705823n,
    ];
    const key = (u: bigint) =>
      X25519PublicKey.fromBytes(
        Uint8Array.of(
          4,
          ...Array.from({ length: 32 }, (_, i) => Number((u >> BigInt(8 * i)) & 255n)),
        ),
      );
    const secrets = [X25519Keypair.generate(), X25519Keypair.generate()];
    try {
      for (const u of smallOrder) {
        expect(isSmallOrder(key(u))).toBe(true);
        for (const secret of secrets) {
          expect(() => secret.ecdh(key(u))).toThrow("KEYPAIR_NON_CONTRIBUTORY_KEY");
        }
      }
      for (const u of [9n, 2n]) {
        expect(isSmallOrder(key(u))).toBe(false);
        for (const secret of secrets) secret.ecdh(key(u)).fill(0);
      }
    } finally {
      for (const secret of secrets) secret.destroy();
    }
  });
});
