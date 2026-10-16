import { describe, expect, it } from "vitest";
import { X25519PublicKey, X25519Secret } from "../src/keypair/x25519.js";

describe("custom-ring X25519 envelope keys", () => {
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
    const a = X25519Secret.fromBytes(new Uint8Array(32));
    const b = X25519Secret.fromBytes(new Uint8Array(32).fill(9));
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
});
